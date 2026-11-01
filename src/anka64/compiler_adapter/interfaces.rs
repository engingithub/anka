//! C3/C4 versioned, zero-copy interface evidence and bounded compatibility.
//!
//! This is an admission component, not an AOM replacement or execution grant.
//! AOM v2 binds ATY1 to guest-emitted symbols and guest linking. Callers must retain
//! and charge the backing, bind these exact bytes to the module and receipt,
//! and independently check current authorities before publication/execution.
//! See DN-71 for the wire format and remaining integration acceptance.

pub const TYPE_MAGIC: &[u8; 8] = b"ANKATY1\0";
pub const TYPE_VERSION: u64 = 1;
pub const HEADER_BYTES: usize = 40;
pub const DECL_BYTES: usize = 112;
pub const FIELD_BYTES: usize = 160;
pub const REF_BYTES: usize = 80;
pub const FUNCTION_BYTES: usize = 480;
const SIGNED_MAX: u64 = i64::MAX as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeError {
    Header, Bounds, Limit, Work, Name, Duplicate, Type, Incomplete,
    Layout, Cycle, Signature, Conflict, Unresolved, Changed,
}

/// Trusted policy. Neither the wire header nor a guest may select these limits.
#[derive(Clone, Copy, Debug)]
pub struct TypeLimits {
    pub bytes: u64,
    pub declarations: u64,
    pub fields: u64,
    pub functions: u64,
}

/// One shared budget across parsing, resolution and revalidation. Exhaustion
/// fails closed; no graph recursion, allocator or unbounded work queue is used.
#[derive(Debug)]
pub struct TypeWork { remaining: u64 }
impl TypeWork {
    pub fn new(units: u64) -> Self { Self { remaining: units } }
    pub fn remaining(&self) -> u64 { self.remaining }
    fn take(&mut self, n: u64) -> Result<(), TypeError> {
        self.remaining = self.remaining.checked_sub(n).ok_or(TypeError::Work)?;
        Ok(())
    }
}

fn word(b: &[u8], off: usize) -> Result<u64, TypeError> {
    let end = off.checked_add(8).ok_or(TypeError::Bounds)?;
    let raw = b.get(off..end).ok_or(TypeError::Bounds)?;
    Ok(u64::from_le_bytes(raw.try_into().map_err(|_| TypeError::Bounds)?))
}
fn end(start: usize, count: u64, stride: usize) -> Result<usize, TypeError> {
    let count = usize::try_from(count).map_err(|_| TypeError::Bounds)?;
    start.checked_add(count.checked_mul(stride).ok_or(TypeError::Bounds)?)
        .ok_or(TypeError::Bounds)
}
fn identifier(b: &[u8]) -> bool {
    if b.len() != 64 { return false; }
    let Some(n) = b.iter().position(|&c| c == 0) else { return false; };
    n > 0 && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b[..n].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
        && b[n..].iter().all(|&c| c == 0)
}
fn align(n: u64, a: u64) -> Result<u64, TypeError> {
    if a == 0 || !a.is_power_of_two() { return Err(TypeError::Layout); }
    n.checked_add(a - 1).map(|n| n & !(a - 1)).filter(|&n| n <= SIGNED_MAX)
        .ok_or(TypeError::Layout)
}

#[derive(Clone, Copy)]
struct Decl<'a> { raw: &'a [u8] }
impl<'a> Decl<'a> {
    fn name(self) -> &'a [u8] { &self.raw[..64] }
    fn complete(self) -> bool { word(self.raw, 64).unwrap() == 1 }
    fn size(self) -> u64 { word(self.raw, 72).unwrap() }
    fn alignment(self) -> u64 { word(self.raw, 80).unwrap() }
    fn count(self) -> u64 { word(self.raw, 88).unwrap() }
    fn rank(self) -> u64 { word(self.raw, 96).unwrap() }
    fn field(self, i: u64) -> &'a [u8] {
        let p = DECL_BYTES + i as usize * FIELD_BYTES;
        &self.raw[p..p + FIELD_BYTES]
    }
}
#[derive(Clone, Copy)]
struct Ref<'a> { raw: &'a [u8] }
impl<'a> Ref<'a> {
    fn kind(self) -> u64 { word(self.raw, 0).unwrap() }
    fn depth(self) -> u64 { word(self.raw, 8).unwrap() }
    fn tag(self) -> &'a [u8] { &self.raw[16..80] }
}

/// Validated, immutable views borrow the entire exact wire object. They allocate
/// no hidden directory. Reordering declarations does not change type identity.
#[derive(Debug)]
pub struct TypeEvidence<'a> {
    bytes: &'a [u8], declarations: u64, functions: u64, functions_at: usize,
}
impl<'a> TypeEvidence<'a> {
    pub fn exact_bytes(&self) -> &'a [u8] { self.bytes }

    fn decl_at(&self, at: usize) -> Result<Decl<'a>, TypeError> {
        let count = word(self.bytes, at.checked_add(88).ok_or(TypeError::Bounds)?)?;
        let stop = end(at.checked_add(DECL_BYTES).ok_or(TypeError::Bounds)?, count, FIELD_BYTES)?;
        Ok(Decl { raw: self.bytes.get(at..stop).ok_or(TypeError::Bounds)? })
    }
    fn find(&self, name: &[u8], work: &mut TypeWork) -> Result<Option<Decl<'a>>, TypeError> {
        let mut at = HEADER_BYTES;
        for _ in 0..self.declarations {
            work.take(1)?;
            let d = self.decl_at(at)?;
            if d.name() == name { return Ok(Some(d)); }
            at += d.raw.len();
        }
        Ok(None)
    }
    fn function(&self, i: u64) -> &'a [u8] {
        let at = self.functions_at + i as usize * FUNCTION_BYTES;
        &self.bytes[at..at + FUNCTION_BYTES]
    }
    fn reference(&self, raw: &'a [u8], work: &mut TypeWork) -> Result<Ref<'a>, TypeError> {
        work.take(1)?;
        let r = Ref { raw };
        if !(1..=4).contains(&r.kind()) || r.depth() > 63 { return Err(TypeError::Type); }
        if r.kind() == 4 {
            if !identifier(r.tag()) || self.find(r.tag(), work)?.is_none() { return Err(TypeError::Type); }
        } else if r.tag().iter().any(|&b| b != 0) { return Err(TypeError::Type); }
        Ok(r)
    }
    fn layout(&self, r: Ref<'a>, work: &mut TypeWork) -> Result<(u64,u64,u64), TypeError> {
        if r.depth() > 0 { return Ok((16,16,0)); }
        match r.kind() {
            1 => Ok((8,8,0)), 2 => Ok((1,1,0)),
            4 => {
                let d = self.find(r.tag(), work)?.ok_or(TypeError::Type)?;
                if !d.complete() { return Err(TypeError::Incomplete); }
                Ok((d.size(),d.alignment(),d.rank()))
            }
            _ => Err(TypeError::Layout),
        }
    }

    pub fn parse(bytes: &'a [u8], limits: TypeLimits, work: &mut TypeWork) -> Result<Self, TypeError> {
        work.take(1)?;
        if bytes.len() < HEADER_BYTES || bytes.get(..8) != Some(TYPE_MAGIC.as_slice())
            || word(bytes,8)? != TYPE_VERSION || word(bytes,16)? != bytes.len() as u64 {
            return Err(TypeError::Header);
        }
        let declarations = word(bytes,24)?;
        let functions = word(bytes,32)?;
        if bytes.len() as u64 > limits.bytes || declarations > limits.declarations
            || functions > limits.functions { return Err(TypeError::Limit); }
        // Preflight minimum geometry before any count-controlled traversal.
        let min = end(end(HEADER_BYTES,declarations,DECL_BYTES)?,functions,FUNCTION_BYTES)?;
        if min > bytes.len() { return Err(TypeError::Bounds); }
        let mut this = Self { bytes, declarations, functions, functions_at: 0 };
        let mut at = HEADER_BYTES;
        let mut fields = 0u64;
        for i in 0..declarations {
            work.take(1)?;
            let d = this.decl_at(at)?;
            if !identifier(d.name()) { return Err(TypeError::Name); }
            fields = fields.checked_add(d.count()).ok_or(TypeError::Limit)?;
            if fields > limits.fields { return Err(TypeError::Limit); }
            let complete = word(d.raw,64)?;
            if complete > 1 || word(d.raw,104)? != 0 { return Err(TypeError::Type); }
            if complete == 0 {
                if d.size() != 0 || d.alignment() != 0 || d.count() != 0 || d.rank() != 0 {
                    return Err(TypeError::Incomplete);
                }
            } else if d.size() == 0 || d.size() > SIGNED_MAX || d.count() == 0
                || !d.alignment().is_power_of_two() || d.alignment() > 16
                || d.rank() == 0 || d.rank() > declarations {
                return Err(TypeError::Layout);
            }
            let mut previous = HEADER_BYTES;
            for _ in 0..i {
                work.take(1)?;
                let old = this.decl_at(previous)?;
                if old.name() == d.name() { return Err(TypeError::Duplicate); }
                previous += old.raw.len();
            }
            at += d.raw.len();
        }
        this.functions_at = at;
        if end(at,functions,FUNCTION_BYTES)? != bytes.len() { return Err(TypeError::Bounds); }
        at = HEADER_BYTES;
        for _ in 0..declarations {
            work.take(1)?;
            let d = this.decl_at(at)?;
            at += d.raw.len();
            if !d.complete() { continue; }
            let (mut used, mut alignment, mut rank) = (0u64,1u64,1u64);
            for i in 0..d.count() {
                work.take(1)?;
                let f = d.field(i);
                if !identifier(&f[..64]) { return Err(TypeError::Name); }
                for j in 0..i {
                    work.take(1)?;
                    if d.field(j)[..64] == f[..64] { return Err(TypeError::Duplicate); }
                }
                let r = this.reference(&f[64..144],work)?;
                let (size,a,child_rank) = this.layout(r,work)?;
                // A strict rank decrease on embedded values rules out cycles.
                // Pointer edges terminate here; no recursive type expansion.
                if child_rank >= d.rank() { return Err(TypeError::Cycle); }
                rank = rank.max(child_rank.checked_add(1).ok_or(TypeError::Cycle)?);
                let offset = word(f,144)?;
                let count = word(f,152)?;
                if count == 0 || offset != align(used,a)? { return Err(TypeError::Layout); }
                used = offset.checked_add(size.checked_mul(count).ok_or(TypeError::Layout)?)
                    .filter(|&n| n <= SIGNED_MAX).ok_or(TypeError::Layout)?;
                alignment = alignment.max(a);
            }
            if d.size() != align(used,alignment)? || d.alignment() != alignment || d.rank() != rank {
                return Err(TypeError::Layout);
            }
        }
        for i in 0..functions {
            work.take(1)?;
            let f = this.function(i);
            if !identifier(&f[..64]) { return Err(TypeError::Name); }
            if !matches!(word(f,64)?,1|2) || word(f,72)? > 4 { return Err(TypeError::Signature); }
            for j in 0..i {
                work.take(1)?;
                if this.function(j)[..64] == f[..64] { return Err(TypeError::Duplicate); }
            }
            let n = word(f,72)? as usize;
            let mut lane = 0;
            for p in 0..5 {
                let raw = &f[80+p*REF_BYTES..80+(p+1)*REF_BYTES];
                if p > n {
                    if raw.iter().any(|&b| b != 0) { return Err(TypeError::Signature); }
                    continue;
                }
                let r = this.reference(raw,work)?;
                if r.depth() == 0 && (r.kind() == 4 || (p > 0 && r.kind() == 3)) {
                    return Err(TypeError::Signature); // no by-value struct ABI
                }
                if p > 0 {
                    lane = if r.depth() > 0 { ((lane+1)&!1)+2 } else { lane+1 };
                    if lane > 4 { return Err(TypeError::Signature); }
                }
            }
        }
        Ok(this)
    }

    /// Exact table-order binding; equal numeric struct placeholders alone are
    /// insufficient. The canonical references retain full tag names.
    pub fn check_symbols(&self, symbols: &[crate::anka64::aom::AomSymbol],
        work: &mut TypeWork) -> Result<(),TypeError> {
        if symbols.len() as u64!=self.functions {return Err(TypeError::Signature);}
        for (i,s) in symbols.iter().enumerate() {
            work.take(1)?;
            let f=self.function(i as u64);
            let len=f[..64].iter().position(|&b|b==0).ok_or(TypeError::Name)?;
            if &f[..len]!=s.name.as_bytes() || word(f,64)?!=s.binding
                || word(f,72)?!=s.parameter_types.len() as u64 {return Err(TypeError::Signature);}
            for p in 0..=s.parameter_types.len() {
                work.take(1)?;
                let r=Ref {raw:&f[80+p*REF_BYTES..80+(p+1)*REF_BYTES]};
                let expected=if p==0 {s.return_type} else {s.parameter_types[p-1]};
                if r.depth()*1000+r.kind()!=expected {return Err(TypeError::Signature);}
            }
        }
        Ok(())
    }

    pub fn same_function(&self,index:usize,other:&Self,other_index:usize,
        work:&mut TypeWork) -> Result<bool,TypeError> {
        work.take(8)?;
        if index as u64>=self.functions || other_index as u64>=other.functions {
            return Err(TypeError::Signature);
        }
        Ok(self.function(index as u64)[72..]==other.function(other_index as u64)[72..])
    }

    /// Object-size-dependent operations require a local complete declaration.
    /// This says nothing about runtime pointer rights, bounds or lifetime.
    pub fn object_layout(&self, tag: &[u8], work: &mut TypeWork) -> Result<(u64,u64),TypeError> {
        if !identifier(tag) { return Err(TypeError::Name); }
        let d = self.find(tag,work)?.ok_or(TypeError::Type)?;
        if !d.complete() { return Err(TypeError::Incomplete); }
        Ok((d.size(),d.alignment()))
    }
}

/// Compatibility evidence only. No kernel, Fabric or pointer capability is
/// accepted or returned. Publication must still bind to current sealed inputs.
#[derive(Debug)]
pub struct CompatibleInterfaces<'a,'m> { modules: &'m [TypeEvidence<'a>] }
impl<'a,'m> CompatibleInterfaces<'a,'m> {
    pub fn validate(modules: &'m [TypeEvidence<'a>], work: &mut TypeWork) -> Result<Self,TypeError> {
        if modules.is_empty() { return Err(TypeError::Unresolved); }
        for (i,m) in modules.iter().enumerate() {
            work.take(1)?;
            let mut at = HEADER_BYTES;
            for _ in 0..m.declarations {
                work.take(1)?;
                let a = m.decl_at(at)?; at += a.raw.len();
                // Global pairwise comparison prevents an opaque declaration
                // from connecting two incompatible complete definitions.
                for peer in &modules[..i] {
                    work.take(1)?;
                    if let Some(b) = peer.find(a.name(),work)? {
                        if a.complete() && b.complete() {
                            work.take(a.count().max(b.count()))?;
                            if a.raw != b.raw { return Err(TypeError::Conflict); }
                        }
                    }
                }
            }
            for f in 0..m.functions {
                work.take(1)?;
                let a = m.function(f);
                let mut found = false;
                for (j,peer) in modules.iter().enumerate() {
                    work.take(1)?;
                    for g in 0..peer.functions {
                        work.take(1)?;
                        if i == j && f == g { continue; }
                        let b = peer.function(g);
                        if a[..64] != b[..64] || word(b,64)? != 1 { continue; }
                        if word(a,64)? == 1 { return Err(TypeError::Duplicate); }
                        if found { return Err(TypeError::Duplicate); }
                        // Includes result type, argument count, full tag names
                        // and pointer depth. Local ordinals never cross this ABI.
                        if a[72..] != b[72..] { return Err(TypeError::Signature); }
                        found = true;
                    }
                }
                if word(a,64)? == 2 && !found { return Err(TypeError::Unresolved); }
            }
        }
        Ok(Self { modules })
    }

    pub fn check_exact_inputs(&self, current: &[&[u8]], work: &mut TypeWork) -> Result<(),TypeError> {
        if current.len() != self.modules.len() { return Err(TypeError::Changed); }
        for (m,now) in self.modules.iter().zip(current) {
            work.take(1 + m.bytes.len() as u64 / 64)?;
            if m.bytes != *now { return Err(TypeError::Changed); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;


/// Cross-check typed modules against every actual export/import in the link
/// input set. Legacy primitive-only modules may participate; local ordinals
/// never substitute for the exact canonical references.
pub(crate) fn validate_link_modules(modules: &[&crate::anka64::aom::AomModule]) -> Result<(),TypeError> {
    if modules.iter().all(|m|m.interface.is_empty()) {return Ok(());}
    let mut work=TypeWork::new(100_000_000);
    let mut views=Vec::new();
    for m in modules {
        if m.interface.is_empty() {views.push(None);continue;}
        let view=TypeEvidence::parse(&m.interface,TypeLimits {bytes:m.interface.len() as u64,
            declarations:4096,fields:4096,functions:4096},&mut work)?;
        view.check_symbols(&m.symbols,&mut work)?;views.push(Some(view));
    }
    for (i,m) in views.iter().enumerate() {
        if let Some(m)=m {
            let mut at=HEADER_BYTES;
            for _ in 0..m.declarations {
                work.take(1)?;let a=m.decl_at(at)?;at+=a.raw.len();
                for peer in views[..i].iter().flatten() {
                    if let Some(b)=peer.find(a.name(),&mut work)? {
                        work.take(a.count().max(b.count()))?;
                        if a.complete() && b.complete() && a.raw!=b.raw {return Err(TypeError::Conflict);}
                    }
                }
            }
        }
        for (si,s) in modules[i].symbols.iter().enumerate().filter(|(_,s)|s.is_import()) {
            let mut found=false;
            for (j,peer) in modules.iter().enumerate() {
                for (sj,t) in peer.symbols.iter().enumerate().filter(|(_,t)|t.is_export()) {
                    work.take(1)?;
                    if s.name!=t.name {continue;}
                    if found {return Err(TypeError::Duplicate);}found=true;
                    if s.return_type!=t.return_type || s.parameter_types!=t.parameter_types {return Err(TypeError::Signature);}
                    if let (Some(a),Some(b))=(&views[i],&views[j]) {
                        if !a.same_function(si,b,sj,&mut work)? {return Err(TypeError::Signature);}
                    }
                }
            }
            if !found {return Err(TypeError::Unresolved);}
        }
    }
    Ok(())
}
