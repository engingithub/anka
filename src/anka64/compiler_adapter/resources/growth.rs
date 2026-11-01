//! C3/C4 checked source/table/link geometry. No hidden 64-KiB source or 1-MiB
//! image ceiling; trusted policy and encodability remain hard bounds. These
//! plans are scalar evidence, not allocation, retry or executable authority.
//! Guest workspace migration and linker use are still required (DN-71).

const MAX: u64 = i64::MAX as u64;
const PAGE: u64 = 4096;
pub const TABLE_COUNT: usize = 7;
pub const CONTROL_BYTES: u64 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrowthError { Policy, Overflow, Capacity, Geometry, Index, Encoding }
fn add(a: u64,b: u64) -> Result<u64,GrowthError> {
    a.checked_add(b).filter(|&n| n <= MAX).ok_or(GrowthError::Overflow)
}
fn round(n: u64,a: u64) -> Result<u64,GrowthError> {
    if a == 0 || !a.is_power_of_two() { return Err(GrowthError::Geometry); }
    Ok(add(n,a-1)? & !(a-1))
}
fn limit(n: u64,max: u64) -> Result<(),GrowthError> {
    if max > MAX { return Err(GrowthError::Policy); }
    if n > max { return Err(GrowthError::Capacity); }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableKind { Functions, Fixups, Locals, Typedefs, Structs, Fields, Enums }
impl TableKind {
    pub fn index(self) -> usize {
        match self { Self::Functions=>0,Self::Fixups=>1,Self::Locals=>2,
            Self::Typedefs=>3,Self::Structs=>4,Self::Fields=>5,Self::Enums=>6 }
    }
    pub fn stride(self) -> u64 { [80,16,40,24,48,40,24][self.index()] }
}
const KINDS: [TableKind;TABLE_COUNT] = [TableKind::Functions,TableKind::Fixups,
    TableKind::Locals,TableKind::Typedefs,TableKind::Structs,TableKind::Fields,TableKind::Enums];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TableSpan { pub offset: u64, pub count: u64, pub stride: u64 }
impl TableSpan {
    /// Return a whole element only. One-past is not a valid table record.
    pub fn element(self,index: u64) -> Result<u64,GrowthError> {
        if index >= self.count || self.stride == 0 { return Err(GrowthError::Index); }
        add(self.offset,index.checked_mul(self.stride).ok_or(GrowthError::Overflow)?)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkspacePlan { tables: [TableSpan;TABLE_COUNT], used: u64, capacity: u64 }
impl WorkspacePlan {
    /// Counts are frozen coordinator policy. A guest requests growth, but does
    /// not choose addresses, roles or record strides. Existing CC2 fixed
    /// addresses/type ordinal encoding must not be used with this new layout.
    pub fn new(counts: [u64;TABLE_COUNT],capacity_limit: u64) -> Result<Self,GrowthError> {
        Self::with_prefix(counts,capacity_limit,CONTROL_BYTES)
    }
    fn with_prefix(counts: [u64;TABLE_COUNT],capacity_limit: u64,prefix: u64) -> Result<Self,GrowthError> {
        if prefix<CONTROL_BYTES || prefix%8!=0 {return Err(GrowthError::Policy);}
        if capacity_limit == 0 || capacity_limit > MAX || capacity_limit % PAGE != 0 {
            return Err(GrowthError::Policy);
        }
        let mut tables = [TableSpan::default();TABLE_COUNT];
        let mut used = prefix;
        for kind in KINDS {
            let i = kind.index();
            let stride = kind.stride();
            if counts[i] > capacity_limit / stride { return Err(GrowthError::Capacity); }
            used = round(used,8)?;
            tables[i] = TableSpan { offset:used,count:counts[i],stride };
            used = add(used,counts[i]*stride)?;
            limit(used,capacity_limit)?;
        }
        let capacity = round(used,PAGE)?;
        limit(capacity,capacity_limit)?;
        Ok(Self { tables,used,capacity })
    }
    pub fn table(self,kind: TableKind) -> TableSpan { self.tables[kind.index()] }
    pub fn used(self) -> u64 { self.used }
    pub fn capacity(self) -> u64 { self.capacity }
}

/// Includes eight bytes of safe source lookahead; empty source still has
/// backed padding. The caller copies exact source bytes and initializes padding.
pub fn source_capacity(length: u64,capacity_limit: u64) -> Result<u64,GrowthError> {
    if capacity_limit == 0 || capacity_limit > MAX || capacity_limit % PAGE != 0 {
        return Err(GrowthError::Policy);
    }
    let n = round(add(length,8)?,PAGE)?;
    limit(n,capacity_limit)?;
    Ok(n)
}

/// Pure capacity selection. The existing retry state machine must separately
/// require a capacity result, actual cleanup, live owner and cumulative budget.
pub fn next_capacity(current: u64,required: u64,capacity_limit: u64) -> Result<u64,GrowthError> {
    if current == 0 || current % PAGE != 0 || capacity_limit == 0
        || capacity_limit > MAX || capacity_limit % PAGE != 0 || current > capacity_limit {
        return Err(GrowthError::Policy);
    }
    if required <= current { return Err(GrowthError::Geometry); }
    let need = round(required,PAGE)?;
    limit(need,capacity_limit)?;
    Ok(need.max(current.saturating_mul(2).min(capacity_limit)))
}

#[derive(Clone, Copy, Debug)]
pub struct ModuleGeometry {
    pub code: u64, pub rodata: u64, pub frames: u64,
    /// Exact serialized frame/type evidence bytes, distinct from spare arena.
    pub metadata: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct LinkLimits {
    pub modules: u64, pub frames: u64, pub metadata: u64, pub image: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkPlan {
    pub code: u64, pub rodata_at: u64, pub metadata_at: u64,
    pub used: u64, pub capacity: u64, pub frames: u64,
}
impl LinkPlan {
    /// A planned image is code, aligned rodata, then exact metadata. The guest
    /// linker remains responsible for producing the layout/relocations. Host
    /// code must validate its result; this API never patches guest instructions.
    pub fn new(modules: &[ModuleGeometry],limits: LinkLimits) -> Result<Self,GrowthError> {
        if modules.is_empty() || modules.len() as u64 > limits.modules || limits.image == 0
            || limits.image > MAX || limits.image % PAGE != 0 || limits.metadata > MAX
            || limits.frames > MAX || limits.modules > MAX {
            return Err(GrowthError::Policy);
        }
        let (mut code,mut rodata,mut metadata,mut frames) = (0,0,0,0);
        for m in modules {
            if m.code == 0 || m.code % 8 != 0 || m.rodata % 8 != 0 || m.metadata % 8 != 0 {
                return Err(GrowthError::Geometry);
            }
            code=add(code,m.code)?;rodata=add(rodata,m.rodata)?;
            metadata=add(metadata,m.metadata)?;frames=add(frames,m.frames)?;
            limit(metadata,limits.metadata)?;limit(frames,limits.frames)?;
            limit(add(add(code,rodata)?,metadata)?,limits.image)?;
        }
        let rodata_at=round(code,16)?;
        let metadata_at=round(add(rodata_at,rodata)?,16)?;
        let used=add(metadata_at,metadata)?;
        let capacity=round(used,PAGE)?;
        limit(capacity,limits.image)?;
        Ok(Self {code,rodata_at,metadata_at,used,capacity,frames})
    }
}

/// Existing CALL PC20 displacement remains signed, in four-byte units.
/// More memory never relaxes instruction encodability.
pub fn call_displacement(from: u64,to: u64) -> Result<i32,GrowthError> {
    if from > MAX || to > MAX || from % 4 != 0 || to % 4 != 0 { return Err(GrowthError::Encoding); }
    let words=(to as i128-from as i128)/4;
    if !(-(1i128<<19)..(1i128<<19)).contains(&words) { return Err(GrowthError::Encoding); }
    Ok(words as i32)
}

#[cfg(test)]
mod tests;

pub mod workspace;
