//! Concrete directory profile 1 for the protected ABI-2 CC2 producer.
//! The fixed 24-KiB prefix retains scalar/parser scratch. All seven name tables
//! and the companion function-frame table live in described, disjoint tails.
use super::*;
pub const WORKSPACE_PROFILE: u64 = 1;
/// Supported effective-source bound for directory profile 1, independent of
/// workspace/output capacities. Shared owner/global quota can reject earlier.
pub const DIRECTORY_SOURCE_LIMIT: usize = 1024*1024-8;
pub const WORKSPACE_REQUEST_BYTES: usize = 1024;
pub const WORKSPACE_PREFIX: u64 = 24576;
const MAX_WORKSPACE: u64 = 1024*1024;
#[cfg(test)]
const STRIDES: [u64;8] = [80,16,40,24,48,40,24,64];

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct WorkspaceDirectory { words: [u64;32], capacity: u64 }
impl WorkspaceDirectory {
    pub fn new(counts: [u64;7],capacity_limit: u64) -> Result<Self,GrowthError> {
        if counts.iter().any(|&n| n==0 || n>4096)
            || capacity_limit>MAX_WORKSPACE { return Err(GrowthError::Policy); }
        let plan=WorkspacePlan::with_prefix(counts,capacity_limit,WORKSPACE_PREFIX)?;
        let mut words=[0u64;32];
        for kind in KINDS {
            let i=kind.index();let span=plan.table(kind);
            words[4*i]=span.offset;words[4*i+1]=span.count;words[4*i+2]=span.stride;
        }
        let at=round(plan.used(),8)?;
        let used=add(at,counts[0].checked_mul(64).ok_or(GrowthError::Overflow)?)?;
        let capacity=round(used,PAGE)?;limit(capacity,capacity_limit)?;
        words[28]=at;words[29]=counts[0];words[30]=64;
        Ok(Self {words,capacity})
    }
    /// Geometric count growth preserves all other tables and recomputes the
    /// companion frame directory. Page capacity need not change for a count to grow.
    pub(crate) fn grow_table(self, table:usize, minimum:u64) -> Result<Self,GrowthError> {
        if table>=7 {return Err(GrowthError::Index);}
        let mut counts=std::array::from_fn(|i|self.words[4*i+1]);
        if minimum<=counts[table] || minimum>4096 {return Err(GrowthError::Capacity);}
        counts[table]=minimum.max((counts[table]*2).min(4096));
        Self::new(counts,MAX_WORKSPACE)
    }
    pub fn capacity(self) -> u64 {self.capacity}
    pub fn words(self) -> [u64;32] {self.words}
    pub fn bytes(self) -> [u8;256] {
        let mut bytes=[0;256];
        for (w,b) in self.words.into_iter().zip(bytes.chunks_exact_mut(8)) {b.copy_from_slice(&w.to_le_bytes());}
        bytes
    }
    /// The complete directory is bound into the existing sealed plan, after
    /// the 22 base budget words. It is not inferred from output success.
    pub fn binding_words(self) -> [u64;35] {
        let mut words=[0;35];words[..3].copy_from_slice(&[0x57445331,WORKSPACE_PROFILE,self.capacity]);
        words[3..].copy_from_slice(&self.words);words
    }
    pub fn decode(bytes: &[u8],capacity: u64) -> Result<Self,GrowthError> {
        if bytes.len()!=256 {return Err(GrowthError::Geometry);}
        let mut words=[0u64;32];
        for (w,b) in words.iter_mut().zip(bytes.chunks_exact(8)) {*w=u64::from_le_bytes(b.try_into().unwrap());}
        let counts=std::array::from_fn(|i| words[4*i+1]);
        let canonical=Self::new(counts,capacity)?;
        if canonical.words!=words || canonical.capacity!=capacity {return Err(GrowthError::Geometry);}
        Ok(canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c31_directory_grows_functions_and_frame_table_together() {
        let d=WorkspaceDirectory::new([128,256,64,64,16,128,128],MAX_WORKSPACE).unwrap();
        assert_eq!(WorkspaceDirectory::decode(&d.bytes(),d.capacity()),Ok(d));
        let mut stop=WORKSPACE_PREFIX;
        for i in 0..8 {
            assert_eq!(d.words[4*i],stop);assert_eq!(d.words[4*i+2],STRIDES[i]);
            stop+=d.words[4*i+1]*STRIDES[i];
        }
        assert_eq!(d.words[29],128);assert_eq!(d.capacity(),round(stop,PAGE).unwrap());
        assert!(d.capacity()>24576);assert_eq!(d.binding_words()[3..],d.words);
    }
    #[test]
    fn c31_directory_rejects_overlap_reserved_words_stride_and_frame_mismatch() {
        let d=WorkspaceDirectory::new([64,128,32,32,16,64,64],MAX_WORKSPACE).unwrap();
        for (i,value) in [(0,0),(4,d.words[0]),(2,16),(3,1),(29,63),(30,8)] {
            let mut b=d.bytes();b[i*8..i*8+8].copy_from_slice(&(value as u64).to_le_bytes());
            assert!(WorkspaceDirectory::decode(&b,d.capacity()).is_err());
        }
        assert!(WorkspaceDirectory::decode(&d.bytes(),d.capacity()+4096).is_err());
    }
    #[test]
    fn c34_directory_bounds_all_counts_with_wide_struct_encoding() {
        for counts in [[64,128,32,32,4097,64,64],[0,128,32,32,16,64,64],
                       [64,4097,32,32,16,64,64],[u64::MAX,128,32,32,16,64,64]] {
            assert!(WorkspaceDirectory::new(counts,MAX_WORKSPACE).is_err());
        }
        assert!(WorkspaceDirectory::new([64,128,32,32,16,64,64],24576).is_err());
        for count in [17,901,4096] {
            let d=WorkspaceDirectory::new([64,128,32,32,count,64,64],MAX_WORKSPACE).unwrap();
            assert_eq!(WorkspaceDirectory::decode(&d.bytes(),d.capacity()),Ok(d));
        }
    }
}
