//! Conservative shared quota for the explicitly bounded preprocessor profile.
//! This accounts retained Rust payload/capacity, not allocator RSS or OS pages.
use super::*;
pub(crate) const MEMBERS:usize=256;
pub(crate) const FIXED_METADATA:u64=4*1024*1024;
pub(crate) const MEMBER_METADATA:u64=65536;

pub(crate) fn charge(image:&[u8],bundle:&SourceBundle,policy:PreprocessGrowthPolicy)
    ->Result<u64,AnkaPreprocessError> {
    if image.is_empty() || image.len() as u64>ANKAPP_MANIFEST_VADDR
        || bundle.is_empty() || bundle.len()>MEMBERS {return Err(AnkaPreprocessError::StoragePolicy);}
    let manifest=word_backing_len(manifest_semantic_len(bundle)?)?;
    // Reject aggregate impossible geometry before constructing the machine or
    // allocating transport copies. PM still decides exact placement thereafter.
    let members=bundle.members().try_fold(0u64,|n,m|
        n.checked_add(word_backing_len(m.bytes().len())?).ok_or(AnkaPreprocessError::SizeOverflow))?;
    if members>ANKAPP_PM_SIZE {return Err(AnkaPreprocessError::StoragePolicy);}
    // Covers RAM, bounded fixed pointer registry/CPU/trace storage, maps and
    // BTree descriptors per member (64 KiB conservative allowance), manifest
    // construction and its retained copy, plus output/copy staging at maximum.
    (ANKAPP_RAM_SIZE as u64).checked_add(FIXED_METADATA)
        .and_then(|n|n.checked_add((bundle.len() as u64+16)*MEMBER_METADATA))
        .and_then(|n|n.checked_add(manifest.checked_mul(2)?))
        .and_then(|n|n.checked_add(policy.maximum_capacity().checked_mul(2)?))
        .ok_or(AnkaPreprocessError::SizeOverflow)
}
