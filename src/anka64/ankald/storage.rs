//! Conservative retained-payload/capacity quota, not allocator RSS.
use super::*;
pub(crate) fn linker_storage_charge(tool:&[u8],modules:&[ValidatedPointerModule],
    profile:ApplicationLinkProfile)->Result<u64,AnkaldError> {
    storage_charge(tool.len(),modules.len(),modules.iter().try_fold(0u64,|n,m|
        n.checked_add(m.bytes().len() as u64).ok_or(AnkaldError::SizeOverflow))?,profile)
}
fn storage_charge(tool:usize,modules:usize,total:u64,profile:ApplicationLinkProfile)
    ->Result<u64,AnkaldError> {
    if tool==0 || tool as u64>ANKALD_CONTROL_VADDR || modules==0 || modules>4096
        || total==0 || total>ANKALD_PM_SIZE {return Err(AnkaldError::InvalidProtectedLayout);}
    // RAM contains code, inputs, scratch, stack and trap. Fixed allowance covers
    // bounded scalar registry/CPU/trace state. Per-module allowance covers maps,
    // capabilities, placement and descriptors. Staging's separate 32*input
    // allowance covers simultaneous module and linked-program validation.
    // Two max images cover temporary byte captures; retained image is separate.
    let control=CTRL_PREFIX_SIZE as u64+modules as u64*MODULE_DESCRIPTOR_SIZE as u64+64;
    (ANKALD_RAM_SIZE as u64).checked_add(4*1024*1024)
        .and_then(|n|n.checked_add((modules as u64+16)*65536))
        .and_then(|n|n.checked_add(2*control))
        .and_then(|n|n.checked_add(2*profile.internal().image_limit()))
        .ok_or(AnkaldError::SizeOverflow)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c2_linker_storage_geometry_and_profile_are_checked_before_machine() {
        let s=ApplicationLinkProfile::Standard;
        for (tool,n,total) in [(0,1,1),(131073,1,1),(1,0,1),(1,4097,1),(1,1,0),(1,1,0x700001)] {
            assert!(storage_charge(tool,n,total,s).is_err());
        }
        let standard=storage_charge(131072,1,0x700000,s).unwrap();
        assert_eq!(standard,0x1000000+4*1024*1024+17*65536+2*(128+16+64)+2*1024*1024);
        assert_eq!(storage_charge(131072,1,0x700000,ApplicationLinkProfile::Large).unwrap(),standard+2*1024*1024);
        assert!(storage_charge(1,4096,0x700000,s).unwrap()>standard);
    }
}
