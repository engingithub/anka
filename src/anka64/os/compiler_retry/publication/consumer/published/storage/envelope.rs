use super::*;
pub(super) const HEADER:usize=136;
pub(super) struct Envelope<'a> {
    pub manifest:Manifest,pub dependencies:&'a[PersistentDependency],header:[u8;HEADER],image:&'a[u8],
}
impl<'a> Envelope<'a> {
    pub fn new(image:&'a AnkaldLinkedImage,profile:ApplicationLinkProfile,id:PersistentLinkIdentity,
        dependencies:&'a[PersistentDependency])->Result<Self,StoreError>
    {
        let count=dependencies.len() as u64;let length=image.bytes.len() as u64;
        if count==0 || count>4096 || length==0 || image.code_size==0 || image.code_size%4!=0
            || image.code_size>image.lit_start || image.lit_start>length || image.entry>=image.code_size || image.entry%4!=0 {
            return Err(StoreError::InvalidRequest)
        }
        if [id.anchor,id.installation,id.artifact,id.generation,id.image,id.metadata,id.dependencies,id.provenance].contains(&0) {
            return Err(StoreError::Authority)
        }
        for d in dependencies {
            if d.anchor!=id.anchor || d.installation!=id.installation || d.artifact==0 || d.generation==0 || d.provenance==0 {
                return Err(StoreError::Authority)
            }
        }
        let size=length.checked_add(HEADER as u64+count*40).ok_or(StoreError::Capacity)?;
        let profile=match profile {ApplicationLinkProfile::Standard=>1,ApplicationLinkProfile::Large=>2};
        let manifest=Manifest{anchor:id.anchor,installation:id.installation,artifact:id.artifact,generation:id.generation,
            role:2,profile,size,image:id.image,metadata:id.metadata,dependencies:id.dependencies,provenance:id.provenance};
        let words=[1,2,profile,id.anchor,id.installation,id.artifact,id.generation,image.code_size,image.lit_start,
            image.entry,length,count,id.image,id.metadata,id.dependencies,id.provenance];
        let mut header=[0;HEADER];header[..8].copy_from_slice(b"ANKACS01");
        for (i,w) in words.iter().enumerate() {header[8+i*8..16+i*8].copy_from_slice(&w.to_le_bytes());}
        Ok(Self{manifest,dependencies,header,image:&image.bytes})
    }
    pub fn copy(&self,offset:u64,out:&mut[u8])->Result<(),StoreError> {
        if offset.checked_add(out.len() as u64).is_none_or(|end|end>self.manifest.size) {return Err(StoreError::InvalidRequest)}
        let mut pos=usize::try_from(offset).map_err(|_|StoreError::Capacity)?;
        let image_start=HEADER+self.dependencies.len()*40;
        for byte in out {
            *byte=if pos<HEADER {self.header[pos]} else if pos<image_start {
                let d=self.dependencies[(pos-HEADER)/40];let at=(pos-HEADER)%40;
                let words=[d.anchor,d.installation,d.artifact,d.generation,d.provenance];
                words[at/8].to_le_bytes()[at%8]
            } else {self.image[pos-image_start]};
            pos+=1;
        }
        Ok(())
    }
}
