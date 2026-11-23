//! Owned committed read bytes. Small CPU observations need no payload allocation.
//! Storage choice never supplies authority; Fabric constructs this after commit checks.

#[derive(Debug, Clone)]
pub enum ReadPayload {
    Heap(Vec<u8>),
    Inline { bytes: [u8; 8], len: u8 },
}

impl ReadPayload {
    pub(crate) fn scalar(data: &[u8]) -> Self {
        assert!(matches!(data.len(), 1 | 2 | 4 | 8));
        let mut bytes = [0; 8];
        bytes[..data.len()].copy_from_slice(data);
        Self::Inline { bytes, len: data.len() as u8 }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Heap(bytes) => bytes.as_slice(),
            Self::Inline { bytes, len } => &bytes[..usize::from(*len)],
        }
    }
}

impl std::ops::Deref for ReadPayload {
    type Target = [u8];
    fn deref(&self) -> &Self::Target { self.as_slice() }
}
