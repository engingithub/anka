//! Anka64 system image — a declarative boot construction manifest.
//!
//! A system image describes the initial software object graph:
//! logical objects, their contents, boot authority, and virtual
//! placement.  It is not a runtime snapshot, filesystem image, or
//! machine configuration.
//!
//! Key identity distinctions:
//!
//!   name ≠ ImageObjectRef ≠ ObjectId ≠ authority ≠ virtual placement ≠ physical placement
//!
//! The host creates the machine (Fabric); the loader resolves
//! image-local identity (ImageObjectRef) into runtime identity
//! (ObjectId) and chooses physical placement; kernel.boot()
//! establishes authoritative boot semantics.

use std::collections::BTreeMap;
use std::fmt;

use crate::anka64::state::{ObjectId, ObjectKind, Permissions};
use crate::anka64::os::{Kernel, BootInfo, BootGrant, BootMap, BootImage};
use crate::anka64::fabric::Fabric;
use crate::anka64::ankad;
use crate::anka64::guest_compiler::{
    SOURCE_SIZE, OUTPUT_SIZE, WS_SIZE, WS_LIT_POS, LAYOUT_WS,
};

// ───────────────────────────────────────────────────────────────────
// Bounded constants
// ───────────────────────────────────────────────────────────────────

pub const MAX_IMAGE_OBJECTS: u32 = 256;
pub const MAX_IMAGE_GRANTS: u32 = 1024;
pub const MAX_IMAGE_MAPS: u32 = 1024;
pub const MAX_IMAGE_NAME: u16 = 255;

// ───────────────────────────────────────────────────────────────────
// Wire-format record sizes (derived from field layouts)
// ───────────────────────────────────────────────────────────────────

pub const HEADER_SIZE: usize = 32;
pub const BOOT_IMAGE_SIZE: usize = 40;
pub const BOOT_LAYOUT_SIZE: usize = 40;
pub const GRANT_RECORD_SIZE: usize = 24;
pub const MAP_RECORD_SIZE: usize = 32;

pub const IMAGE_MAGIC: &[u8; 8] = b"ANKA64SI";
pub const IMAGE_VERSION: u32 = 1;

// ───────────────────────────────────────────────────────────────────
// Image-local identity
// ───────────────────────────────────────────────────────────────────

/// Image-local object reference — an index into `SystemImage.objects`.
///
/// This is not a runtime ObjectId, not a physical address, and not
/// a name.  It exists only within the context of a single image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImageObjectRef(pub u32);

impl fmt::Display for ImageObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImageRef({})", self.0)
    }
}

// ───────────────────────────────────────────────────────────────────
// Image object
// ───────────────────────────────────────────────────────────────────

/// A logical object in the system image.
///
/// `seal_after_load` is construction intent: the loader allocates
/// Active, initializes bytes, then seals through normal Fabric
/// operation.  We never serialize ObjectState::Sealed and pretend
/// we restored a runtime object.
///
/// Payload semantics: initial object bytes = contents || 0^(size - |contents|).
/// The loader enforces this via explicit zero-fill regardless of
/// prior Fabric memory contents.
#[derive(Debug, PartialEq, Eq)]
pub struct ImageObject {
    pub name: String,
    pub kind: ObjectKind,
    pub size: u64,
    pub contents: Vec<u8>,
    pub seal_after_load: bool,
}

// ───────────────────────────────────────────────────────────────────
// Boot manifest
// ───────────────────────────────────────────────────────────────────

/// Boot image descriptor — identifies the initial process's code object.
#[derive(Debug, PartialEq, Eq)]
pub struct ImageBootImage {
    pub obj: ImageObjectRef,
    pub code_offset: u64,
    pub code_size: u64,
    pub entry: u64,
    pub lit_start: u64,
}

/// Boot grant — initial authority for the boot process.
///
/// An object may appear in multiple grants with different ranges/
/// permissions.  Duplicate references are allowed.
#[derive(Debug, PartialEq, Eq)]
pub struct ImageBootGrant {
    pub obj: ImageObjectRef,
    pub offset: u64,
    pub size: u64,
    pub perms: Permissions,
}

/// Boot address map entry.
///
/// An object may appear in multiple maps at different virtual
/// addresses.  Duplicate references are allowed.
#[derive(Debug, PartialEq, Eq)]
pub struct ImageBootMap {
    pub vaddr: u64,
    pub size: u64,
    pub obj: ImageObjectRef,
    pub obj_offset: u64,
}

/// Complete boot manifest for the initial process.
#[derive(Debug, PartialEq, Eq)]
pub struct ImageBootInfo {
    pub image: ImageBootImage,
    pub grants: Vec<ImageBootGrant>,
    pub maps: Vec<ImageBootMap>,
    pub code_vaddr: u64,
    pub stack_vaddr: u64,
    pub stack_size: u64,
    pub trap_vaddr: u64,
}

// ───────────────────────────────────────────────────────────────────
// System image
// ───────────────────────────────────────────────────────────────────

/// A complete system image — a declarative boot construction manifest.
///
/// Contains the logical object graph and boot manifest.  Contains
/// no physical addresses, no runtime ObjectIds, no process slots,
/// no domains, and no generations.
#[derive(Debug, PartialEq, Eq)]
pub struct SystemImage {
    pub version: u32,
    pub objects: Vec<ImageObject>,
    pub boot: ImageBootInfo,
}

// ───────────────────────────────────────────────────────────────────
// Loaded system
// ───────────────────────────────────────────────────────────────────

/// Result of loading a system image into a Fabric.
///
/// The host calls `kernel.boot(&loaded.boot_info)` after loading.
/// Boot is not hidden inside the loader.
pub struct LoadedSystem {
    pub kernel: Kernel,
    pub boot_info: BootInfo,
    pub object_map: BTreeMap<ImageObjectRef, ObjectId>,
}

// ───────────────────────────────────────────────────────────────────
// Errors
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageError {
    // Wire-format / decode errors
    BadMagic,
    UnsupportedVersion(u32),
    Truncated,
    TrailingBytes,
    ReservedNonZero,
    InvalidObjectKind(u8),
    InvalidSealFlag(u8),
    InvalidPermissions(u8),
    InvalidUtf8Name,
    InvalidObjectRef(u32),
    ContentExceedsSize { content_len: u64, object_size: u64 },
    NameTooLong(usize),
    Overflow,

    // Encode validation errors
    TooManyObjects(usize),
    TooManyGrants(usize),
    TooManyMaps(usize),

    // Loader errors
    PhysBaseNotAligned(u64),
    PhysRangeExceedsFabric,
    PlacementFailed(ImageObjectRef),
    InitializationFailed(ImageObjectRef),
    SealFailed(ImageObjectRef),
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "bad magic (expected ANKA64SI)"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version {v}"),
            Self::Truncated => write!(f, "truncated image data"),
            Self::TrailingBytes => write!(f, "unexpected trailing bytes"),
            Self::ReservedNonZero => write!(f, "nonzero reserved field"),
            Self::InvalidObjectKind(k) => write!(f, "invalid object kind {k}"),
            Self::InvalidSealFlag(s) => write!(f, "invalid seal flag {s}"),
            Self::InvalidPermissions(p) => write!(f, "invalid permission bits 0x{p:02x}"),
            Self::InvalidUtf8Name => write!(f, "object name is not valid UTF-8"),
            Self::InvalidObjectRef(r) => write!(f, "object ref {r} out of range"),
            Self::ContentExceedsSize { content_len, object_size } =>
                write!(f, "content_len {content_len} > object size {object_size}"),
            Self::NameTooLong(n) => write!(f, "name length {n} exceeds maximum"),
            Self::Overflow => write!(f, "integer overflow in size computation"),
            Self::TooManyObjects(n) => write!(f, "{n} objects exceeds maximum {MAX_IMAGE_OBJECTS}"),
            Self::TooManyGrants(n) => write!(f, "{n} grants exceeds maximum {MAX_IMAGE_GRANTS}"),
            Self::TooManyMaps(n) => write!(f, "{n} maps exceeds maximum {MAX_IMAGE_MAPS}"),
            Self::PhysBaseNotAligned(b) => write!(f, "phys_base 0x{b:x} not page-aligned"),
            Self::PhysRangeExceedsFabric => write!(f, "physical range exceeds fabric memory"),
            Self::PlacementFailed(r) => write!(f, "placement failed for {r}"),
            Self::InitializationFailed(r) => write!(f, "initialization failed for {r}"),
            Self::SealFailed(r) => write!(f, "seal failed for {r}"),
        }
    }
}

// ───────────────────────────────────────────────────────────────────
// Loader
// ───────────────────────────────────────────────────────────────────

fn align_up(val: u64, align: u64) -> Option<u64> {
    let mask = align - 1;
    val.checked_add(mask).map(|v| v & !mask)
}

impl SystemImage {
    /// Load this image into a host-created Fabric at the given
    /// physical base address.
    ///
    /// The host owns machine instantiation (Fabric); the loader
    /// resolves image-local identity (ImageObjectRef) into runtime
    /// identity (ObjectId) and chooses physical placement.
    ///
    /// Fabric is consumed by value: on error the partially
    /// constructed machine is simply dropped (transactional).
    pub fn load_into(
        &self,
        mut fabric: Fabric,
        phys_base: u64,
    ) -> Result<LoadedSystem, ImageError> {
        self.validate_model()?;

        if phys_base & 0xFFF != 0 {
            return Err(ImageError::PhysBaseNotAligned(phys_base));
        }

        let mem_size = fabric.mem_size() as u64;
        let mut current_phys = phys_base;
        let mut object_map = BTreeMap::new();

        for (i, img_obj) in self.objects.iter().enumerate() {
            let obj_id = fabric.alloc_object(&img_obj.name, img_obj.size, img_obj.kind);

            // Verify physical range fits within Fabric
            let page_size = align_up(img_obj.size, 0x1000)
                .ok_or(ImageError::Overflow)?;
            let range_end = current_phys.checked_add(page_size)
                .ok_or(ImageError::Overflow)?;
            if range_end > mem_size {
                return Err(ImageError::PhysRangeExceedsFabric);
            }

            if !fabric.place_object(obj_id, current_phys) {
                return Err(ImageError::PlacementFailed(ImageObjectRef(i as u32)));
            }

            // Zero entire extent, then initialize contents prefix.
            // This guarantees contents || 0^(size - |contents|)
            // regardless of prior Fabric memory contents.
            if !fabric.zero_object_extent(obj_id) {
                return Err(ImageError::InitializationFailed(ImageObjectRef(i as u32)));
            }
            if !img_obj.contents.is_empty() {
                if !fabric.initialize_object(obj_id, 0, &img_obj.contents) {
                    return Err(ImageError::InitializationFailed(ImageObjectRef(i as u32)));
                }
            }

            if img_obj.seal_after_load {
                if !fabric.seal_object(obj_id) {
                    return Err(ImageError::SealFailed(ImageObjectRef(i as u32)));
                }
            }

            object_map.insert(ImageObjectRef(i as u32), obj_id);
            current_phys = range_end;
        }

        // Resolve boot manifest references
        let resolve = |r: ImageObjectRef| -> ObjectId {
            object_map[&r]
        };

        let boot_info = BootInfo {
            image: BootImage {
                obj: resolve(self.boot.image.obj),
                code_offset: self.boot.image.code_offset,
                code_size: self.boot.image.code_size,
                entry: self.boot.image.entry,
                lit_start: self.boot.image.lit_start,
            },
            grants: self.boot.grants.iter().map(|g| BootGrant {
                obj: resolve(g.obj),
                offset: g.offset,
                size: g.size,
                perms: g.perms,
            }).collect(),
            maps: self.boot.maps.iter().map(|m| BootMap {
                vaddr: m.vaddr,
                size: m.size,
                obj: resolve(m.obj),
                obj_offset: m.obj_offset,
            }).collect(),
            code_vaddr: self.boot.code_vaddr,
            stack_vaddr: self.boot.stack_vaddr,
            stack_size: self.boot.stack_size,
            trap_vaddr: self.boot.trap_vaddr,
        };

        // next_phys = max(end of image load, high watermark of pre-existing placements)
        let hwm = fabric.physical_high_watermark()
            .ok_or(ImageError::Overflow)?;
        let mut kernel = Kernel::new(fabric);
        kernel.next_phys = std::cmp::max(current_phys, hwm);

        Ok(LoadedSystem { kernel, boot_info, object_map })
    }

    /// Convenience helper: create a fresh Fabric and load at the
    /// default base address.
    pub fn instantiate(&self, mem_size: usize) -> Result<LoadedSystem, ImageError> {
        self.load_into(Fabric::new(mem_size), 0x100000)
    }
}

// ───────────────────────────────────────────────────────────────────
// Model validation (shared by encode and load_into)
// ───────────────────────────────────────────────────────────────────

impl SystemImage {
    /// Validate the in-memory model's structural constraints.
    ///
    /// This catches issues that would cause encode() or load_into()
    /// to fail: count bounds, name lengths, content sizes, and
    /// reference validity.  Does not validate boot semantics —
    /// that belongs to kernel.boot().
    fn validate_model(&self) -> Result<(), ImageError> {
        if self.version != IMAGE_VERSION {
            return Err(ImageError::UnsupportedVersion(self.version));
        }
        if self.objects.len() > MAX_IMAGE_OBJECTS as usize {
            return Err(ImageError::TooManyObjects(self.objects.len()));
        }
        if self.boot.grants.len() > MAX_IMAGE_GRANTS as usize {
            return Err(ImageError::TooManyGrants(self.boot.grants.len()));
        }
        if self.boot.maps.len() > MAX_IMAGE_MAPS as usize {
            return Err(ImageError::TooManyMaps(self.boot.maps.len()));
        }
        let obj_count = self.objects.len() as u32;

        for obj in &self.objects {
            if obj.name.len() > MAX_IMAGE_NAME as usize {
                return Err(ImageError::NameTooLong(obj.name.len()));
            }
            if obj.contents.len() as u64 > obj.size {
                return Err(ImageError::ContentExceedsSize {
                    content_len: obj.contents.len() as u64,
                    object_size: obj.size,
                });
            }
        }

        // Validate all ImageObjectRef values
        let check_ref = |r: ImageObjectRef| -> Result<(), ImageError> {
            if r.0 >= obj_count {
                Err(ImageError::InvalidObjectRef(r.0))
            } else {
                Ok(())
            }
        };

        check_ref(self.boot.image.obj)?;
        for g in &self.boot.grants {
            check_ref(g.obj)?;
            Permissions::from_bits_checked(g.perms.0 as u64)
                .ok_or(ImageError::InvalidPermissions(g.perms.0))?;
        }
        for m in &self.boot.maps {
            check_ref(m.obj)?;
        }

        Ok(())
    }
}

// ───────────────────────────────────────────────────────────────────
// Wire-format helpers
// ───────────────────────────────────────────────────────────────────

fn object_kind_to_wire(kind: ObjectKind) -> u8 {
    match kind {
        ObjectKind::Memory => 0,
        ObjectKind::Device => 1,
        ObjectKind::Ipc => 2,
    }
}

fn wire_to_object_kind(byte: u8) -> Result<ObjectKind, ImageError> {
    match byte {
        0 => Ok(ObjectKind::Memory),
        1 => Ok(ObjectKind::Device),
        2 => Ok(ObjectKind::Ipc),
        _ => Err(ImageError::InvalidObjectKind(byte)),
    }
}

fn seal_to_wire(seal: bool) -> u8 {
    if seal { 1 } else { 0 }
}

fn wire_to_seal(byte: u8) -> Result<bool, ImageError> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ImageError::InvalidSealFlag(byte)),
    }
}

/// Read helpers for the decoder — each returns the value and advances
/// the cursor, or returns Truncated.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], ImageError> {
        if self.remaining() < n {
            return Err(ImageError::Truncated);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, ImageError> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u16_le(&mut self) -> Result<u16, ImageError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u32_le(&mut self) -> Result<u32, ImageError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64_le(&mut self) -> Result<u64, ImageError> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
}

// ───────────────────────────────────────────────────────────────────
// Encoder
// ───────────────────────────────────────────────────────────────────

impl SystemImage {
    /// Encode this image into a deterministic canonical byte stream.
    ///
    /// Returns Err if the model violates representability constraints
    /// (too many objects, name too long, contents > size, etc.).
    pub fn encode(&self) -> Result<Vec<u8>, ImageError> {
        self.validate_model()?;

        // Pre-compute total size with checked arithmetic
        let fixed = HEADER_SIZE
            .checked_add(BOOT_IMAGE_SIZE).ok_or(ImageError::Overflow)?
            .checked_add(BOOT_LAYOUT_SIZE).ok_or(ImageError::Overflow)?;
        let grants_total = self.boot.grants.len()
            .checked_mul(GRANT_RECORD_SIZE).ok_or(ImageError::Overflow)?;
        let maps_total = self.boot.maps.len()
            .checked_mul(MAP_RECORD_SIZE).ok_or(ImageError::Overflow)?;
        let mut total = fixed
            .checked_add(grants_total).ok_or(ImageError::Overflow)?
            .checked_add(maps_total).ok_or(ImageError::Overflow)?;

        for obj in &self.objects {
            // name_len(2) + name + kind(1) + seal(1) + reserved(4) + size(8) + content_len(8) + content
            let obj_fixed = 2usize + obj.name.len() + 1 + 1 + 4 + 8 + 8 + obj.contents.len();
            total = total.checked_add(obj_fixed).ok_or(ImageError::Overflow)?;
        }

        let mut out = Vec::with_capacity(total);

        // ── Header (32 bytes) ──
        out.extend_from_slice(IMAGE_MAGIC);                                     // 8
        out.extend_from_slice(&self.version.to_le_bytes());                     // 4
        out.extend_from_slice(&(self.objects.len() as u32).to_le_bytes());      // 4
        out.extend_from_slice(&(self.boot.grants.len() as u32).to_le_bytes());  // 4
        out.extend_from_slice(&(self.boot.maps.len() as u32).to_le_bytes());    // 4
        out.extend_from_slice(&0u64.to_le_bytes());                             // 8 reserved

        // ── Boot image record (40 bytes) ──
        out.extend_from_slice(&self.boot.image.obj.0.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved
        out.extend_from_slice(&self.boot.image.code_offset.to_le_bytes());
        out.extend_from_slice(&self.boot.image.code_size.to_le_bytes());
        out.extend_from_slice(&self.boot.image.entry.to_le_bytes());
        out.extend_from_slice(&self.boot.image.lit_start.to_le_bytes());

        // ── Boot layout (40 bytes) ──
        out.extend_from_slice(&self.boot.code_vaddr.to_le_bytes());
        out.extend_from_slice(&self.boot.stack_vaddr.to_le_bytes());
        out.extend_from_slice(&self.boot.stack_size.to_le_bytes());
        out.extend_from_slice(&self.boot.trap_vaddr.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // reserved

        // ── Grant records (24 bytes each) ──
        for g in &self.boot.grants {
            out.extend_from_slice(&g.obj.0.to_le_bytes());
            out.push(g.perms.0);
            out.extend_from_slice(&[0u8; 3]); // reserved
            out.extend_from_slice(&g.offset.to_le_bytes());
            out.extend_from_slice(&g.size.to_le_bytes());
        }

        // ── Map records (32 bytes each) ──
        for m in &self.boot.maps {
            out.extend_from_slice(&m.obj.0.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // reserved
            out.extend_from_slice(&m.vaddr.to_le_bytes());
            out.extend_from_slice(&m.size.to_le_bytes());
            out.extend_from_slice(&m.obj_offset.to_le_bytes());
        }

        // ── Object records (variable) ──
        for obj in &self.objects {
            let name_bytes = obj.name.as_bytes();
            out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.push(object_kind_to_wire(obj.kind));
            out.push(seal_to_wire(obj.seal_after_load));
            out.extend_from_slice(&0u32.to_le_bytes()); // reserved
            out.extend_from_slice(&obj.size.to_le_bytes());
            out.extend_from_slice(&(obj.contents.len() as u64).to_le_bytes());
            out.extend_from_slice(&obj.contents);
        }

        debug_assert_eq!(out.len(), total);
        Ok(out)
    }
}

// ───────────────────────────────────────────────────────────────────
// Decoder
// ───────────────────────────────────────────────────────────────────

impl SystemImage {
    /// Decode a system image from canonical bytes.
    ///
    /// Validates the wire format only — boot semantics are validated
    /// by kernel.boot() (Rule 28).
    pub fn decode(data: &[u8]) -> Result<SystemImage, ImageError> {
        let mut r = Reader::new(data);

        // ── Header (32 bytes) ──
        let magic = r.read_bytes(8)?;
        if magic != IMAGE_MAGIC {
            return Err(ImageError::BadMagic);
        }
        let version = r.read_u32_le()?;
        if version != IMAGE_VERSION {
            return Err(ImageError::UnsupportedVersion(version));
        }
        let object_count = r.read_u32_le()?;
        if object_count > MAX_IMAGE_OBJECTS {
            return Err(ImageError::TooManyObjects(object_count as usize));
        }
        let grant_count = r.read_u32_le()?;
        if grant_count > MAX_IMAGE_GRANTS {
            return Err(ImageError::TooManyGrants(grant_count as usize));
        }
        let map_count = r.read_u32_le()?;
        if map_count > MAX_IMAGE_MAPS {
            return Err(ImageError::TooManyMaps(map_count as usize));
        }
        let reserved = r.read_u64_le()?;
        if reserved != 0 {
            return Err(ImageError::ReservedNonZero);
        }

        // ── Boot image record (40 bytes) ──
        let img_obj_ref = r.read_u32_le()?;
        let img_reserved = r.read_u32_le()?;
        if img_reserved != 0 {
            return Err(ImageError::ReservedNonZero);
        }
        let code_offset = r.read_u64_le()?;
        let code_size = r.read_u64_le()?;
        let entry = r.read_u64_le()?;
        let lit_start = r.read_u64_le()?;

        if img_obj_ref >= object_count {
            return Err(ImageError::InvalidObjectRef(img_obj_ref));
        }

        // ── Boot layout (40 bytes) ──
        let code_vaddr = r.read_u64_le()?;
        let stack_vaddr = r.read_u64_le()?;
        let stack_size = r.read_u64_le()?;
        let trap_vaddr = r.read_u64_le()?;
        let layout_reserved = r.read_u64_le()?;
        if layout_reserved != 0 {
            return Err(ImageError::ReservedNonZero);
        }

        // ── Grant records (24 bytes each) ──
        let mut grants = Vec::with_capacity(grant_count as usize);
        for _ in 0..grant_count {
            let obj_ref = r.read_u32_le()?;
            if obj_ref >= object_count {
                return Err(ImageError::InvalidObjectRef(obj_ref));
            }
            let perms_byte = r.read_u8()?;
            let perms = Permissions::from_bits_checked(perms_byte as u64)
                .ok_or(ImageError::InvalidPermissions(perms_byte))?;
            let res = r.read_bytes(3)?;
            if res != [0, 0, 0] {
                return Err(ImageError::ReservedNonZero);
            }
            let offset = r.read_u64_le()?;
            let size = r.read_u64_le()?;
            grants.push(ImageBootGrant {
                obj: ImageObjectRef(obj_ref),
                offset,
                size,
                perms,
            });
        }

        // ── Map records (32 bytes each) ──
        let mut maps = Vec::with_capacity(map_count as usize);
        for _ in 0..map_count {
            let obj_ref = r.read_u32_le()?;
            if obj_ref >= object_count {
                return Err(ImageError::InvalidObjectRef(obj_ref));
            }
            let map_reserved = r.read_u32_le()?;
            if map_reserved != 0 {
                return Err(ImageError::ReservedNonZero);
            }
            let vaddr = r.read_u64_le()?;
            let size = r.read_u64_le()?;
            let obj_offset = r.read_u64_le()?;
            maps.push(ImageBootMap {
                vaddr,
                size,
                obj: ImageObjectRef(obj_ref),
                obj_offset,
            });
        }

        // ── Object records (variable) ──
        let mut objects = Vec::with_capacity(object_count as usize);
        for _ in 0..object_count {
            let name_len = r.read_u16_le()?;
            if name_len > MAX_IMAGE_NAME {
                return Err(ImageError::NameTooLong(name_len as usize));
            }
            let name_bytes = r.read_bytes(name_len as usize)?;
            let name = std::str::from_utf8(name_bytes)
                .map_err(|_| ImageError::InvalidUtf8Name)?
                .to_string();
            let kind = wire_to_object_kind(r.read_u8()?)?;
            let seal_after_load = wire_to_seal(r.read_u8()?)?;
            let obj_reserved = r.read_u32_le()?;
            if obj_reserved != 0 {
                return Err(ImageError::ReservedNonZero);
            }
            let size = r.read_u64_le()?;
            let content_len = r.read_u64_le()?;
            if content_len > size {
                return Err(ImageError::ContentExceedsSize {
                    content_len,
                    object_size: size,
                });
            }
            let contents = r.read_bytes(content_len as usize)?.to_vec();
            objects.push(ImageObject {
                name,
                kind,
                size,
                contents,
                seal_after_load,
            });
        }

        // ── Reject trailing bytes ──
        if r.remaining() != 0 {
            return Err(ImageError::TrailingBytes);
        }

        Ok(SystemImage {
            version,
            objects,
            boot: ImageBootInfo {
                image: ImageBootImage {
                    obj: ImageObjectRef(img_obj_ref),
                    code_offset,
                    code_size,
                    entry,
                    lit_start,
                },
                grants,
                maps,
                code_vaddr,
                stack_vaddr,
                stack_size,
                trap_vaddr,
            },
        })
    }
}

// ───────────────────────────────────────────────────────────────────
// Production image builder
// ───────────────────────────────────────────────────────────────────

/// CCB_CODE_BASE: where CC_B's code is placed in the child's virtual space.
const CCB_CODE_BASE: u64 = 0x30000;

fn page_align(val: u64) -> u64 {
    (val + 0xFFF) & !0xFFF
}

/// Build a system image for the Anka compiler system.
///
/// The image contains 5 objects:
///   Ref 0: ankad supervisor code (Sealed)
///   Ref 1: CC_B compiler code (Sealed)
///   Ref 2: source (Active, length-prefixed)
///   Ref 3: output (Active, empty — zero-filled by loader)
///   Ref 4: workspace (Active, minimal WS_LIT_POS init)
///
/// The boot manifest boots ankad, which spawns CC_B to compile the
/// source and produce output.
pub fn build_compiler_system_image(ccb: &[u8], source: &[u8]) -> SystemImage {
    assert!(source.len() + 8 <= SOURCE_SIZE as usize,
        "source ({} + 8 header bytes) exceeds source object ({})",
        source.len(), SOURCE_SIZE);

    // Build ankad code for CC_B
    let ankad_code = ankad::build_ankad_code(ccb.len(), CCB_CODE_BASE);
    let ankad_size = page_align(ankad_code.len() as u64);
    let ccb_size = page_align(ccb.len() as u64);

    // Source: length-prefixed
    let mut source_contents = Vec::with_capacity(source.len() + 8);
    source_contents.extend_from_slice(&(source.len() as u64).to_le_bytes());
    source_contents.extend_from_slice(source);

    // Workspace: only WS_LIT_POS initialization (sparse)
    let ws_lit_offset = (WS_LIT_POS - LAYOUT_WS) as usize;
    let mut workspace_contents = vec![0u8; ws_lit_offset + 8];
    workspace_contents[ws_lit_offset..ws_lit_offset + 8]
        .copy_from_slice(&(OUTPUT_SIZE as u64).to_le_bytes());

    SystemImage {
        version: IMAGE_VERSION,
        objects: vec![
            // Ref 0: ankad code
            ImageObject {
                name: "ankad_code".to_string(),
                kind: ObjectKind::Memory,
                size: ankad_size,
                contents: ankad_code,
                seal_after_load: true,
            },
            // Ref 1: CC_B code
            ImageObject {
                name: "compiler_code".to_string(),
                kind: ObjectKind::Memory,
                size: ccb_size,
                contents: ccb.to_vec(),
                seal_after_load: true,
            },
            // Ref 2: source (length-prefixed, sparse)
            ImageObject {
                name: "source".to_string(),
                kind: ObjectKind::Memory,
                size: SOURCE_SIZE as u64,
                contents: source_contents,
                seal_after_load: false,
            },
            // Ref 3: output (empty, zero-filled by loader)
            ImageObject {
                name: "output".to_string(),
                kind: ObjectKind::Memory,
                size: OUTPUT_SIZE as u64,
                contents: vec![],
                seal_after_load: false,
            },
            // Ref 4: workspace (minimal WS_LIT_POS init, sparse)
            ImageObject {
                name: "workspace".to_string(),
                kind: ObjectKind::Memory,
                size: WS_SIZE as u64,
                contents: workspace_contents,
                seal_after_load: false,
            },
        ],
        boot: ImageBootInfo {
            image: ImageBootImage {
                obj: ImageObjectRef(0), // ankad
                code_offset: 0,
                code_size: ankad_size,
                entry: 0,
                lit_start: 0,
            },
            grants: vec![
                // CC_B: RX
                ImageBootGrant {
                    obj: ImageObjectRef(1),
                    offset: 0,
                    size: ccb_size,
                    perms: Permissions::RX,
                },
                // source: R
                ImageBootGrant {
                    obj: ImageObjectRef(2),
                    offset: 0,
                    size: SOURCE_SIZE as u64,
                    perms: Permissions::READ,
                },
                // output: RWS
                ImageBootGrant {
                    obj: ImageObjectRef(3),
                    offset: 0,
                    size: OUTPUT_SIZE as u64,
                    perms: Permissions::RWS,
                },
                // workspace: RW
                ImageBootGrant {
                    obj: ImageObjectRef(4),
                    offset: 0,
                    size: WS_SIZE as u64,
                    perms: Permissions::RW,
                },
            ],
            maps: vec![
                // source @ 0x07000
                ImageBootMap {
                    vaddr: 0x07000,
                    size: SOURCE_SIZE as u64,
                    obj: ImageObjectRef(2),
                    obj_offset: 0,
                },
                // workspace @ 0x0C000
                ImageBootMap {
                    vaddr: 0x0C000,
                    size: WS_SIZE as u64,
                    obj: ImageObjectRef(4),
                    obj_offset: 0,
                },
                // output @ 0x12000
                ImageBootMap {
                    vaddr: 0x12000,
                    size: OUTPUT_SIZE as u64,
                    obj: ImageObjectRef(3),
                    obj_offset: 0,
                },
                // compiler @ 0x30000
                ImageBootMap {
                    vaddr: ankad::SUPERVISOR_COMPILER_VADDR,
                    size: ccb_size,
                    obj: ImageObjectRef(1),
                    obj_offset: 0,
                },
            ],
            code_vaddr: 0,
            stack_vaddr: 0x50000,
            stack_size: 0x4000,
            trap_vaddr: 0x54000,
        },
    }
}
