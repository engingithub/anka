//! Phase 10.6 concrete bootstrap witness. Host code transports and observes
//! exact bytes; ankapp, CC_B/CC2, and ankald execute inside Anka.
//! The same immutable source bundle is used for both self-host edges. No host
//! parser, resolver, linker, entry trampoline, or byte repair participates.

use super::ankald::{publish_linked_image, run_ankald, AnkaldError,
    AnkaldLinkedImage, AnkaldPublishError, LinkedArtifactKey};
use super::dev_compiler::{bootstrap_extended_ccb, compile_bootstrap_aom_with_linked_compiler,
    compile_bootstrap_aom_stage3, compile_c_with_ccb, compile_c_with_extended_ccb,
    CompiledCImage, DevelopmentCompileError};
use super::dev_runner::DeveloperExecutionAuthority;
use super::fabric::Fabric;
use super::placement::PhysicalPlacementManager;
use super::source_bundle::{ AnkaPreprocessError, SourceBundle,
    SourceBundleError, SourceBundleMember};
use super::state::ObjectState;

#[derive(Debug, PartialEq, Eq)]
pub enum Cc2FixedPointError {
    ExecutionAuthorityRequired,
    SourceBundle(SourceBundleError),
    Bootstrap(DevelopmentCompileError),
    Preprocess { generation: u8, error: AnkaPreprocessError },
    EffectiveSourceChanged,
    Compile { generation: u8, error: DevelopmentCompileError },
    Link { generation: u8, error: AnkaldError },
    Publish { generation: u8, error: AnkaldPublishError },
    PublicationIdentityChanged,
    ArtifactMismatch {
        first_byte_difference: Option<usize>,
        cc2_1_geometry: (u64, u64, u64, usize),
        cc2_2_geometry: (u64, u64, u64, usize),
    },
}

pub struct Cc2FixedPointWitness {
    pub seed: CompiledCImage,
    pub cc2_1: AnkaldLinkedImage,
    pub cc2_2: AnkaldLinkedImage,
    pub aom_1: Vec<u8>,
    pub aom_2: Vec<u8>,
    /// Exact distinct sealed publications, rather than friendly filenames.
    pub cc2_1_key: LinkedArtifactKey,
    pub cc2_2_key: LinkedArtifactKey,
    pub effective_source_bytes: usize,
    publication_fabric: Fabric,
    publication_placement: PhysicalPlacementManager,
    original_keys: (LinkedArtifactKey, LinkedArtifactKey),
    compiler_identity: AnkaldLinkedImage,
    preprocessor: CompiledCImage,
    linker: CompiledCImage,
}

/// Byte equality alone is insufficient: entry and segment geometry are part
/// of compiler identity. Process observation counts are not artifact content.
pub fn linked_compilers_identical(a: &AnkaldLinkedImage, b: &AnkaldLinkedImage) -> bool {
    a.bytes == b.bytes && a.code_size == b.code_size
        && a.lit_start == b.lit_start && a.entry == b.entry
}

/// Produce the entire lineage from the exact current compiler source. There
/// is deliberately no imported/compiler-selection argument. Provisioning the
/// development token is explicit caller policy; source names confer no power.
/// Failures return no closure witness and never manufacture a next generation.
pub fn witness_cc2_fixed_point(
    authority: Option<&DeveloperExecutionAuthority>,
    compiler_source: &[u8],
    preprocessor_source: &[u8],
    linker_source: &[u8],
) -> Result<Cc2FixedPointWitness, Cc2FixedPointError> {
    let authority = authority.ok_or(Cc2FixedPointError::ExecutionAuthorityRequired)?;
    let bundle = SourceBundle::new("/system/compiler/ankacc2_stage3.c", [
        SourceBundleMember::new("/system/compiler/ankacc2_stage3.c", compiler_source.to_vec())
            .map_err(Cc2FixedPointError::SourceBundle)?,
    ]).map_err(Cc2FixedPointError::SourceBundle)?;
    eprintln!("CC2 fixed-point: bootstrapping extended CC_B");
    let ccb = bootstrap_extended_ccb().map_err(Cc2FixedPointError::Bootstrap)?;
    let seed = compile_c_with_extended_ccb(&ccb, compiler_source)
        .map_err(Cc2FixedPointError::Bootstrap)?;
    eprintln!("CC2 fixed-point: CC2_0 ready (code={} backing={})", seed.code_size, seed.bytes.len());
    eprintln!("CC2 fixed-point: compiling preprocessor with CC_B");
    let preprocessor = compile_c_with_ccb(&ccb, preprocessor_source)
        .map_err(Cc2FixedPointError::Bootstrap)?;
    eprintln!("CC2 fixed-point: compiling linker with extended CC_B arena");
    let linker = compile_c_with_extended_ccb(&ccb, linker_source)
        .map_err(Cc2FixedPointError::Bootstrap)?;

    let effective_1 = super::source_bundle::run_ankapp_with_capacity(&preprocessor.bytes, &bundle,super::dev_compiler::DEVELOPMENT_COMPILER_SOURCE_SIZE-8)
        .map_err(|error| Cc2FixedPointError::Preprocess { generation: 1, error })?;
    // This first witness intentionally supports the current standalone source.
    // An include-bearing seed needs its own preprocessing admission first.
    if effective_1.bytes != compiler_source {
        return Err(Cc2FixedPointError::EffectiveSourceChanged);
    }
    eprintln!("CC2 fixed-point: compiling exact source with CC2_0");
    let aom_1 = compile_bootstrap_aom_stage3(&seed.bytes, &effective_1.bytes, authority)
        .map_err(|error| Cc2FixedPointError::Compile { generation: 1, error })?.bytes;
    let cc2_1 = run_ankald(&linker.bytes, &[&aom_1], "main")
        .map_err(|error| Cc2FixedPointError::Link { generation: 1, error })?;
    let mut fabric = Fabric::new(0x1000000);
    let mut placement = PhysicalPlacementManager::new(0x10000, 0x700000)
        .expect("fixed witness publication pool is valid");
    eprintln!("CC2 fixed-point: CC2_1 linked (code={} backing={} entry={})",
        cc2_1.code_size, cc2_1.bytes.len(), cc2_1.entry);
    let first = publish_linked_image(&mut fabric, &mut placement, "CC2_1", &cc2_1)
        .map_err(|error| Cc2FixedPointError::Publish { generation: 1, error })?;
    verify_publication(&fabric, &placement, first.key, &cc2_1)?;

    let effective_2 = super::source_bundle::run_ankapp_with_capacity(&preprocessor.bytes, &bundle,super::dev_compiler::DEVELOPMENT_COMPILER_SOURCE_SIZE-8)
        .map_err(|error| Cc2FixedPointError::Preprocess { generation: 2, error })?;
    if effective_1.bytes != effective_2.bytes {
        return Err(Cc2FixedPointError::EffectiveSourceChanged);
    }
    // Only the exact output of edge 0->1 can produce generation 2. No cached
    // seed or developer-imported compiler is consulted on this edge.
    eprintln!("CC2 fixed-point: compiling exact source with CC2_1");
    let aom_2 = compile_bootstrap_aom_with_linked_compiler(&cc2_1, &effective_2.bytes, authority)
        .map_err(|error| Cc2FixedPointError::Compile { generation: 2, error })?.bytes;
    let cc2_2 = run_ankald(&linker.bytes, &[&aom_2], "main")
        .map_err(|error| Cc2FixedPointError::Link { generation: 2, error })?;
    eprintln!("CC2 fixed-point: CC2_2 linked (code={} backing={} entry={})",
        cc2_2.code_size, cc2_2.bytes.len(), cc2_2.entry);
    let second = publish_linked_image(&mut fabric, &mut placement, "CC2_2", &cc2_2)
        .map_err(|error| Cc2FixedPointError::Publish { generation: 2, error })?;
    verify_publication(&fabric, &placement, first.key, &cc2_1)?;
    verify_publication(&fabric, &placement, second.key, &cc2_2)?;
    if !linked_compilers_identical(&cc2_1, &cc2_2) {
        let first_byte_difference = cc2_1.bytes.iter().zip(&cc2_2.bytes)
            .position(|(a, b)| a != b)
            .or_else(|| (cc2_1.bytes.len() != cc2_2.bytes.len())
                .then_some(cc2_1.bytes.len().min(cc2_2.bytes.len())));
        return Err(Cc2FixedPointError::ArtifactMismatch {
            first_byte_difference,
            cc2_1_geometry: (cc2_1.code_size, cc2_1.lit_start, cc2_1.entry, cc2_1.bytes.len()),
            cc2_2_geometry: (cc2_2.code_size, cc2_2.lit_start, cc2_2.entry, cc2_2.bytes.len()),
        });
    }
    Ok(Cc2FixedPointWitness { compiler_identity: cc2_1.clone(), seed, cc2_1, cc2_2, aom_1, aom_2,
        cc2_1_key: first.key, cc2_2_key: second.key,
        effective_source_bytes: effective_1.bytes.len(),
        publication_fabric: fabric,
        publication_placement: placement, original_keys: (first.key, second.key),
        preprocessor, linker })
}

fn verify_publication(
    fabric: &Fabric, placement: &PhysicalPlacementManager,
    key: LinkedArtifactKey, image: &AnkaldLinkedImage,
) -> Result<(), Cc2FixedPointError> {
    let object = fabric.objects.get(&key.object)
        .ok_or(Cc2FixedPointError::PublicationIdentityChanged)?;
    let extent = placement.allocated_extent(key.object)
        .ok_or(Cc2FixedPointError::PublicationIdentityChanged)?;
    if object.state != ObjectState::Sealed || object.generation != key.generation
        || fabric.read_physical(extent.base, image.bytes.len() as u64) != image.bytes
    {
        return Err(Cc2FixedPointError::PublicationIdentityChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p106_fixed_point_requires_bytes_and_all_execution_geometry() {
        let original = AnkaldLinkedImage { bytes: vec![0; 24], code_size: 16,
            lit_start: 16, entry: 8, process_slots_observed: 1 };
        assert!(linked_compilers_identical(&original, &original));
        let mut changed = original.clone(); changed.bytes[0] = 1;
        assert!(!linked_compilers_identical(&original, &changed));
        let mut changed = original.clone(); changed.code_size = 8;
        assert!(!linked_compilers_identical(&original, &changed));
        let mut changed = original.clone(); changed.lit_start = 0;
        assert!(!linked_compilers_identical(&original, &changed));
        let mut changed = original.clone(); changed.entry = 0;
        assert!(!linked_compilers_identical(&original, &changed));
    }

    #[test]
    fn p106_fixed_point_requires_explicit_authority_before_bootstrap() {
        assert!(matches!(witness_cc2_fixed_point(None, &[], &[], &[]),
            Err(Cc2FixedPointError::ExecutionAuthorityRequired)));
    }

    #[test]
    fn p106_concrete_cc2_generation_chain_closes_fixed_point() {
        let authority = DeveloperExecutionAuthority::provision();
        let witness = witness_cc2_fixed_point(Some(&authority),
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),
                "/userspace/system/compiler/ankacc2_stage3.c")),
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),
                "/userspace/system/compiler/ankapp.c")),
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),
                "/userspace/system/compiler/ankald.c")))
            .expect("Phase 10.6 must produce identical CC2_1 and CC2_2 linked compilers");
        assert!(linked_compilers_identical(&witness.cc2_1, &witness.cc2_2));
        assert_ne!(witness.cc2_1_key.object, witness.cc2_2_key.object);
        assert_eq!(witness.cc2_1.process_slots_observed, 1);
        assert_eq!(witness.cc2_2.process_slots_observed, 1);
    }
}

impl Cc2FixedPointWitness {
    pub(crate) fn application_tools(&self) -> Result<(&AnkaldLinkedImage, &CompiledCImage, &CompiledCImage), Cc2FixedPointError> {
        if (self.cc2_1_key, self.cc2_2_key) != self.original_keys
            || !linked_compilers_identical(&self.cc2_1, &self.compiler_identity)
            || !linked_compilers_identical(&self.cc2_2, &self.compiler_identity) {
            return Err(Cc2FixedPointError::PublicationIdentityChanged);
        }
        verify_publication(&self.publication_fabric, &self.publication_placement, self.cc2_1_key, &self.cc2_1)?;
        verify_publication(&self.publication_fabric, &self.publication_placement, self.cc2_2_key, &self.cc2_2)?;
        Ok((&self.compiler_identity, &self.preprocessor, &self.linker))
    }
}

impl core::fmt::Debug for Cc2FixedPointWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cc2FixedPointWitness")
            .field("cc2_1_key", &self.cc2_1_key)
            .field("cc2_2_key", &self.cc2_2_key)
            .field("effective_source_bytes", &self.effective_source_bytes)
            .finish_non_exhaustive()
    }
}
