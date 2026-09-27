//! Phase 10.5 executable witnesses for explicit source bundles and the
//! include-only userspace preprocessor.

use std::fs;
use std::sync::OnceLock;

use super::aom::{AomModule, AOM_BINDING_IMPORT};
use super::ankald::run_ankald;
use super::dev_compiler::{
    bootstrap_development_ccb, bootstrap_extended_ccb,
    compile_c_to_aom_stage3, compile_c_with_ccb, compile_c_with_extended_ccb,
    CompiledCImage,
};
use super::source_bundle::{
    compile_source_bundle_to_aom_stage3, run_ankapp,
    AnkaPreprocessError, SourceBundle, SourceBundleCompileError, SourceBundleError,
    SourceBundleMember,
};

fn stage3_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/compiler/ankacc2_stage3.c"
    ))
}

fn ankapp_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/compiler/ankapp.c"
    ))
}

fn ankald_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/compiler/ankald.c"
    ))
}

fn canonical_ccb() -> &'static Vec<u8> {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        bootstrap_development_ccb().expect("Phase 10.5 must bootstrap canonical CC_B")
    })
}

fn extended_ccb() -> &'static Vec<u8> {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        bootstrap_extended_ccb().expect("Phase 10.5 must bootstrap extended CC_B")
    })
}

fn stage3_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_extended_ccb(extended_ccb(), stage3_source())
            .expect("extended CC_B must build the real Stage-3 AnkaCC2")
    })
}

fn ankapp_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(canonical_ccb(), ankapp_source())
            .expect("canonical CC_B must compile the real userspace ankapp")
    })
}

fn ankald_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(canonical_ccb(), ankald_source())
            .expect("canonical CC_B must compile the real userspace ankald")
    })
}

fn member(name: &str, text: &str) -> SourceBundleMember {
    SourceBundleMember::new(name, text.as_bytes().to_vec()).unwrap()
}

fn simple_bundle() -> SourceBundle {
    SourceBundle::new(
        "/src/main.c",
        [
            member("/src/main.c", "#include \"/include/anka/add.h\"\nint main(){return addone(41);}\n"),
            member("/include/anka/add.h", "int addone(int x);\n"),
        ],
    ).unwrap()
}

#[test]
fn p105_source_bundle_is_exact_unique_and_order_independent() {
    let a = SourceBundle::new(
        "/src/main.c",
        [member("/src/main.c", "int main(){return 0;}"), member("/h", "int x();")],
    ).unwrap();
    let b = SourceBundle::new(
        "/src/main.c",
        [member("/h", "int x();"), member("/src/main.c", "int main(){return 0;}")],
    ).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.get("/h").unwrap().bytes(), b"int x();");
    assert!(a.get("h").is_none(), "lookup is exact and has no path fallback");
}

#[test]
fn p105_duplicate_name_empty_bundle_and_missing_root_are_rejected() {
    assert_eq!(
        SourceBundle::new("/a", Vec::<SourceBundleMember>::new()),
        Err(SourceBundleError::EmptyBundle),
    );
    assert_eq!(
        SourceBundle::new("/missing", [member("/a", "x")]),
        Err(SourceBundleError::RootNotFound("/missing".to_string())),
    );
    assert_eq!(
        SourceBundle::new("/a", [member("/a", "x"), member("/a", "y")]),
        Err(SourceBundleError::DuplicateLogicalName("/a".to_string())),
    );
}

#[test]
fn p105_host_path_is_consumed_but_not_source_identity() {
    let path = std::env::temp_dir().join(format!("anka105-source-{}.h", std::process::id()));
    fs::write(&path, b"int answer();\n").unwrap();
    let from_host = SourceBundleMember::from_host_file("/include/answer.h", &path).unwrap();
    fs::remove_file(&path).unwrap();
    let from_bytes = SourceBundleMember::new("/include/answer.h", b"int answer();\n".to_vec()).unwrap();
    assert_eq!(from_host, from_bytes,
        "host pathname is not retained in source identity");
}

#[test]
fn p105_ccb_builds_real_userspace_ankapp() {
    let image = ankapp_image();
    assert!(image.code_size > 0);
    assert_eq!(image.lit_start, 0, "bootstrap ankapp remains code-only");
    assert_eq!(image.bytes.len() as u64, image.code_size);
    assert_eq!(image.process_slots_observed, 2,
        "building ankapp remains compile-only");
}

#[test]
fn p105_include_expansion_runs_inside_anka_and_is_deterministic() {
    let bundle = simple_bundle();
    let before = bundle.clone();
    let first = run_ankapp(&ankapp_image().bytes, &bundle).unwrap();
    let second = run_ankapp(&ankapp_image().bytes, &bundle).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.process_slots_observed, 1,
        "ankapp is the only runtime process and never executes source output");
    assert_eq!(bundle, before, "preprocessing may not mutate bundle bytes");
    let text = std::str::from_utf8(&first.bytes).unwrap();
    assert!(!text.contains("#include"));
    assert!(text.contains("int addone(int x);"));
    assert!(text.contains("int main(){return addone(41);}"));
}

#[test]
fn p105_missing_include_has_no_ambient_fallback() {
    let bundle = SourceBundle::new(
        "/src/main.c",
        [member("/src/main.c", "#include \"/not/in/bundle.h\"\nint main(){return 0;}\n")],
    ).unwrap();
    assert_eq!(
        run_ankapp(&ankapp_image().bytes, &bundle),
        Err(AnkaPreprocessError::PreprocessorRejected(2)),
    );
}

#[test]
fn p105_active_include_cycle_is_rejected() {
    let bundle = SourceBundle::new(
        "/a.h",
        [
            member("/a.h", "#include \"/b.h\"\n"),
            member("/b.h", "#include \"/a.h\"\n"),
        ],
    ).unwrap();
    assert_eq!(
        run_ankapp(&ankapp_image().bytes, &bundle),
        Err(AnkaPreprocessError::PreprocessorRejected(4)),
    );
}

#[test]
fn p105_include_depth_bound_is_enforced() {
    let mut members = Vec::new();
    for i in 0..33 {
        let name = format!("/h{i}");
        let text = if i == 32 {
            "int answer();\n".to_string()
        } else {
            format!("#include \"/h{}\"\n", i + 1)
        };
        members.push(SourceBundleMember::new(name, text.into_bytes()).unwrap());
    }
    let bundle = SourceBundle::new("/h0", members).unwrap();
    assert_eq!(
        run_ankapp(&ankapp_image().bytes, &bundle),
        Err(AnkaPreprocessError::PreprocessorRejected(5)),
    );
}

#[test]
fn p105_macros_and_conditionals_remain_unearned() {
    let define = SourceBundle::new(
        "/main.c",
        [member("/main.c", "#define X 1\nint main(){return X;}\n")],
    ).unwrap();
    assert_eq!(
        run_ankapp(&ankapp_image().bytes, &define),
        Err(AnkaPreprocessError::PreprocessorRejected(6)),
    );

    let conditional = SourceBundle::new(
        "/main.c",
        [member("/main.c", "#ifdef X\nint main(){return 1;}\n#endif\n")],
    ).unwrap();
    assert_eq!(
        run_ankapp(&ankapp_image().bytes, &conditional),
        Err(AnkaPreprocessError::PreprocessorRejected(6)),
    );
}


#[test]
fn p105_malformed_angle_include_is_rejected_without_search_semantics() {
    let bundle = SourceBundle::new(
        "/main.c",
        [member("/main.c", "#include </include/anka/add.h>\nint main(){return 0;}\n")],
    ).unwrap();
    assert_eq!(
        run_ankapp(&ankapp_image().bytes, &bundle),
        Err(AnkaPreprocessError::PreprocessorRejected(8)),
    );
}

#[test]
fn p105_effective_source_bound_is_enforced_before_stage3() {
    let payload = vec![b'x'; super::guest_compiler::SOURCE_SIZE as usize - 8];
    let bundle = SourceBundle::new(
        "/main.c",
        [
            member("/main.c", "#include \"/huge.h\"\n"),
            SourceBundleMember::new("/huge.h", payload).unwrap(),
        ],
    ).unwrap();
    assert_eq!(
        run_ankapp(&ankapp_image().bytes, &bundle),
        Err(AnkaPreprocessError::PreprocessorRejected(7)),
    );
}

#[test]
fn p105_failed_preprocessing_never_enters_stage3() {
    let bundle = SourceBundle::new(
        "/main.c",
        [member("/main.c", "#include \"/missing.h\"\nint main(){return 0;}\n")],
    ).unwrap();
    assert_eq!(
        compile_source_bundle_to_aom_stage3(&ankapp_image().bytes, &stage3_image().bytes, &bundle),
        Err(SourceBundleCompileError::Preprocess(
            AnkaPreprocessError::PreprocessorRejected(2)
        )),
    );
}

#[test]
fn p105_bundle_preprocesses_to_one_stage3_translation_unit_and_links() {
    let caller = compile_source_bundle_to_aom_stage3(
        &ankapp_image().bytes,
        &stage3_image().bytes,
        &simple_bundle(),
    ).expect("complete include expansion must admit Stage-3 compilation");
    let caller_aom = AomModule::parse(&caller.bytes).unwrap();
    assert_eq!(caller_aom.symbol("addone").unwrap().binding, AOM_BINDING_IMPORT,
        "included header remains declaration text in the same translation unit");

    let callee = compile_c_to_aom_stage3(
        &stage3_image().bytes,
        b"int addone(int x){return x+1;}",
    ).unwrap();
    let linked = run_ankald(
        &ankald_image().bytes,
        &[&caller.bytes, &callee.bytes],
        "main",
    ).expect("10.5 effective source must feed the existing 10.3/10.4 pipeline");
    assert!(linked.code_size > 0);
    assert_eq!(linked.process_slots_observed, 1);
}
