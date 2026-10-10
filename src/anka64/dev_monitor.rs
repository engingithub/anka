//! Interactive Anka64 development monitor (Phase 9.3h.4).
//!
//! This is intentionally a thin command layer over the already-closed 9.3h
//! mechanisms:
//!
//!   `load bin` -> 9.3h.1 transactional ingress
//!   `compile`  -> 9.3h.2 CC_B compile-only path
//!   `run`      -> 9.3h.3 explicit execution authority + SYS_SPAWN/SYS_WAIT
//!   `aom`      -> 10.3 Stage-3 compile-only AOM emission
//!   `link`     -> 10.4 ordinary userspace ankald linking
//!   `dump`     -> host-side observation/export of exact toolchain bytes
//!
//! The monitor adds no new authority rule.  Entering a development command is
//! the explicit host/developer act that provisions the corresponding short-
//! lived development token; the token is never guest authority.  Phase-10
//! toolchain artifacts are kept in a separate host-side debug store and are
//! never registered as executable artifacts merely because they were emitted
//! or linked.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use super::ankald::{run_ankald, AnkaldError};
use super::dev_compiler::{
    bootstrap_development_ccb, bootstrap_extended_ccb, compile_c_to_aom_stage3,
    compile_c_with_ccb, compile_c_with_extended_ccb, CompiledCImage, DevelopmentCompileError,
};
use super::dev_runner::{
    run_registered_artifact, DeveloperExecutionAuthority, DevelopmentRunError,
};
use super::dev_shell::{
    DevelopmentArtifactKind, DevelopmentArtifactLoader, DevelopmentMode,
    DevelopmentShellError, DeveloperIngressAuthority,
};
use super::fabric::Fabric;
use super::os::ProcessResult;
use super::placement::{PhysicalPlacementManager, PlacementError};

/// Persistent development-machine RAM.  The PM owns only the lower half; the
/// upper half remains available for transient kernel stack/trap allocations
/// made by the ordinary 9.3h.3 run path.
pub const DEVELOPMENT_SHELL_RAM: usize = 0x0200_0000; // 32 MiB
pub const DEVELOPMENT_SHELL_PM_BASE: u64 = 0x0001_0000;
pub const DEVELOPMENT_SHELL_PM_SIZE: u64 = 0x0100_0000; // 16 MiB

const BANNER: &str = "Anka64 Development Shell — phase 10 toolchain debug surface\nType 'help' for commands.";

const HELP: &str = "\
commands:
  compile <source.c> [name]       compile host C through canonical CC_B
  load bin <file> [name]         import raw Anka64 bytecode
  run <name|/logical/path>        run via explicit authority + SYS_SPAWN/SYS_WAIT

  cc2 bootstrap [name]           build/cache Stage-3 AnkaCC2; optionally retain exact image
  cc2 import <host-file> [name]  cache a prebuilt code-only Stage-3 image; optionally retain it
  aom <source.c> [name]          compile one TU through Stage 3 and retain exact AOM bytes
  link <name> <entry> <aom>...   run userspace ankald over retained AOMs
  tool-artifacts                 list retained AOM/linked debug artifacts
  dump <name> <host-file>        write exact retained toolchain bytes to a host file

  artifacts                      list registered executable development artifacts
  objects                        list persistent Fabric objects
  placements                     list PM allocations and free extents
  help                           show this help
  quit | exit                    leave the development shell

source paths may be rooted at userspace/ or relative to the configured
userspace root.  `aom` and `link` expose already-closed Phase 10.3/10.4
mechanisms only; they do not register or execute their outputs.  `dump` is an
observation/export operation for exact-byte comparison during later bootstrap
work.  The ordinary `compile` command still never runs its output.";

#[derive(Debug, PartialEq, Eq)]
pub enum DevelopmentMonitorError {
    UnterminatedQuote,
    UnknownCommand(String),
    Usage(&'static str),
    CannotDeriveArtifactName,
    ToolArtifactAlreadyRegistered(String),
    ToolArtifactNotFound(String),
    ToolArtifactWrongKind(String),
    HostRead(std::io::ErrorKind),
    HostWrite(std::io::ErrorKind),
    Placement(PlacementError),
    CompilerBootstrap(DevelopmentCompileError),
    ToolchainCompile(DevelopmentCompileError),
    Linker(AnkaldError),
    Artifact(DevelopmentShellError),
    Run(DevelopmentRunError),
}

impl fmt::Display for DevelopmentMonitorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnterminatedQuote => write!(f, "unterminated quoted argument"),
            Self::UnknownCommand(cmd) => write!(f, "unknown command '{cmd}'"),
            Self::Usage(usage) => write!(f, "usage: {usage}"),
            Self::CannotDeriveArtifactName => write!(f, "cannot derive artifact name from path"),
            Self::ToolArtifactAlreadyRegistered(name) => write!(f, "toolchain artifact '{name}' already exists"),
            Self::ToolArtifactNotFound(name) => write!(f, "toolchain artifact '{name}' was not found"),
            Self::ToolArtifactWrongKind(name) => write!(f, "toolchain artifact '{name}' is not an AOM module"),
            Self::HostRead(kind) => write!(f, "host read failed: {kind:?}"),
            Self::HostWrite(kind) => write!(f, "host write failed: {kind:?}"),
            Self::Placement(err) => write!(f, "placement setup failed: {err:?}"),
            Self::CompilerBootstrap(err) => write!(f, "compiler bootstrap failed: {err:?}"),
            Self::ToolchainCompile(err) => write!(f, "toolchain compile failed: {err:?}"),
            Self::Linker(err) => write!(f, "ankald failed: {err:?}"),
            Self::Artifact(err) => write!(f, "artifact operation failed: {err:?}"),
            Self::Run(err) => write!(f, "run failed: {err:?}"),
        }
    }
}

/// Result of one parsed command.  `run` is deliberately synchronous, so no
/// process handle escapes into this UI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevelopmentCommandResult {
    Continue(String),
    Quit,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DevelopmentToolArtifactKind {
    Compiler,
    Aom,
    Linked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DevelopmentToolArtifact {
    kind: DevelopmentToolArtifactKind,
    bytes: Vec<u8>,
    code_size: Option<u64>,
    lit_start: Option<u64>,
    entry: Option<u64>,
}

/// Stateful host-development session.
///
/// The executable-development state remains the 9.3h artifact machine:
/// Fabric, PM, and registry.  Phase-10 compiler/AOM/linked bytes live in a
/// separate host-side observation store and never become executable authority
/// merely by appearing there.  Compiler images are lazily bootstrapped and
/// cached for repeated toolchain-debug commands.
pub struct DevelopmentShellSession {
    userspace_root: PathBuf,
    fabric: Fabric,
    placement: PhysicalPlacementManager,
    loader: DevelopmentArtifactLoader,
    ccb_image: Option<Vec<u8>>,
    extended_ccb_image: Option<Vec<u8>>,
    stage3_image: Option<CompiledCImage>,
    ankald_image: Option<CompiledCImage>,
    tool_artifacts: BTreeMap<String, DevelopmentToolArtifact>,
}

impl DevelopmentShellSession {
    pub fn new<P: AsRef<Path>>(userspace_root: P) -> Result<Self, DevelopmentMonitorError> {
        let placement = PhysicalPlacementManager::new(
            DEVELOPMENT_SHELL_PM_BASE,
            DEVELOPMENT_SHELL_PM_SIZE,
        ).map_err(DevelopmentMonitorError::Placement)?;

        Ok(Self {
            userspace_root: userspace_root.as_ref().to_path_buf(),
            fabric: Fabric::new(DEVELOPMENT_SHELL_RAM),
            placement,
            loader: DevelopmentArtifactLoader::new(DevelopmentMode::Development),
            ccb_image: None,
            extended_ccb_image: None,
            stage3_image: None,
            ankald_image: None,
            tool_artifacts: BTreeMap::new(),
        })
    }

    pub fn userspace_root(&self) -> &Path {
        &self.userspace_root
    }

    pub fn loader(&self) -> &DevelopmentArtifactLoader {
        &self.loader
    }

    pub fn fabric(&self) -> &Fabric {
        &self.fabric
    }

    pub fn placement(&self) -> &PhysicalPlacementManager {
        &self.placement
    }

    pub fn compiler_ready(&self) -> bool {
        self.ccb_image.is_some()
    }

    /// Execute one shell line.  The original commands remain thin 9.3h
    /// wrappers.  Phase-10 debug commands call the already-closed Stage-3 and
    /// ankald APIs and retain only host-side observation bytes.
    pub fn execute_line(
        &mut self,
        line: &str,
    ) -> Result<DevelopmentCommandResult, DevelopmentMonitorError> {
        let args = tokenize(line)?;
        if args.is_empty() {
            return Ok(DevelopmentCommandResult::Continue(String::new()));
        }

        match args[0].as_str() {
            "help" => {
                require_arity(&args, 1, "help")?;
                Ok(DevelopmentCommandResult::Continue(HELP.to_string()))
            }
            "quit" | "exit" => {
                require_arity(&args, 1, "quit")?;
                Ok(DevelopmentCommandResult::Quit)
            }
            "compile" => self.command_compile(&args),
            "load" => self.command_load(&args),
            "run" => self.command_run(&args),
            "cc2" => self.command_cc2(&args),
            "aom" => self.command_aom(&args),
            "link" => self.command_link(&args),
            "dump" => self.command_dump(&args),
            "tool-artifacts" => {
                require_arity(&args, 1, "tool-artifacts")?;
                Ok(DevelopmentCommandResult::Continue(self.format_tool_artifacts()))
            }
            "artifacts" => {
                require_arity(&args, 1, "artifacts")?;
                Ok(DevelopmentCommandResult::Continue(self.format_artifacts()))
            }
            "objects" => {
                require_arity(&args, 1, "objects")?;
                Ok(DevelopmentCommandResult::Continue(self.format_objects()))
            }
            "placements" => {
                require_arity(&args, 1, "placements")?;
                Ok(DevelopmentCommandResult::Continue(self.format_placements()))
            }
            other => Err(DevelopmentMonitorError::UnknownCommand(other.to_string())),
        }
    }

    /// Run an interactive line-oriented session.  Command errors are printed
    /// and the shell remains alive; EOF and `quit` exit normally.
    pub fn run_interactive<R: BufRead, W: Write>(
        &mut self,
        mut input: R,
        mut output: W,
    ) -> io::Result<()> {
        writeln!(output, "{BANNER}")?;
        writeln!(output, "userspace: {}", self.userspace_root.display())?;

        let mut line = String::new();
        loop {
            write!(output, "anka64> ")?;
            output.flush()?;
            line.clear();
            if input.read_line(&mut line)? == 0 {
                writeln!(output)?;
                return Ok(());
            }

            match self.execute_line(&line) {
                Ok(DevelopmentCommandResult::Continue(text)) => {
                    if !text.is_empty() {
                        writeln!(output, "{text}")?;
                    }
                }
                Ok(DevelopmentCommandResult::Quit) => return Ok(()),
                Err(err) => writeln!(output, "error: {err}")?,
            }
        }
    }

    fn command_compile(
        &mut self,
        args: &[String],
    ) -> Result<DevelopmentCommandResult, DevelopmentMonitorError> {
        if args.len() != 2 && args.len() != 3 {
            return Err(DevelopmentMonitorError::Usage("compile <source.c> [name]"));
        }
        let source = self.resolve_host_path(&args[1]);
        let name = if args.len() == 3 {
            args[2].clone()
        } else {
            derive_name(&source)?
        };

        let bootstrapped = self.ensure_canonical_ccb()?;
        let ccb = self.ccb_image.as_deref().expect("CC_B initialized above");
        let ingress = DeveloperIngressAuthority::provision();
        let key = self.loader.compile_c_file(
            Some(&ingress),
            &mut self.fabric,
            &mut self.placement,
            &name,
            &self.userspace_root,
            &source,
            ccb,
        ).map_err(DevelopmentMonitorError::Artifact)?;

        let artifact = self.loader.registry().get(&name)
            .expect("successful compile must publish registry entry");
        let logical = artifact.logical_path.as_deref().unwrap_or("-");
        let prefix = if bootstrapped { "bootstrapped CC_B; " } else { "" };
        Ok(DevelopmentCommandResult::Continue(format!(
            "{prefix}compiled {} as '{}' -> {} (object={} generation={} code={} bytes)",
            source.display(), name, logical, key.object.0, key.generation.0,
            artifact.code_size,
        )))
    }

    fn ensure_canonical_ccb(&mut self) -> Result<bool, DevelopmentMonitorError> {
        let bootstrapped = self.ccb_image.is_none();
        if self.ccb_image.is_none() {
            self.ccb_image = Some(
                bootstrap_development_ccb()
                    .map_err(DevelopmentMonitorError::CompilerBootstrap)?,
            );
        }
        Ok(bootstrapped)
    }

    fn ensure_extended_ccb(&mut self) -> Result<bool, DevelopmentMonitorError> {
        let bootstrapped = self.extended_ccb_image.is_none();
        if self.extended_ccb_image.is_none() {
            self.extended_ccb_image = Some(
                bootstrap_extended_ccb()
                    .map_err(DevelopmentMonitorError::CompilerBootstrap)?,
            );
        }
        Ok(bootstrapped)
    }

    fn ensure_stage3(&mut self) -> Result<bool, DevelopmentMonitorError> {
        let bootstrapped = self.stage3_image.is_none();
        if self.stage3_image.is_none() {
            self.ensure_extended_ccb()?;
            let ccb = self.extended_ccb_image.as_deref()
                .expect("extended CC_B initialized above");
            let source = fs::read(self.userspace_root.join("system/compiler/ankacc2_stage3.c"))
                .map_err(|err| DevelopmentMonitorError::HostRead(err.kind()))?;
            self.stage3_image = Some(
                compile_c_with_extended_ccb(ccb, &source)
                    .map_err(DevelopmentMonitorError::ToolchainCompile)?,
            );
        }
        Ok(bootstrapped)
    }

    fn ensure_ankald(&mut self) -> Result<bool, DevelopmentMonitorError> {
        let bootstrapped = self.ankald_image.is_none();
        if self.ankald_image.is_none() {
            self.ensure_canonical_ccb()?;
            let ccb = self.ccb_image.as_deref().expect("canonical CC_B initialized above");
            let source = fs::read(self.userspace_root.join("system/compiler/ankald.c"))
                .map_err(|err| DevelopmentMonitorError::HostRead(err.kind()))?;
            self.ankald_image = Some(
                compile_c_with_ccb(ccb, &source)
                    .map_err(DevelopmentMonitorError::ToolchainCompile)?,
            );
        }
        Ok(bootstrapped)
    }

    fn command_cc2(
        &mut self,
        args: &[String],
    ) -> Result<DevelopmentCommandResult, DevelopmentMonitorError> {
        if args.len() >= 2 && args[1] == "bootstrap" {
            if args.len() != 2 && args.len() != 3 {
                return Err(DevelopmentMonitorError::Usage("cc2 bootstrap [name]"));
            }
            if args.len() == 3 && self.tool_artifacts.contains_key(&args[2]) {
                return Err(DevelopmentMonitorError::ToolArtifactAlreadyRegistered(args[2].clone()));
            }
            let bootstrapped = self.ensure_stage3()?;
            let image = self.stage3_image.as_ref().expect("Stage 3 initialized above");
            let retained = if args.len() == 3 {
                let name = args[2].clone();
                self.tool_artifacts.insert(name.clone(), DevelopmentToolArtifact {
                    kind: DevelopmentToolArtifactKind::Compiler,
                    bytes: image.bytes.clone(),
                    code_size: Some(image.code_size),
                    lit_start: Some(image.lit_start),
                    entry: Some(0),
                });
                format!("; retained as '{name}'")
            } else {
                String::new()
            };
            return Ok(DevelopmentCommandResult::Continue(format!(
                "{}Stage-3 AnkaCC2 ready (code={} bytes backing={} bytes functions={}){}",
                if bootstrapped { "bootstrapped extended CC_B; " } else { "" },
                image.code_size,
                image.bytes.len(),
                image.function_count,
                retained,
            )));
        }

        if args.len() >= 2 && args[1] == "import" {
            if args.len() != 3 && args.len() != 4 {
                return Err(DevelopmentMonitorError::Usage("cc2 import <host-file> [name]"));
            }
            if args.len() == 4 && self.tool_artifacts.contains_key(&args[3]) {
                return Err(DevelopmentMonitorError::ToolArtifactAlreadyRegistered(args[3].clone()));
            }
            let path = PathBuf::from(&args[2]);
            let bytes = fs::read(&path)
                .map_err(|err| DevelopmentMonitorError::HostRead(err.kind()))?;
            if bytes.is_empty() {
                return Err(DevelopmentMonitorError::ToolchainCompile(
                    DevelopmentCompileError::EmptyCompilerImage,
                ));
            }
            if bytes.len() > 0x1ffff {
                return Err(DevelopmentMonitorError::ToolchainCompile(
                    DevelopmentCompileError::CompilerImageTooLarge,
                ));
            }
            let code_size = bytes.len() as u64;
            self.stage3_image = Some(CompiledCImage {
                bytes: bytes.clone(),
                code_size,
                lit_start: 0,
                function_count: 0,
                process_slots_observed: 0,
            });
            let retained = if args.len() == 4 {
                let name = args[3].clone();
                self.tool_artifacts.insert(name.clone(), DevelopmentToolArtifact {
                    kind: DevelopmentToolArtifactKind::Compiler,
                    bytes,
                    code_size: Some(code_size),
                    lit_start: Some(0),
                    entry: Some(0),
                });
                format!("; retained as '{name}'")
            } else {
                String::new()
            };
            return Ok(DevelopmentCommandResult::Continue(format!(
                "imported Stage-3 AnkaCC2 from {} (code={} bytes; function count not encoded){}",
                path.display(), code_size, retained,
            )));
        }

        Err(DevelopmentMonitorError::Usage(
            "cc2 bootstrap [name] | cc2 import <host-file> [name]",
        ))
    }

    fn command_aom(
        &mut self,
        args: &[String],
    ) -> Result<DevelopmentCommandResult, DevelopmentMonitorError> {
        if args.len() != 2 && args.len() != 3 {
            return Err(DevelopmentMonitorError::Usage("aom <source.c> [name]"));
        }
        let source_path = self.resolve_host_path(&args[1]);
        let name = if args.len() == 3 { args[2].clone() } else { derive_name(&source_path)? };
        if self.tool_artifacts.contains_key(&name) {
            return Err(DevelopmentMonitorError::ToolArtifactAlreadyRegistered(name));
        }
        let source = fs::read(&source_path)
            .map_err(|err| DevelopmentMonitorError::HostRead(err.kind()))?;
        let bootstrapped = self.ensure_stage3()?;
        let stage3 = self.stage3_image.as_ref().expect("Stage 3 initialized above");
        let compiled = compile_c_to_aom_stage3(&stage3.bytes, &source)
            .map_err(DevelopmentMonitorError::ToolchainCompile)?;
        let size = compiled.bytes.len();
        self.tool_artifacts.insert(name.clone(), DevelopmentToolArtifact {
            kind: DevelopmentToolArtifactKind::Aom,
            bytes: compiled.bytes,
            code_size: None,
            lit_start: None,
            entry: None,
        });
        Ok(DevelopmentCommandResult::Continue(format!(
            "{}compiled {} as AOM '{}' ({} bytes)",
            if bootstrapped { "bootstrapped Stage-3 AnkaCC2; " } else { "" },
            source_path.display(), name, size,
        )))
    }

    fn command_link(
        &mut self,
        args: &[String],
    ) -> Result<DevelopmentCommandResult, DevelopmentMonitorError> {
        if args.len() < 4 {
            return Err(DevelopmentMonitorError::Usage("link <name> <entry> <aom>..."));
        }
        let name = args[1].clone();
        if self.tool_artifacts.contains_key(&name) {
            return Err(DevelopmentMonitorError::ToolArtifactAlreadyRegistered(name));
        }
        let entry = args[2].clone();
        let mut modules = Vec::with_capacity(args.len() - 3);
        for module_name in &args[3..] {
            let artifact = self.tool_artifacts.get(module_name)
                .ok_or_else(|| DevelopmentMonitorError::ToolArtifactNotFound(module_name.clone()))?;
            if artifact.kind != DevelopmentToolArtifactKind::Aom {
                return Err(DevelopmentMonitorError::ToolArtifactWrongKind(module_name.clone()));
            }
            modules.push(artifact.bytes.clone());
        }
        let bootstrapped = self.ensure_ankald()?;
        let linker = self.ankald_image.as_ref().expect("ankald initialized above");
        let module_refs: Vec<&[u8]> = modules.iter().map(Vec::as_slice).collect();
        let linked = run_ankald(&linker.bytes, &module_refs, &entry)
            .map_err(DevelopmentMonitorError::Linker)?;
        let size = linked.bytes.len();
        let code_size = linked.code_size;
        let lit_start = linked.lit_start;
        let entry_offset = linked.entry;
        self.tool_artifacts.insert(name.clone(), DevelopmentToolArtifact {
            kind: DevelopmentToolArtifactKind::Linked,
            bytes: linked.bytes,
            code_size: Some(code_size),
            lit_start: Some(lit_start),
            entry: Some(entry_offset),
        });
        Ok(DevelopmentCommandResult::Continue(format!(
            "{}linked '{}' from {} AOM(s) (size={} code={} lit_start={} entry={})",
            if bootstrapped { "bootstrapped userspace ankald; " } else { "" },
            name, modules.len(), size, code_size, lit_start, entry_offset,
        )))
    }

    fn command_dump(
        &mut self,
        args: &[String],
    ) -> Result<DevelopmentCommandResult, DevelopmentMonitorError> {
        if args.len() != 3 {
            return Err(DevelopmentMonitorError::Usage("dump <name> <host-file>"));
        }
        let artifact = self.tool_artifacts.get(&args[1])
            .ok_or_else(|| DevelopmentMonitorError::ToolArtifactNotFound(args[1].clone()))?;
        let path = PathBuf::from(&args[2]);
        fs::write(&path, &artifact.bytes)
            .map_err(|err| DevelopmentMonitorError::HostWrite(err.kind()))?;
        Ok(DevelopmentCommandResult::Continue(format!(
            "dumped '{}' -> {} ({} bytes)", args[1], path.display(), artifact.bytes.len(),
        )))
    }

    fn command_load(
        &mut self,
        args: &[String],
    ) -> Result<DevelopmentCommandResult, DevelopmentMonitorError> {
        if (args.len() != 3 && args.len() != 4) || args.get(1).map(String::as_str) != Some("bin") {
            return Err(DevelopmentMonitorError::Usage("load bin <file> [name]"));
        }
        let path = PathBuf::from(&args[2]);
        let name = if args.len() == 4 {
            args[3].clone()
        } else {
            derive_name(&path)?
        };
        let ingress = DeveloperIngressAuthority::provision();
        let key = self.loader.import_bytecode_file(
            Some(&ingress),
            &mut self.fabric,
            &mut self.placement,
            &name,
            &path,
        ).map_err(DevelopmentMonitorError::Artifact)?;

        Ok(DevelopmentCommandResult::Continue(format!(
            "loaded {} as '{}' (object={} generation={})",
            path.display(), name, key.object.0, key.generation.0,
        )))
    }

    fn command_run(
        &mut self,
        args: &[String],
    ) -> Result<DevelopmentCommandResult, DevelopmentMonitorError> {
        if args.len() != 2 {
            return Err(DevelopmentMonitorError::Usage("run <name|/logical/path>"));
        }

        // The command itself is the explicit developer act.  The token is
        // intentionally short-lived and is never retained in shell state.
        let execution = DeveloperExecutionAuthority::provision();
        let report = run_registered_artifact(
            self.loader.registry(),
            Some(&execution),
            &mut self.fabric,
            &mut self.placement,
            &args[1],
        ).map_err(DevelopmentMonitorError::Run)?;

        let result = match report.child_result {
            ProcessResult::Exited(code) => format!("exited {code}"),
            ProcessResult::SupervisorFault => "supervisor fault".to_string(),
            ProcessResult::ProtectionFault => "protection fault".to_string(),
        };
        let mut text = String::new();
        if !report.byte_output.is_empty() {
            text.push_str(&String::from_utf8_lossy(&report.byte_output));
            if !text.ends_with('\n') {
                text.push('\n');
            }
        }
        text.push_str(&format!(
            "run {} -> {} (object={} generation={})",
            args[1], result, report.artifact.object.0, report.artifact.generation.0,
        ));
        Ok(DevelopmentCommandResult::Continue(text))
    }

    fn resolve_host_path(&self, arg: &str) -> PathBuf {
        let path = PathBuf::from(arg);
        if path.is_absolute() || path.starts_with(&self.userspace_root) {
            path
        } else {
            self.userspace_root.join(path)
        }
    }

    fn format_tool_artifacts(&self) -> String {
        if self.tool_artifacts.is_empty() {
            return "no retained toolchain artifacts".to_string();
        }
        let mut out = String::from("NAME\tKIND\tSIZE\tCODE\tLIT_START\tENTRY");
        for (name, artifact) in &self.tool_artifacts {
            let kind = match artifact.kind {
                DevelopmentToolArtifactKind::Compiler => "compiler",
                DevelopmentToolArtifactKind::Aom => "AOM",
                DevelopmentToolArtifactKind::Linked => "linked",
            };
            let show = |value: Option<u64>| value
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!(
                "\n{name}\t{kind}\t{}\t{}\t{}\t{}",
                artifact.bytes.len(),
                show(artifact.code_size),
                show(artifact.lit_start),
                show(artifact.entry),
            ));
        }
        out
    }

    fn format_artifacts(&self) -> String {
        if self.loader.registry().is_empty() {
            return "no registered artifacts".to_string();
        }
        let mut out = String::from("NAME\tLOGICAL\tOBJECT\tGEN\tKIND\tCODE\tSIZE");
        for (name, artifact) in self.loader.registry().iter() {
            let logical = artifact.logical_path.as_deref().unwrap_or("-");
            let kind = match artifact.kind {
                DevelopmentArtifactKind::Bytecode => "bytecode",
                DevelopmentArtifactKind::CompiledC => "C",
            };
            out.push_str(&format!(
                "\n{name}\t{logical}\t{}\t{}\t{kind}\t{}\t{}",
                artifact.key.object.0,
                artifact.key.generation.0,
                artifact.code_size,
                artifact.logical_size,
            ));
        }
        out
    }

    fn format_objects(&self) -> String {
        if self.fabric.objects.is_empty() {
            return "no persistent objects".to_string();
        }
        let mut out = String::from("OBJECT\tGEN\tSTATE\tKIND\tSIZE\tPHYS\tNAME");
        for (id, object) in &self.fabric.objects {
            let phys = self.fabric.physical_base(*id)
                .map(|base| format!("0x{base:x}"))
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!(
                "\n{}\t{}\t{:?}\t{:?}\t{}\t{}\t{}",
                id.0, object.generation.0, object.state, object.kind,
                object.size, phys, object.name,
            ));
        }
        out
    }

    fn format_placements(&self) -> String {
        let pool = self.placement.pool();
        let mut out = format!(
            "pool 0x{:x}..0x{:x}  allocated={}  free={} bytes",
            pool.base,
            pool.end().unwrap_or(pool.base),
            self.placement.allocated_count(),
            self.placement.free_bytes(),
        );
        for id in self.fabric.objects.keys() {
            if let Some(extent) = self.placement.allocated_extent(*id) {
                out.push_str(&format!(
                    "\nobject {} -> 0x{:x}..0x{:x} ({} bytes)",
                    id.0,
                    extent.base,
                    extent.end().unwrap_or(extent.base),
                    extent.size,
                ));
            }
        }
        out.push_str("\nfree:");
        for extent in self.placement.free_extents() {
            out.push_str(&format!(
                "\n  0x{:x}..0x{:x} ({} bytes)",
                extent.base,
                extent.end().unwrap_or(extent.base),
                extent.size,
            ));
        }
        out
    }
}

fn require_arity(
    args: &[String],
    expected: usize,
    usage: &'static str,
) -> Result<(), DevelopmentMonitorError> {
    if args.len() == expected {
        Ok(())
    } else {
        Err(DevelopmentMonitorError::Usage(usage))
    }
}

fn derive_name(path: &Path) -> Result<String, DevelopmentMonitorError> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .ok_or(DevelopmentMonitorError::CannotDeriveArtifactName)
}

/// Minimal shell tokenizer with quoted-path support.  It intentionally does
/// not implement variable expansion, globbing, pipes, redirection, or any
/// other host-shell language feature.
fn tokenize(line: &str) -> Result<Vec<String>, DevelopmentMonitorError> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if escaped {
        current.push('\\');
    }
    if quote.is_some() {
        return Err(DevelopmentMonitorError::UnterminatedQuote);
    }
    if !current.is_empty() {
        out.push(current);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anka64::isa::{Asm64, R0, R1};
    use crate::anka64::os::SYS_EXIT;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!(
            "anka64-p93h4-{tag}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn temp_exit_binary(dir: &Path, name: &str, code: u64) -> PathBuf {
        let mut asm = Asm64::new();
        asm.movi(R1, code as i32);
        asm.movi(R0, SYS_EXIT as i32);
        asm.trap(0);
        let path = dir.join(name);
        fs::write(&path, asm.to_bytes()).unwrap();
        path
    }

    #[test]
    fn p93h4_tokenizer_is_small_but_accepts_quoted_paths() {
        assert_eq!(
            tokenize("compile \"bin/my hello.c\" hello").unwrap(),
            vec!["compile", "bin/my hello.c", "hello"],
        );
        assert_eq!(
            tokenize("load bin path\\ with\\ spaces/prog.anka").unwrap(),
            vec!["load", "bin", "path with spaces/prog.anka"],
        );
        assert_eq!(
            tokenize("run 'hello").unwrap_err(),
            DevelopmentMonitorError::UnterminatedQuote,
        );
    }

    #[test]
    fn p93h4_help_and_quit_are_presentation_only() {
        let root = temp_dir("help");
        let mut shell = DevelopmentShellSession::new(&root).unwrap();
        assert!(matches!(
            shell.execute_line("help").unwrap(),
            DevelopmentCommandResult::Continue(text) if text.contains("compile <source.c>")
        ));
        assert_eq!(shell.fabric().objects.len(), 0);
        assert_eq!(shell.placement().allocated_count(), 0);
        assert_eq!(shell.execute_line("quit").unwrap(), DevelopmentCommandResult::Quit);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p93h4_load_command_uses_transactional_ingress_registry() {
        let root = temp_dir("load");
        let bin = temp_exit_binary(&root, "hello.anka", 31);
        let mut shell = DevelopmentShellSession::new(&root).unwrap();

        let result = shell.execute_line(&format!("load bin {}", bin.display())).unwrap();
        assert!(matches!(result,
            DevelopmentCommandResult::Continue(text) if text.contains("loaded") && text.contains("hello")));
        assert_eq!(shell.loader().registry().len(), 1);
        assert!(shell.loader().registry().get("hello").is_some());
        assert_eq!(shell.placement().allocated_count(), 1);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p93h4_run_command_uses_ordinary_spawn_wait_path() {
        let root = temp_dir("run");
        let bin = temp_exit_binary(&root, "answer.anka", 31);
        let mut shell = DevelopmentShellSession::new(&root).unwrap();
        shell.execute_line(&format!("load bin {} answer", bin.display())).unwrap();
        let key = shell.loader().registry().get("answer").unwrap().key;
        let extent_before = shell.placement().allocated_extent(key.object).unwrap();

        let result = shell.execute_line("run answer").unwrap();
        assert!(matches!(result,
            DevelopmentCommandResult::Continue(text) if text.contains("exited 31")));
        assert_eq!(shell.placement().allocated_extent(key.object), Some(extent_before));
        assert_eq!(shell.loader().registry().resolve_current(shell.fabric(), "answer").unwrap().key, key);
        assert!(shell.fabric().domains.is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p93h4_observation_commands_do_not_create_authority() {
        let root = temp_dir("observe");
        let bin = temp_exit_binary(&root, "inspect.anka", 0);
        let mut shell = DevelopmentShellSession::new(&root).unwrap();
        shell.execute_line(&format!("load bin {} inspect", bin.display())).unwrap();
        let objects_before = shell.fabric().objects.len();
        let allocations_before = shell.placement().allocated_count();

        let artifacts = shell.execute_line("artifacts").unwrap();
        let objects = shell.execute_line("objects").unwrap();
        let placements = shell.execute_line("placements").unwrap();
        assert!(matches!(artifacts, DevelopmentCommandResult::Continue(text) if text.contains("inspect")));
        assert!(matches!(objects, DevelopmentCommandResult::Continue(text) if text.contains("Sealed")));
        assert!(matches!(placements, DevelopmentCommandResult::Continue(text) if text.contains("object")));
        assert_eq!(shell.fabric().objects.len(), objects_before);
        assert_eq!(shell.placement().allocated_count(), allocations_before);
        assert!(shell.fabric().domains.is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p93h4_bad_command_is_side_effect_free() {
        let root = temp_dir("bad-command");
        let mut shell = DevelopmentShellSession::new(&root).unwrap();
        assert_eq!(
            shell.execute_line("sudo magic").unwrap_err(),
            DevelopmentMonitorError::UnknownCommand("sudo".to_string()),
        );
        assert!(shell.fabric().objects.is_empty());
        assert_eq!(shell.placement().allocated_count(), 0);
        assert!(!shell.compiler_ready());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p93h4_compile_then_run_closes_the_interactive_c_path() {
        let root = temp_dir("compile-run");
        let bin_dir = root.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let source = bin_dir.join("hello.c");
        fs::write(&source, b"int main() { return 23; }").unwrap();

        let mut shell = DevelopmentShellSession::new(&root).unwrap();
        assert!(!shell.compiler_ready());
        let compiled = shell.execute_line("compile bin/hello.c hello").unwrap();
        assert!(matches!(compiled, DevelopmentCommandResult::Continue(text)
            if text.contains("bootstrapped CC_B") && text.contains("/bin/hello")));
        assert!(shell.compiler_ready());

        let artifact = shell.loader().registry()
            .resolve_current_by_logical_path(shell.fabric(), "/bin/hello")
            .unwrap();
        assert_eq!(artifact.kind, DevelopmentArtifactKind::CompiledC);

        let ran = shell.execute_line("run /bin/hello").unwrap();
        assert!(matches!(ran, DevelopmentCommandResult::Continue(text)
            if text.contains("exited 23")));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p10dev_help_exposes_existing_phase10_toolchain_surfaces() {
        let root = temp_dir("phase10-help");
        let mut shell = DevelopmentShellSession::new(&root).unwrap();
        let help = shell.execute_line("help").unwrap();
        assert!(matches!(help, DevelopmentCommandResult::Continue(text)
            if text.contains("cc2 bootstrap [name]")
                && text.contains("cc2 import <host-file> [name]")
                && text.contains("aom <source.c>")
                && text.contains("link <name> <entry>")
                && text.contains("dump <name> <host-file>")));
        assert!(shell.tool_artifacts.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p10dev_tool_artifact_observation_is_side_effect_free() {
        let root = temp_dir("phase10-observe");
        let mut shell = DevelopmentShellSession::new(&root).unwrap();
        shell.tool_artifacts.insert("probe".to_string(), DevelopmentToolArtifact {
            kind: DevelopmentToolArtifactKind::Aom,
            bytes: vec![1, 2, 3],
            code_size: None,
            lit_start: None,
            entry: None,
        });
        let fabric_objects = shell.fabric.objects.len();
        let placements = shell.placement.allocated_count();
        let result = shell.execute_line("tool-artifacts").unwrap();
        assert!(matches!(result, DevelopmentCommandResult::Continue(text)
            if text.contains("probe") && text.contains("AOM")));
        assert_eq!(shell.fabric.objects.len(), fabric_objects);
        assert_eq!(shell.placement.allocated_count(), placements);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p10dev_imported_stage3_bypasses_bootstrap_cache() {
        let root = temp_dir("phase10-import-stage3");
        let compiler = root.join("cc2-0.bin");
        fs::write(&compiler, [0x11u8, 0x22, 0x33, 0x44]).unwrap();

        let mut shell = DevelopmentShellSession::new(&root).unwrap();
        let imported = shell.execute_line(&format!(
            "cc2 import {} cc2-0", compiler.display())).unwrap();
        assert!(matches!(imported, DevelopmentCommandResult::Continue(text)
            if text.contains("imported Stage-3 AnkaCC2") && text.contains("cc2-0")));
        assert!(shell.ccb_image.is_none());
        assert!(shell.extended_ccb_image.is_none());
        let image = shell.stage3_image.as_ref().unwrap();
        assert_eq!(image.bytes, vec![0x11, 0x22, 0x33, 0x44]);
        assert_eq!(image.code_size, 4);
        assert_eq!(image.lit_start, 0);
        assert_eq!(shell.tool_artifacts.get("cc2-0").unwrap().kind,
            DevelopmentToolArtifactKind::Compiler);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn p10dev_stage3_aom_ankald_and_dump_close_debug_surface() {
        let userspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("userspace");
        let tmp = temp_dir("phase10-toolchain");
        let source = tmp.join("probe.c");
        let dumped = tmp.join("probe-linked.bin");
        fs::write(&source, b"int main(){return 42;}").unwrap();

        let mut shell = DevelopmentShellSession::new(&userspace).unwrap();
        let ready = shell.execute_line("cc2 bootstrap cc2-0").unwrap();
        assert!(matches!(ready, DevelopmentCommandResult::Continue(text)
            if text.contains("Stage-3 AnkaCC2 ready") && text.contains("cc2-0")));
        assert_eq!(shell.tool_artifacts.get("cc2-0").unwrap().kind,
            DevelopmentToolArtifactKind::Compiler);

        let aom = shell.execute_line(&format!("aom {} probe-aom", source.display())).unwrap();
        assert!(matches!(aom, DevelopmentCommandResult::Continue(text)
            if text.contains("AOM 'probe-aom'")));
        assert_eq!(shell.fabric.objects.len(), 0,
            "retained AOM bytes are debug observations, not executable Fabric artifacts");

        let linked = shell.execute_line("link probe-linked main probe-aom").unwrap();
        assert!(matches!(linked, DevelopmentCommandResult::Continue(text)
            if text.contains("linked 'probe-linked'") && text.contains("entry=")));
        assert_eq!(shell.fabric.objects.len(), 0,
            "link debug output is not implicitly published into the executable registry");

        let dumped_result = shell.execute_line(&format!(
            "dump probe-linked {}", dumped.display())).unwrap();
        assert!(matches!(dumped_result, DevelopmentCommandResult::Continue(text)
            if text.contains("dumped 'probe-linked'")));
        let dumped_bytes = fs::read(&dumped).unwrap();
        let retained = shell.tool_artifacts.get("probe-linked").unwrap();
        assert_eq!(dumped_bytes, retained.bytes);
        assert_eq!(retained.kind, DevelopmentToolArtifactKind::Linked);
        assert!(retained.code_size.unwrap() > 0);
        assert_eq!(retained.entry, Some(0));

        fs::remove_dir_all(tmp).unwrap();
    }

    #[test]
    fn p93h4_interactive_loop_recovers_from_command_error() {
        let root = temp_dir("loop");
        let mut shell = DevelopmentShellSession::new(&root).unwrap();
        let input = io::Cursor::new(b"bogus\nhelp\nquit\n".to_vec());
        let mut output = Vec::new();
        shell.run_interactive(input, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("error: unknown command 'bogus'"));
        assert!(text.contains("compile <source.c>"));
        assert!(text.matches("anka64> ").count() >= 3);
        fs::remove_dir_all(root).unwrap();
    }
}
