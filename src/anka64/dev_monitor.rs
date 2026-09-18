//! Interactive Anka64 development monitor (Phase 9.3h.4).
//!
//! This is intentionally a thin command layer over the already-closed 9.3h
//! mechanisms:
//!
//!   `load bin` -> 9.3h.1 transactional ingress
//!   `compile`  -> 9.3h.2 CC_B compile-only path
//!   `run`      -> 9.3h.3 explicit execution authority + SYS_SPAWN/SYS_WAIT
//!
//! The monitor adds no new authority rule.  Entering a development command is
//! the explicit host/developer act that provisions the corresponding short-
//! lived development token; the token is never guest authority.

use std::fmt;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use super::dev_compiler::{bootstrap_development_ccb, DevelopmentCompileError};
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

const BANNER: &str = "Anka64 Development Shell — phase 9.3h\nType 'help' for commands.";

const HELP: &str = "\
commands:
  compile <source.c> [name]   compile host C through self-hosted CC_B
  load bin <file> [name]     import raw Anka64 bytecode
  run <name|/logical/path>    run via explicit authority + SYS_SPAWN/SYS_WAIT
  artifacts                  list registered development artifacts
  objects                    list persistent Fabric objects
  placements                 list PM allocations and free extents
  help                       show this help
  quit | exit                leave the development shell

source paths may be rooted at userspace/ or relative to the configured
userspace root.  A compile command never runs its output.  The run command is
synchronous in phase 9.3h.4 and returns the SYS_WAIT result; there is therefore
no separate wait/ps command yet.";

#[derive(Debug, PartialEq, Eq)]
pub enum DevelopmentMonitorError {
    UnterminatedQuote,
    UnknownCommand(String),
    Usage(&'static str),
    CannotDeriveArtifactName,
    Placement(PlacementError),
    CompilerBootstrap(DevelopmentCompileError),
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
            Self::Placement(err) => write!(f, "placement setup failed: {err:?}"),
            Self::CompilerBootstrap(err) => write!(f, "CC_B bootstrap failed: {err:?}"),
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

/// Stateful host-development session.
///
/// The persistent state is exactly the 9.3h artifact machine: Fabric, PM, and
/// registry.  CC_B is lazily bootstrapped on the first `compile` and cached as
/// host development bytes; user C still runs through the 9.3h.2 CC_B path.
pub struct DevelopmentShellSession {
    userspace_root: PathBuf,
    fabric: Fabric,
    placement: PhysicalPlacementManager,
    loader: DevelopmentArtifactLoader,
    ccb_image: Option<Vec<u8>>,
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

    /// Execute one shell line.  No command in this function bypasses a lower
    /// 9.3h API: parsing is the only new behavior introduced in 9.3h.4.
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

        let bootstrapped = self.ccb_image.is_none();
        if self.ccb_image.is_none() {
            self.ccb_image = Some(
                bootstrap_development_ccb()
                    .map_err(DevelopmentMonitorError::CompilerBootstrap)?,
            );
        }
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
    use std::fs;
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
