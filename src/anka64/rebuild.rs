//! Ordinary host command ingress to the protected Anka64 rebuild service.
//! Bootstrapping accepted tools is trusted provisioning, outside per-job quota.
use super::{cc2_fixed_point,compiler_adapter,dev_runner,source_bundle};
use super::os::compiler_retry::service::RebuildService;
use super::os::ProcessResult;
use std::io::{Read,Write};
use std::path::Path;
use std::time::{Duration,Instant};
const HELP:&str="Usage: anka rebuild [--include FILE] [--initial-output BYTES] [--run] [--input FILE] ROOT.c [MODULE.c ...]\n\
Compiles up to eight modules in argument order, guest-links and publishes them.\n\
Bundle lookup names are file basenames; includes must use those exact names.\n\
--run executes the linked protected application and writes its captured bytes.\n\
--input supplies up to 65536 bytes to the actual child; requires --run.\n\
Bootstraps accepted tools once per invocation. No source is compiled by the host.";
fn fail(e:impl std::fmt::Debug)->String {format!("{e:?}")}
struct Options {roots:Vec<String>,includes:Vec<String>,run:bool,capacity:u64,input:Option<String>}
fn options(args:&[String])->Result<Options,String> {
    let mut o=Options{roots:Vec::new(),includes:Vec::new(),run:false,capacity:0x40000,input:None};
    let mut it=args.iter();
    while let Some(a)=it.next() {
        match a.as_str() {
            "--run"=>o.run=true,
            "--input"=>{if o.input.is_some(){return Err("duplicate --input".into());}
                o.input=Some(it.next().ok_or("missing input path")?.clone());},
            "--include"=>{if o.includes.len()>=248 {return Err("too many include files".into());}
                o.includes.push(it.next().ok_or("missing include path")?.clone());},
            "--initial-output"=>{o.capacity=it.next().ok_or("missing capacity")?.parse().map_err(fail)?;
                if o.capacity<4096 || o.capacity>1048576 || o.capacity%4096!=0 {
                    return Err("output capacity must be a 4096-byte multiple from 4096 to 1048576".into());}},
            _ if a.starts_with('-')=>return Err(format!("unknown option: {a}")),
            _=>{if o.roots.len()>=8 {return Err("at most eight modules per invocation".into());}o.roots.push(a.clone());},
        }
    }
    if o.roots.is_empty() {return Err(HELP.into());}
    if o.input.is_some() && !o.run {return Err("--input requires --run".into());}Ok(o)
}
// Host ingress is bounded independently of guest service quota. take() also
// prevents a growing file from defeating a metadata-only size check.
fn read_member(path:&str)->Result<source_bundle::SourceBundleMember,String> {
    let name=Path::new(path).file_name().and_then(|n|n.to_str()).ok_or("invalid file name")?;
    let mut bytes=Vec::new();
    std::fs::File::open(path).map_err(fail)?.take(1048577).read_to_end(&mut bytes).map_err(fail)?;
    if bytes.len()>1048576 {return Err(format!("input exceeds 1 MiB: {path}"));}
    source_bundle::SourceBundleMember::new(name,bytes).map_err(fail)
}
/// Entry point for `anka rebuild`; stdout is application bytes, diagnostics stderr.
pub fn command(args:&[String])->i32 {
    if args.iter().any(|a|a=="--help" || a=="-h") {println!("{HELP}");return 0;}
    match execute(args) {Ok(code)=>code,Err(e)=>{eprintln!("rebuild: {e}");1}}
}
fn execute(args:&[String])->Result<i32,String> {
    let o=options(args)?;
    let input=if let Some(path)=&o.input {
        let mut bytes=Vec::new();std::fs::File::open(path).map_err(fail)?.take(65537)
            .read_to_end(&mut bytes).map_err(fail)?;
        if bytes.len()>65536{return Err("run input exceeds 65536 bytes".into());}Some(bytes)
    }else{None};
    let mut members=Vec::new();let mut total=16usize;
    for p in o.roots.iter().chain(o.includes.iter()) {
        let m=read_member(p)?;
        total=total.checked_add(16+m.logical_name().len()+m.bytes().len()).ok_or("bundle overflow")?;
        if total+127>1048576 {return Err("combined bundle exceeds 1 MiB publication policy".into());}
        members.push(m);
    }
    // Validate duplicate/missing names before spending time bootstrapping.
    let roots:Vec<String>=o.roots.iter().map(|p|Path::new(p).file_name().unwrap().to_str().unwrap().to_owned()).collect();
    let mut bundle=source_bundle::SourceBundle::new(&roots[0],members).map_err(fail)?;
    let execution=dev_runner::DeveloperExecutionAuthority::provision();
    let publication=compiler_adapter::RebuildPublicationAuthority::provision();
    eprintln!("Rebuild: provisioning accepted lineage and protected compiler");
    let lineage=cc2_fixed_point::witness_cc2_fixed_point(Some(&execution),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).map_err(fail)?;
    let mut service=RebuildService::new(&lineage,&execution)?;
    let mut epochs=Vec::with_capacity(8);
    for (i,name) in roots.iter().enumerate() {
        if i>0 {bundle=source_bundle::SourceBundle::new(name,bundle.members().cloned()).map_err(fail)?;}
        let h=service.submit(&bundle,o.capacity,1_000_000_000,&execution,&publication)?;
        let mut last=Instant::now();let start=last;
        loop {
            if let Some(epoch)=service.poll(h,&execution,&publication)? {
                eprintln!("Rebuild: {name} published epoch={epoch} in {:.2}s",start.elapsed().as_secs_f64());
                epochs.push(epoch);break;
            }
            if last.elapsed()>=Duration::from_secs(5) {eprintln!("Rebuild: {name} active {:.1}s",start.elapsed().as_secs_f64());last=Instant::now();}
        }
    }
    let linked=service.link(&epochs,&execution,&publication)?;
    eprintln!("Rebuild: linked receipt epoch={linked}, modules={}",epochs.len());
    if !o.run {return Ok(0);}
    let emit=|bytes:&[u8]|std::io::stdout().write_all(bytes).map_err(fail);
    let result=match input {
        Some(bytes)=>service.run_with_input(linked,&execution,&dev_runner::DeveloperInputAuthority::provision(),&bytes,emit)?,
        None=>service.run(linked,&execution,emit)?,
    };
    eprintln!("Rebuild: {result:?}");
    match result {ProcessResult::Exited(code)=>Ok((code&255) as i32),other=>Err(format!("application failed: {other:?}"))}
}
#[cfg(test)]
mod tests {
    use super::*;
    fn args(a:&[&str])->Vec<String>{a.iter().map(|s|s.to_string()).collect()}
    #[test] fn c5_service_cli_capacity_and_argument_bounds() {
        assert!(options(&args(&["--initial-output","4096","a.c","--run"])).unwrap().run);
        for a in [vec![],vec!["--include"],vec!["--initial-output","4097","a.c"],vec!["--unknown","a.c"]] {
            assert!(options(&args(&a)).is_err());
        }
        assert!(options(&vec!["a.c".into();9]).is_err());
        assert!(options(&args(&["--input","request","a.c"])).is_err());
        assert!(options(&args(&["--run","--input","request","a.c"])).unwrap().input.is_some());
    }
}
