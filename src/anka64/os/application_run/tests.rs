use super::*;
fn realm()->Kernel {
    let mut f=Fabric::with_application_heap(0x1000000).unwrap();
    let domain=f.create_domain();let agent=AgentId(1);
    f.register_agent(agent,AgentKind::Cpu(CoreId(0)),domain);
    let mut k=Kernel::new(f);k.spawn(Anka64Core::new(agent,domain));
    k.enable_heap_service(0x100000).unwrap();k
}
#[test]
fn c2_run_output_arithmetic_checks_exact_limit_chunk_and_overflow() {
    for (used,count,ok) in [(0,4096,true),(65536,0,true),(65535,1,true),
        (65536,1,false),(65537,0,false),(0,4097,false),(usize::MAX,u64::MAX,false)] {
        assert_eq!(output_fits(used,count),ok);
    }
}
#[test]
fn c2_run_admission_preallocates_output_and_requires_exact_realm() {
    let mut k=realm();k.prepare_application_run().unwrap();
    assert_eq!(k.byte_output.len(),0);assert_eq!(k.byte_output.capacity(),OUTPUT_BYTES);
    assert!(k.prepare_application_run().is_err());
    let mut other=realm();other.byte_output.push(1);
    assert!(other.prepare_application_run().is_err());assert!(other.application_run.is_none());
}
#[test]
fn c2_run_raw_syscalls_only_admit_one_supervisor_spawn() {
    let mut k=realm();k.prepare_application_run().unwrap();
    for n in [SYS_WRITE,SYS_EXEC,SYS_MALLOC,SYS_SEND,SYS_YIELD] {
        k.processes[0].core.r[0]=n;assert!(!k.application_run_syscall_allowed(0));
    }
    k.processes[0].core.r[0]=SYS_SPAWN;
    assert!(k.application_run_syscall_allowed(0));assert!(!k.application_run_syscall_allowed(0));
    k.processes[1].core.r[0]=SYS_SPAWN;assert!(!k.application_run_syscall_allowed(1));
    k.processes[0].core.r[0]=SYS_WAIT;assert!(k.application_run_syscall_allowed(0));
}
#[test]
fn c2_run_metadata_depth_and_process_count_are_bounded() {
    let mut k=realm();k.prepare_application_run().unwrap();
    assert!(k.application_run_step_ok(0));
    k.processes[0].core.return_stack.resize(128,ReturnAuthority {
        code_object:ObjectId(99),generation:Generation(0),target:0});
    assert!(!k.application_run_step_ok(0));
    k.processes[0].core.return_stack.clear();
    let d=k.fabric.create_domain();k.spawn(Anka64Core::new(AgentId(8),d));
    let d=k.fabric.create_domain();k.spawn(Anka64Core::new(AgentId(9),d));
    assert!(!k.application_run_step_ok(0));
}
