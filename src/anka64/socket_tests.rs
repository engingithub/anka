//! Phase 9.4f process-facing stream socket integration tests.
//!
//! `socket.c` owns NIC/TCP state. `socket_echo.c` is an ordinary client
//! process with no NIC capability. The two processes share only an explicitly
//! granted 1024-byte stream buffer and communicate with generation-qualified
//! IPC. Rust supplies deterministic virtual-NIC traffic and inspects TX bytes.

use std::sync::OnceLock;

use super::core::Anka64Core;
use super::dev_compiler::{
    bootstrap_development_ccb, compile_c_with_ccb, CompiledCImage,
};
use super::fabric::Fabric;
use super::guest_compiler::{install_trap_handler, seal_code_object};
use super::isa::SP;
use super::nic::{NicController, NIC_MAX_FRAME_SIZE};
use super::os::{Kernel, ProcessResult};
use super::state::{
    AgentId, CapabilityHandle, DeviceBinding, DeviceRights, ObjectId, ObjectKind,
    Permissions, ProcessKey,
};

const CODE_SIZE: u64 = 0x1_8000;
const NET_VADDR: u64 = 0x1_8000;
const NET_SIZE: u64 = NIC_MAX_FRAME_SIZE as u64;
const SVC_BUF_VADDR: u64 = 0x1_C000;
const CLI_BUF_VADDR: u64 = 0x1_8000;
const SOCK_BUF_SIZE: u64 = 1024;
const STACK_VADDR: u64 = 0x2_0000;
const STACK_SIZE: u64 = 0x4000;
const TRAP_VADDR: u64 = CODE_SIZE - 0x10;
const RAM_SIZE: usize = 0x40_0000;

const SVC_CODE_PHYS: u64 = 0x1_0000;
const CLI_CODE_PHYS: u64 = 0x3_0000;
const NET_PHYS: u64 = 0x5_0000;
const SOCK_PHYS: u64 = 0x6_0000;
const SVC_STACK_PHYS: u64 = 0x7_0000;
const CLI_STACK_PHYS: u64 = 0x8_0000;

const LOCAL_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const LOCAL_IP: [u8; 4] = [10, 0, 0, 2];
const PEER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const PEER_IP: [u8; 4] = [10, 0, 0, 9];
const SERVICE_PORT: u16 = 49153;
const PEER_PORT: u16 = 34568;
const LOCAL_ISS: u32 = 0x414E_4B41;
const PEER_ISS: u32 = 0x1020_3040;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH_ACK: u8 = 0x18;

fn ccb_image() -> &'static Vec<u8> {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        bootstrap_development_ccb().expect("phase 9.4f tests must bootstrap canonical CC_B")
    })
}

fn socket_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/services/net/socket.c"
    ))
}

fn client_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/bin/socket_echo.c"
    ))
}

fn socket_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(ccb_image(), socket_source())
            .expect("CC_B must compile the real socket service")
    })
}

fn client_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(ccb_image(), client_source())
            .expect("CC_B must compile the ordinary socket client")
    })
}

fn make_core(
    fabric: &mut Fabric,
    image: &CompiledCImage,
    agent: AgentId,
    name: &str,
    code_phys: u64,
    stack_phys: u64,
    maps: &[(u64, ObjectId, u64)],
) -> Anka64Core {
    assert_eq!(image.lit_start, 0,
        "phase 9.4f C witnesses intentionally have no literal segment");
    assert!(image.bytes.len() as u64 <= TRAP_VADDR,
        "compiled image must leave room for the fixed trap stub");

    let code = fabric.alloc_object(
        &format!("{name}-code"), CODE_SIZE, ObjectKind::Memory);
    assert!(fabric.place_object(code, code_phys));
    assert!(fabric.initialize_object(code, 0, &image.bytes));
    install_trap_handler(fabric, code_phys, CODE_SIZE);

    let stack = fabric.alloc_object(
        &format!("{name}-stack"), STACK_SIZE, ObjectKind::Memory);
    assert!(fabric.place_object(stack, stack_phys));
    assert!(fabric.zero_object_extent(stack));

    let dom = fabric.create_domain();
    assert!(fabric.grant(dom, stack, 0, STACK_SIZE, Permissions::RW).is_some());
    for &(_, obj, size) in maps {
        assert!(fabric.grant(dom, obj, 0, size, Permissions::RW).is_some());
    }
    seal_code_object(fabric, code, dom);

    let mut core = Anka64Core::new(agent, dom);
    core.address_map.add(0, CODE_SIZE, code);
    core.address_map.add(STACK_VADDR, STACK_SIZE, stack);
    for &(vaddr, obj, size) in maps {
        core.address_map.add(vaddr, size, obj);
    }
    core.r[SP as usize] = STACK_VADDR + STACK_SIZE;
    core.trap_vector = TRAP_VADDR;
    core
}

struct SockRun {
    kernel: Kernel,
    binding: DeviceBinding,
    shared: ObjectId,
    service: ProcessKey,
    client: ProcessKey,
}

fn start_socket() -> SockRun {
    let simg = socket_image();
    let cimg = client_image();

    let mut fabric = Fabric::new(RAM_SIZE);
    let netbuf = fabric.alloc_object("p94f-netbuf", NET_SIZE, ObjectKind::Memory);
    assert!(fabric.place_object(netbuf, NET_PHYS));
    assert!(fabric.zero_object_extent(netbuf));

    let shared = fabric.alloc_object("p94f-sockbuf", SOCK_BUF_SIZE, ObjectKind::Memory);
    assert!(fabric.place_object(shared, SOCK_PHYS));
    assert!(fabric.zero_object_extent(shared));

    let service_core = make_core(
        &mut fabric,
        simg,
        AgentId(946),
        "p94f-socket",
        SVC_CODE_PHYS,
        SVC_STACK_PHYS,
        &[(NET_VADDR, netbuf, NET_SIZE), (SVC_BUF_VADDR, shared, SOCK_BUF_SIZE)],
    );
    let client_core = make_core(
        &mut fabric,
        cimg,
        AgentId(947),
        "p94f-client",
        CLI_CODE_PHYS,
        CLI_STACK_PHYS,
        &[(CLI_BUF_VADDR, shared, SOCK_BUF_SIZE)],
    );

    let mut kernel = Kernel::new(fabric);
    let service = kernel.spawn(service_core);
    let client = kernel.spawn(client_core);
    assert_eq!(service, ProcessKey { slot: 0, generation: 0 });
    assert_eq!(client, ProcessKey { slot: 1, generation: 0 });

    let binding = kernel.register_nic_device(
        NicController::new(AgentId(948)),
    ).expect("phase 9.4f test NIC registration");

    let rights = DeviceRights(
        DeviceRights::EVENT_WAIT.0 | DeviceRights::NIC_RX.0 | DeviceRights::NIC_TX.0,
    );
    let device = kernel.install_device_capability(service.slot, binding.object, rights)
        .expect("phase 9.4f socket NIC capability");
    let dma = kernel.install_capability(
        service.slot,
        netbuf,
        0,
        NET_SIZE,
        Permissions::RW,
    ).expect("phase 9.4f socket DMA capability");
    assert_eq!(device, CapabilityHandle { slot: 0, generation: 0 });
    assert_eq!(dma, CapabilityHandle { slot: 1, generation: 0 });

    assert_eq!(
        kernel.processes[client.slot].cap_table.as_ref().unwrap().occupied_count(),
        0,
        "ordinary socket client must receive no NIC or DMA capability",
    );

    kernel.run(800_000, 260);
    assert_eq!(kernel.processes[service.slot].result, None);
    assert_eq!(kernel.processes[client.slot].result, None);
    assert!(kernel.processes[service.slot].event_wait.is_some(),
        "socket service waits for NIC activity without polling");
    assert_eq!(
        kernel.processes[client.slot].recv_wait.as_ref().map(|w| w.peer),
        Some(service),
        "client initially waits on the exact socket-service incarnation",
    );

    SockRun { kernel, binding, shared, service, client }
}

impl SockRun {
    fn send(&mut self, frame: &[u8]) {
        assert!(!frame.is_empty());
        assert!(frame.len() <= NIC_MAX_FRAME_SIZE);
        assert!(self.kernel.inject_nic_rx(self.binding, frame));
        self.kernel.run(800_000, 320);
    }

    fn take_tx(&mut self) -> Option<Vec<u8>> {
        self.kernel.take_nic_tx(self.binding)
    }

    fn shared_bytes(&self, len: usize) -> Vec<u8> {
        let phys = self.kernel.fabric.translate(self.shared, 0).unwrap();
        self.kernel.fabric.read_physical(phys, len as u64).to_vec()
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut pos = 0usize;
    while pos + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as u32;
        sum = (sum & 0xFFFF) + (sum >> 16);
        pos += 2;
    }
    if pos < bytes.len() {
        sum += (bytes[pos] as u32) << 8;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(frame: &[u8], tcp_len: usize) -> u16 {
    let mut bytes = Vec::with_capacity(12 + tcp_len);
    bytes.extend_from_slice(&frame[26..30]);
    bytes.extend_from_slice(&frame[30..34]);
    bytes.push(0);
    bytes.push(6);
    bytes.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    bytes.extend_from_slice(&frame[34..34 + tcp_len]);
    checksum(&bytes)
}

fn set_ipv4_checksum(frame: &mut [u8]) {
    frame[24] = 0;
    frame[25] = 0;
    let sum = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&sum.to_be_bytes());
}

fn set_tcp_checksum(frame: &mut [u8]) {
    let total = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    let tcp_len = total - 20;
    frame[50] = 0;
    frame[51] = 0;
    let sum = tcp_checksum(frame, tcp_len);
    frame[50..52].copy_from_slice(&sum.to_be_bytes());
}

fn tcp_frame(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total_len = 20 + tcp_len;
    let frame_len = (14 + total_len).max(60);
    let mut frame = vec![0xA7; frame_len];

    frame[0..6].copy_from_slice(&LOCAL_MAC);
    frame[6..12].copy_from_slice(&PEER_MAC);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[15] = 0;
    frame[16..18].copy_from_slice(&(total_len as u16).to_be_bytes());
    frame[18..20].copy_from_slice(&0x5432u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[22] = 50;
    frame[23] = 6;
    frame[24] = 0;
    frame[25] = 0;
    frame[26..30].copy_from_slice(&PEER_IP);
    frame[30..34].copy_from_slice(&LOCAL_IP);

    frame[34..36].copy_from_slice(&PEER_PORT.to_be_bytes());
    frame[36..38].copy_from_slice(&SERVICE_PORT.to_be_bytes());
    frame[38..42].copy_from_slice(&seq.to_be_bytes());
    frame[42..46].copy_from_slice(&ack.to_be_bytes());
    frame[46] = 0x50;
    frame[47] = flags;
    frame[48..50].copy_from_slice(&4096u16.to_be_bytes());
    frame[50] = 0;
    frame[51] = 0;
    frame[52] = 0;
    frame[53] = 0;
    frame[54..54 + payload.len()].copy_from_slice(payload);

    set_tcp_checksum(&mut frame);
    set_ipv4_checksum(&mut frame);
    frame
}

fn establish(run: &mut SockRun) -> (u32, u32) {
    run.send(&tcp_frame(PEER_ISS, 0, SYN, &[]));
    let synack = run.take_tx().expect("socket service must answer valid SYN");
    let local_seq = u32::from_be_bytes(synack[38..42].try_into().unwrap());
    let peer_nxt = PEER_ISS.wrapping_add(1);
    let local_nxt = local_seq.wrapping_add(1);
    assert_eq!(local_seq, LOCAL_ISS);
    assert_eq!(u32::from_be_bytes(synack[42..46].try_into().unwrap()), peer_nxt);

    run.send(&tcp_frame(peer_nxt, local_nxt, ACK, &[]));
    assert!(run.take_tx().is_none(), "final handshake ACK is not acknowledged");
    assert_eq!(
        run.kernel.processes[run.client.slot].recv_wait.as_ref().map(|w| w.peer),
        Some(run.service),
        "after CONNECTED the client waits again for socket DATA",
    );
    (peer_nxt, local_nxt)
}

#[test]
fn p94f_socket_service_and_ordinary_client_compile_with_self_hosted_ccb() {
    let service = socket_image();
    let client = client_image();
    assert!(service.code_size > 0);
    assert!(client.code_size > 0);
    assert_eq!(service.lit_start, 0);
    assert_eq!(client.lit_start, 0);
    assert_eq!(service.process_slots_observed, 2);
    assert_eq!(client.process_slots_observed, 2);
}

#[test]
fn p94f_socket_client_has_shared_stream_memory_but_no_nic_capability() {
    let run = start_socket();
    assert_eq!(
        run.kernel.processes[run.client.slot].cap_table.as_ref().unwrap().occupied_count(),
        0,
    );
    assert!(run.kernel.processes[run.service.slot].event_wait.is_some());
    assert!(run.kernel.processes[run.client.slot].recv_wait.is_some());
}

#[test]
fn p94f_socket_hides_handshake_and_notifies_client_only_after_established() {
    let mut run = start_socket();
    let (peer_nxt, local_nxt) = establish(&mut run);
    assert_eq!(peer_nxt, PEER_ISS + 1);
    assert_eq!(local_nxt, LOCAL_ISS + 1);
    assert_eq!(run.kernel.processes[run.client.slot].result, None);
}

#[test]
fn p94f_socket_delivers_stream_bytes_and_client_reply_without_tcp_metadata() {
    let mut run = start_socket();
    let (peer_nxt, local_nxt) = establish(&mut run);

    run.send(&tcp_frame(peer_nxt, local_nxt, PSH_ACK, b"ping"));
    let ack = run.take_tx().expect("incoming stream bytes must receive TCP ACK");
    let data = run.take_tx().expect("ordinary socket client must produce pong reply");

    assert_eq!(ack[47], ACK);
    assert_eq!(u32::from_be_bytes(ack[38..42].try_into().unwrap()), local_nxt);
    assert_eq!(u32::from_be_bytes(ack[42..46].try_into().unwrap()), peer_nxt + 4);

    assert_eq!(data[47], PSH_ACK);
    assert_eq!(u16::from_be_bytes([data[16], data[17]]), 44);
    assert_eq!(u32::from_be_bytes(data[38..42].try_into().unwrap()), local_nxt);
    assert_eq!(u32::from_be_bytes(data[42..46].try_into().unwrap()), peer_nxt + 4);
    assert_eq!(&data[54..58], b"pong");
    assert_eq!(tcp_checksum(&data, 24), 0);
    assert_eq!(checksum(&data[14..34]), 0);
    assert_eq!(&data[58..60], &[0, 0]);
    assert_eq!(run.shared_bytes(4), b"pong");
}

#[test]
fn p94f_socket_rejects_bad_or_out_of_order_network_data_before_client_delivery() {
    let mut run = start_socket();
    let (peer_nxt, local_nxt) = establish(&mut run);

    let future = tcp_frame(peer_nxt + 1, local_nxt, PSH_ACK, b"ping");
    run.send(&future);
    assert!(run.take_tx().is_none());
    assert_eq!(run.shared_bytes(4), &[0, 0, 0, 0]);
    assert_eq!(
        run.kernel.processes[run.client.slot].recv_wait.as_ref().map(|w| w.peer),
        Some(run.service),
        "rejected TCP data must not wake the socket client",
    );

    let mut bad = tcp_frame(peer_nxt, local_nxt, PSH_ACK, b"ping");
    bad[50] ^= 1;
    run.send(&bad);
    assert!(run.take_tx().is_none());
    assert_eq!(run.shared_bytes(4), &[0, 0, 0, 0]);

    run.send(&tcp_frame(peer_nxt, local_nxt, PSH_ACK, b"ping"));
    assert!(run.take_tx().is_some());
    assert!(run.take_tx().is_some(), "exact segment must eventually reach client and reply");
}

#[test]
fn p94f_socket_service_owns_send_sequence_progression_not_client() {
    let mut run = start_socket();
    let (peer_nxt, local_nxt) = establish(&mut run);

    run.send(&tcp_frame(peer_nxt, local_nxt, PSH_ACK, b"ping"));
    let _ack = run.take_tx().unwrap();
    let data = run.take_tx().unwrap();
    assert_eq!(u32::from_be_bytes(data[38..42].try_into().unwrap()), local_nxt);

    let peer_after = peer_nxt + 4;
    let local_after = local_nxt + 4;
    run.send(&tcp_frame(peer_after, local_after, ACK, &[]));
    assert!(run.take_tx().is_none());

    run.send(&tcp_frame(peer_after, local_after, FIN | ACK, &[]));
    let final_ack = run.take_tx().expect("valid FIN receives final socket-owned ACK");
    assert_eq!(final_ack[47], ACK);
    assert_eq!(u32::from_be_bytes(final_ack[38..42].try_into().unwrap()), local_after);
    assert_eq!(u32::from_be_bytes(final_ack[42..46].try_into().unwrap()), peer_after + 1);
    assert_eq!(run.kernel.processes[run.service.slot].result, Some(ProcessResult::Exited(1)));
    assert_eq!(run.kernel.processes[run.client.slot].result, Some(ProcessResult::Exited(0)));
}

#[test]
fn p94f_socket_full_lifecycle_is_connected_data_send_closed_for_client() {
    let mut run = start_socket();
    let (peer_nxt, local_nxt) = establish(&mut run);

    run.send(&tcp_frame(peer_nxt, local_nxt, ACK, b"ping"));
    let ack = run.take_tx().unwrap();
    let response = run.take_tx().unwrap();
    assert_eq!(&response[54..58], b"pong");

    let peer_after = u32::from_be_bytes(ack[42..46].try_into().unwrap());
    let local_after = u32::from_be_bytes(response[38..42].try_into().unwrap()) + 4;
    run.send(&tcp_frame(peer_after, local_after, ACK, &[]));
    assert!(run.take_tx().is_none());
    run.send(&tcp_frame(peer_after, local_after, FIN | ACK, &[]));
    assert!(run.take_tx().is_some());

    assert_eq!(run.kernel.processes[run.service.slot].result, Some(ProcessResult::Exited(1)));
    assert_eq!(run.kernel.processes[run.client.slot].result, Some(ProcessResult::Exited(0)));
}
