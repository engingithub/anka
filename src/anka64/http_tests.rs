//! Phase 9.4g HTTP /alive integration tests.
//!
//! `socket.c` owns NIC/TCP state. `httpd.c` is an ordinary application
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
const HTTP_BUF_VADDR: u64 = 0x1_8000;
const SOCK_BUF_SIZE: u64 = 1024;
const STACK_VADDR: u64 = 0x2_0000;
const STACK_SIZE: u64 = 0x4000;
const TRAP_VADDR: u64 = CODE_SIZE - 0x10;
const RAM_SIZE: usize = 0x40_0000;

const SVC_CODE_PHYS: u64 = 0x1_0000;
const HTTP_CODE_PHYS: u64 = 0x3_0000;
const NET_PHYS: u64 = 0x5_0000;
const SOCK_PHYS: u64 = 0x6_0000;
const SVC_STACK_PHYS: u64 = 0x7_0000;
const HTTP_STACK_PHYS: u64 = 0x8_0000;

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
        bootstrap_development_ccb().expect("phase 9.4g tests must bootstrap canonical CC_B")
    })
}

fn socket_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/services/net/socket.c"
    ))
}

fn http_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/services/net/httpd.c"
    ))
}

fn socket_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(ccb_image(), socket_source())
            .expect("CC_B must compile the real socket service")
    })
}

fn http_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(ccb_image(), http_source())
            .expect("CC_B must compile the HTTP application")
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
        "phase 9.4g C witnesses intentionally have no literal segment");
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

struct HttpRun {
    kernel: Kernel,
    binding: DeviceBinding,
    shared: ObjectId,
    service: ProcessKey,
    http: ProcessKey,
}

fn start_http() -> HttpRun {
    let simg = socket_image();
    let cimg = http_image();

    let mut fabric = Fabric::new(RAM_SIZE);
    let netbuf = fabric.alloc_object("p94g-netbuf", NET_SIZE, ObjectKind::Memory);
    assert!(fabric.place_object(netbuf, NET_PHYS));
    assert!(fabric.zero_object_extent(netbuf));

    let shared = fabric.alloc_object("p94g-sockbuf", SOCK_BUF_SIZE, ObjectKind::Memory);
    assert!(fabric.place_object(shared, SOCK_PHYS));
    assert!(fabric.zero_object_extent(shared));

    let service_core = make_core(
        &mut fabric,
        simg,
        AgentId(946),
        "p94g-socket",
        SVC_CODE_PHYS,
        SVC_STACK_PHYS,
        &[(NET_VADDR, netbuf, NET_SIZE), (SVC_BUF_VADDR, shared, SOCK_BUF_SIZE)],
    );
    let http_core = make_core(
        &mut fabric,
        cimg,
        AgentId(947),
        "p94g-http",
        HTTP_CODE_PHYS,
        HTTP_STACK_PHYS,
        &[(HTTP_BUF_VADDR, shared, SOCK_BUF_SIZE)],
    );

    let mut kernel = Kernel::new(fabric);
    let service = kernel.spawn(service_core);
    let http = kernel.spawn(http_core);
    assert_eq!(service, ProcessKey { slot: 0, generation: 0 });
    assert_eq!(http, ProcessKey { slot: 1, generation: 0 });

    let binding = kernel.register_nic_device(
        NicController::new(AgentId(948)),
    ).expect("phase 9.4g test NIC registration");

    let rights = DeviceRights(
        DeviceRights::EVENT_WAIT.0 | DeviceRights::NIC_RX.0 | DeviceRights::NIC_TX.0,
    );
    let device = kernel.install_device_capability(service.slot, binding.object, rights)
        .expect("phase 9.4g socket NIC capability");
    let dma = kernel.install_capability(
        service.slot,
        netbuf,
        0,
        NET_SIZE,
        Permissions::RW,
    ).expect("phase 9.4g socket DMA capability");
    assert_eq!(device, CapabilityHandle { slot: 0, generation: 0 });
    assert_eq!(dma, CapabilityHandle { slot: 1, generation: 0 });

    assert_eq!(
        kernel.processes[http.slot].cap_table.as_ref().unwrap().occupied_count(),
        0,
        "HTTP application must receive no NIC or DMA capability",
    );

    kernel.run(800_000, 260);
    assert_eq!(kernel.processes[service.slot].result, None);
    assert_eq!(kernel.processes[http.slot].result, None);
    assert!(kernel.processes[service.slot].event_wait.is_some(),
        "socket service waits for NIC activity without polling");
    assert_eq!(
        kernel.processes[http.slot].recv_wait.as_ref().map(|w| w.peer),
        Some(service),
        "http initially waits on the exact socket-service incarnation",
    );

    HttpRun { kernel, binding, shared, service, http }
}

impl HttpRun {
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

fn establish(run: &mut HttpRun) -> (u32, u32) {
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
        run.kernel.processes[run.http.slot].recv_wait.as_ref().map(|w| w.peer),
        Some(run.service),
        "after CONNECTED the http waits again for socket DATA",
    );
    (peer_nxt, local_nxt)
}


const ALIVE_REQ: &[u8] = b"GET /alive HTTP/1.1\r\n\r\n";
const ALIVE_HDR_REQ: &[u8] = b"GET /alive HTTP/1.1\r\nHost: anka64\r\nX-Test: yes\r\n\r\n";
const ALIVE_RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nAnka64 is alive.";
const NOT_FOUND_RESP: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

fn exchange(run: &mut HttpRun, request: &[u8]) -> (u32, u32, Vec<u8>, Vec<u8>) {
    let (peer_nxt, local_nxt) = establish(run);
    run.send(&tcp_frame(peer_nxt, local_nxt, PSH_ACK, request));
    let ack = run.take_tx().expect("HTTP request bytes must receive TCP ACK");
    let response = run.take_tx().expect("HTTP application must answer through socket SEND");
    (peer_nxt, local_nxt, ack, response)
}

fn tcp_payload(frame: &[u8]) -> &[u8] {
    let total = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    let tcp_len = total - 20;
    &frame[54..34 + tcp_len]
}

fn close_after_response(run: &mut HttpRun, peer_nxt: u32, local_nxt: u32, req_len: usize, resp_len: usize) {
    let peer_after = peer_nxt.wrapping_add(req_len as u32);
    let local_after = local_nxt.wrapping_add(resp_len as u32);
    run.send(&tcp_frame(peer_after, local_after, ACK, &[]));
    assert!(run.take_tx().is_none(), "pure ACK for HTTP response needs no reply");
    run.send(&tcp_frame(peer_after, local_after, FIN | ACK, &[]));
    let final_ack = run.take_tx().expect("valid FIN receives final socket-owned ACK");
    assert_eq!(final_ack[47], ACK);
    assert_eq!(u32::from_be_bytes(final_ack[38..42].try_into().unwrap()), local_after);
    assert_eq!(u32::from_be_bytes(final_ack[42..46].try_into().unwrap()), peer_after + 1);
    assert_eq!(run.kernel.processes[run.service.slot].result, Some(ProcessResult::Exited(1)));
    assert_eq!(run.kernel.processes[run.http.slot].result, Some(ProcessResult::Exited(0)));
}

#[test]
fn p94g_socket_service_and_httpd_compile_with_self_hosted_ccb() {
    let service = socket_image();
    let http = http_image();
    assert!(service.code_size > 0);
    assert!(http.code_size > 0);
    assert_eq!(service.lit_start, 0);
    assert_eq!(http.lit_start, 0,
        "phase 9.4g HTTP witness intentionally avoids host-style literal dependence");
    assert_eq!(service.process_slots_observed, 2);
    assert_eq!(http.process_slots_observed, 2);
}

#[test]
fn p94g_http_application_has_stream_memory_but_no_nic_capability() {
    let run = start_http();
    assert_eq!(
        run.kernel.processes[run.http.slot].cap_table.as_ref().unwrap().occupied_count(),
        0,
        "HTTP application must receive no NIC or DMA capability",
    );
    assert!(run.kernel.processes[run.service.slot].event_wait.is_some());
    assert_eq!(
        run.kernel.processes[run.http.slot].recv_wait.as_ref().map(|w| w.peer),
        Some(run.service),
        "HTTP application waits on exact socket-service incarnation",
    );
}

#[test]
fn p94g_get_alive_returns_exact_http_200_and_body() {
    let mut run = start_http();
    let (peer_nxt, local_nxt, ack, response) = exchange(&mut run, ALIVE_REQ);

    assert_eq!(ack[47], ACK);
    assert_eq!(u32::from_be_bytes(ack[38..42].try_into().unwrap()), local_nxt);
    assert_eq!(u32::from_be_bytes(ack[42..46].try_into().unwrap()), peer_nxt + ALIVE_REQ.len() as u32);

    assert_eq!(response[47], PSH_ACK);
    assert_eq!(tcp_payload(&response), ALIVE_RESP);
    assert_eq!(tcp_checksum(&response, 20 + ALIVE_RESP.len()), 0);
    assert_eq!(checksum(&response[14..34]), 0);
    assert_eq!(run.shared_bytes(ALIVE_RESP.len()), ALIVE_RESP);

    close_after_response(&mut run, peer_nxt, local_nxt, ALIVE_REQ.len(), ALIVE_RESP.len());
}

#[test]
fn p94g_alive_accepts_opaque_headers_until_terminal_blank_line() {
    let mut run = start_http();
    let (peer_nxt, local_nxt, _ack, response) = exchange(&mut run, ALIVE_HDR_REQ);
    assert_eq!(tcp_payload(&response), ALIVE_RESP);
    close_after_response(&mut run, peer_nxt, local_nxt, ALIVE_HDR_REQ.len(), ALIVE_RESP.len());
}

#[test]
fn p94g_wrong_route_returns_bounded_404_without_alive_body() {
    let mut run = start_http();
    let request = b"GET /missing HTTP/1.1\r\n\r\n";
    let (peer_nxt, local_nxt, _ack, response) = exchange(&mut run, request);
    assert_eq!(tcp_payload(&response), NOT_FOUND_RESP);
    assert!(!tcp_payload(&response).windows(b"Anka64 is alive.".len())
        .any(|w| w == b"Anka64 is alive."));
    close_after_response(&mut run, peer_nxt, local_nxt, request.len(), NOT_FOUND_RESP.len());
}

#[test]
fn p94g_wrong_method_version_or_incomplete_request_never_gets_alive_200() {
    for request in [
        b"POST /alive HTTP/1.1\r\n\r\n".as_slice(),
        b"GET /alive HTTP/1.0\r\n\r\n".as_slice(),
        b"GET /alive HTTP/1.1\r\nHost: anka64\r\n".as_slice(),
    ] {
        let mut run = start_http();
        let (peer_nxt, local_nxt, _ack, response) = exchange(&mut run, request);
        assert_eq!(tcp_payload(&response), NOT_FOUND_RESP);
        close_after_response(&mut run, peer_nxt, local_nxt, request.len(), NOT_FOUND_RESP.len());
    }
}

#[test]
fn p94g_http_response_length_is_owned_as_socket_stream_progress() {
    let mut run = start_http();
    let (peer_nxt, local_nxt, ack, response) = exchange(&mut run, ALIVE_REQ);
    let peer_after = u32::from_be_bytes(ack[42..46].try_into().unwrap());
    assert_eq!(peer_after, peer_nxt + ALIVE_REQ.len() as u32);
    assert_eq!(u32::from_be_bytes(response[38..42].try_into().unwrap()), local_nxt);
    assert_eq!(u32::from_be_bytes(response[42..46].try_into().unwrap()), peer_after);

    let local_after = local_nxt + ALIVE_RESP.len() as u32;
    run.send(&tcp_frame(peer_after, local_after, ACK, &[]));
    assert!(run.take_tx().is_none());
    run.send(&tcp_frame(peer_after, local_after, FIN | ACK, &[]));
    let final_ack = run.take_tx().unwrap();
    assert_eq!(u32::from_be_bytes(final_ack[38..42].try_into().unwrap()), local_after);
    assert_eq!(u32::from_be_bytes(final_ack[42..46].try_into().unwrap()), peer_after + 1);
    assert_eq!(run.kernel.processes[run.http.slot].result, Some(ProcessResult::Exited(0)));
}
