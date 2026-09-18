//! Phase 9.4e TCP userspace integration tests.
//!
//! Protocol code lives in `userspace/system/services/net/tcp.c`. Rust only
//! constructs deterministic virtual-NIC frames, provisions the exact NIC/DMA
//! authority required by the service, and inspects committed TX bytes.

use std::sync::OnceLock;

use super::dev_compiler::{
    bootstrap_development_ccb, compile_c_with_ccb, CompiledCImage,
};
use super::fabric::Fabric;
use super::nic::{NicController, NIC_MAX_FRAME_SIZE};
use super::os::{BootGrant, BootImage, BootInfo, BootMap, Kernel, ProcessResult};
use super::state::{
    AgentId, CapabilityHandle, DeviceBinding, DeviceRights, ObjectId, ObjectKind, Permissions,
};

const NET_BUFFER_VADDR: u64 = 0x1_0000;
const NET_BUFFER_SIZE: u64 = NIC_MAX_FRAME_SIZE as u64;
const NET_STACK_VADDR: u64 = 0x2_0000;
const NET_STACK_SIZE: u64 = 0x4000;
const NET_TRAP_VADDR: u64 = 0x2_4000;
const NET_CODE_PHYS: u64 = 0x1_0000;
const NET_BUFFER_PHYS: u64 = 0x3_0000;
const NET_RAM_SIZE: usize = 0x40_0000;

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
        bootstrap_development_ccb().expect("phase 9.4e tests must bootstrap canonical CC_B")
    })
}

fn tcp_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/services/net/tcp.c"
    ))
}

fn tcp_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(ccb_image(), tcp_source())
            .expect("CC_B must compile the real TCP system service")
    })
}

struct NetRun {
    kernel: Kernel,
    binding: DeviceBinding,
    buffer: ObjectId,
}

fn start_tcp() -> NetRun {
    let image = tcp_image();
    assert_eq!(image.lit_start, 0,
        "phase 9.4e TCP source intentionally has no literal segment");
    assert!(image.code_size < NET_BUFFER_VADDR,
        "TCP service code must not overlap its fixed DMA-buffer mapping");

    let mut fabric = Fabric::new(NET_RAM_SIZE);
    let code = fabric.alloc_object(
        "p94e-tcp-code",
        image.bytes.len() as u64,
        ObjectKind::Memory,
    );
    assert!(fabric.place_object(code, NET_CODE_PHYS));
    assert!(fabric.initialize_object(code, 0, &image.bytes));
    assert!(fabric.seal_object(code));

    let buffer = fabric.alloc_object(
        "p94e-tcp-buffer",
        NET_BUFFER_SIZE,
        ObjectKind::Memory,
    );
    assert!(fabric.place_object(buffer, NET_BUFFER_PHYS));
    assert!(fabric.zero_object_extent(buffer));

    let boot = BootInfo {
        image: BootImage {
            obj: code,
            code_offset: 0,
            code_size: image.code_size,
            entry: 0,
            lit_start: image.lit_start,
        },
        grants: vec![BootGrant {
            obj: buffer,
            offset: 0,
            size: NET_BUFFER_SIZE,
            perms: Permissions::RW,
        }],
        maps: vec![BootMap {
            vaddr: NET_BUFFER_VADDR,
            size: NET_BUFFER_SIZE,
            obj: buffer,
            obj_offset: 0,
        }],
        code_vaddr: 0,
        stack_vaddr: NET_STACK_VADDR,
        stack_size: NET_STACK_SIZE,
        trap_vaddr: NET_TRAP_VADDR,
    };

    let mut kernel = Kernel::new(fabric);
    let binding = kernel.register_nic_device(
        NicController::new(AgentId(944)),
    ).expect("phase 9.4e test NIC registration");

    kernel.boot(&boot).expect("phase 9.4e TCP service boot");

    let rights = DeviceRights(
        DeviceRights::EVENT_WAIT.0 | DeviceRights::NIC_RX.0 | DeviceRights::NIC_TX.0,
    );
    let device = kernel.install_device_capability(0, binding.object, rights)
        .expect("phase 9.4e NIC capability");
    let dma = kernel.install_capability(
        0,
        buffer,
        0,
        NET_BUFFER_SIZE,
        Permissions::RW,
    ).expect("phase 9.4e DMA capability");
    assert_eq!(device, CapabilityHandle { slot: 0, generation: 0 });
    assert_eq!(dma, CapabilityHandle { slot: 1, generation: 0 });

    kernel.run(800_000, 220);
    assert_eq!(kernel.processes[0].result, None,
        "persistent TCP service must not exit when RX queue is initially empty");
    assert!(kernel.processes[0].event_wait.is_some(),
        "persistent TCP service must sleep in SYS_DEV_EVENT_WAIT when RX is empty");
    NetRun { kernel, binding, buffer }
}

impl NetRun {
    fn send(&mut self, frame: &[u8]) {
        assert!(!frame.is_empty());
        assert!(frame.len() <= NIC_MAX_FRAME_SIZE);
        assert!(self.kernel.inject_nic_rx(self.binding, frame));
        self.kernel.run(800_000, 220);
    }

    fn take_tx(&mut self) -> Option<Vec<u8>> {
        self.kernel.take_nic_tx(self.binding)
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

fn establish(run: &mut NetRun) -> (u32, u32) {
    let syn = tcp_frame(PEER_ISS, 0, SYN, &[]);
    run.send(&syn);
    let synack = run.take_tx().expect("valid SYN must receive SYN-ACK");
    let local_seq = u32::from_be_bytes(synack[38..42].try_into().unwrap());
    let peer_nxt = PEER_ISS.wrapping_add(1);
    let local_nxt = local_seq.wrapping_add(1);
    assert_eq!(local_seq, LOCAL_ISS);
    assert_eq!(u32::from_be_bytes(synack[42..46].try_into().unwrap()), peer_nxt);

    let ack = tcp_frame(peer_nxt, local_nxt, ACK, &[]);
    run.send(&ack);
    assert!(run.take_tx().is_none(), "final handshake ACK is not itself acknowledged");
    (peer_nxt, local_nxt)
}

#[test]
fn p94e_real_tcp_c_compiles_with_self_hosted_ccb() {
    let image = tcp_image();
    assert!(image.code_size > 0);
    assert_eq!(image.lit_start, 0);
    assert_eq!(image.process_slots_observed, 2,
        "compile-only CC_B must not execute phase 9.4e output");
}

#[test]
fn p94e_tcp_c_performs_exact_three_way_passive_open() {
    let mut run = start_tcp();
    let syn = tcp_frame(PEER_ISS, 0, SYN, &[]);
    run.send(&syn);
    let tx = run.take_tx().expect("SYN must receive SYN-ACK");

    assert_eq!(tx.len(), 60);
    assert_eq!(&tx[0..6], &PEER_MAC);
    assert_eq!(&tx[6..12], &LOCAL_MAC);
    assert_eq!(&tx[12..14], &[0x08, 0x00]);
    assert_eq!(tx[14], 0x45);
    assert_eq!(u16::from_be_bytes([tx[16], tx[17]]), 40);
    assert_eq!(tx[22], 64);
    assert_eq!(tx[23], 6);
    assert_eq!(&tx[26..30], &LOCAL_IP);
    assert_eq!(&tx[30..34], &PEER_IP);
    assert_eq!(checksum(&tx[14..34]), 0);

    assert_eq!(u16::from_be_bytes([tx[34], tx[35]]), SERVICE_PORT);
    assert_eq!(u16::from_be_bytes([tx[36], tx[37]]), PEER_PORT);
    assert_eq!(u32::from_be_bytes(tx[38..42].try_into().unwrap()), LOCAL_ISS);
    assert_eq!(u32::from_be_bytes(tx[42..46].try_into().unwrap()), PEER_ISS + 1);
    assert_eq!(tx[46], 0x50);
    assert_eq!(tx[47], SYN | ACK);
    assert_eq!(u16::from_be_bytes([tx[48], tx[49]]), 4096);
    assert_eq!(tcp_checksum(&tx, 20), 0);
    assert_eq!(&tx[54..60], &[0, 0, 0, 0, 0, 0]);

    let final_ack = tcp_frame(PEER_ISS + 1, LOCAL_ISS + 1, ACK, &[]);
    run.send(&final_ack);
    assert!(run.take_tx().is_none());
}

#[test]
fn p94e_tcp_c_rejects_bad_checksum_options_and_wrong_endpoint_before_syn() {
    let mut run = start_tcp();

    let mut badsum = tcp_frame(PEER_ISS, 0, SYN, &[]);
    badsum[50] ^= 0x01;
    run.send(&badsum);
    assert!(run.take_tx().is_none());

    let mut options = tcp_frame(PEER_ISS, 0, SYN, &[]);
    options[46] = 0x60;
    set_tcp_checksum(&mut options);
    run.send(&options);
    assert!(run.take_tx().is_none());

    let mut wrong = tcp_frame(PEER_ISS, 0, SYN, &[]);
    wrong[36..38].copy_from_slice(&(SERVICE_PORT + 1).to_be_bytes());
    set_tcp_checksum(&mut wrong);
    run.send(&wrong);
    assert!(run.take_tx().is_none());

    let syn = tcp_frame(PEER_ISS, 0, SYN, &[]);
    run.send(&syn);
    assert!(run.take_tx().is_some(),
        "rejected packets must not disturb LISTEN state");
}

#[test]
fn p94e_tcp_c_requires_exact_tuple_sequence_and_ack_to_establish() {
    let mut run = start_tcp();
    let syn = tcp_frame(PEER_ISS, 0, SYN, &[]);
    run.send(&syn);
    let synack = run.take_tx().unwrap();
    let peer_nxt = PEER_ISS + 1;
    let local_nxt = u32::from_be_bytes(synack[38..42].try_into().unwrap()) + 1;

    let wrong_ack = tcp_frame(peer_nxt, local_nxt + 1, ACK, &[]);
    run.send(&wrong_ack);
    assert!(run.take_tx().is_none());

    let mut wrong_tuple = tcp_frame(peer_nxt, local_nxt, ACK, &[]);
    wrong_tuple[34..36].copy_from_slice(&(PEER_PORT + 1).to_be_bytes());
    set_tcp_checksum(&mut wrong_tuple);
    run.send(&wrong_tuple);
    assert!(run.take_tx().is_none());

    let early_data = tcp_frame(peer_nxt, local_nxt, PSH_ACK, b"early");
    run.send(&early_data);
    assert!(run.take_tx().is_none(), "data cannot bypass SYN_RCVD");

    let final_ack = tcp_frame(peer_nxt, local_nxt, ACK, &[]);
    run.send(&final_ack);
    assert!(run.take_tx().is_none());

    let data = tcp_frame(peer_nxt, local_nxt, PSH_ACK, b"ok");
    run.send(&data);
    assert!(run.take_tx().is_some(), "data is accepted only after exact final ACK");
}

#[test]
fn p94e_tcp_c_acks_in_order_payload_by_exact_byte_count() {
    let mut run = start_tcp();
    let (peer_nxt, local_nxt) = establish(&mut run);
    let payload = b"Anka TCP payload!";
    let data = tcp_frame(peer_nxt, local_nxt, PSH_ACK, payload);
    assert_eq!((20 + payload.len()) & 1, 1,
        "witness intentionally exercises odd TCP checksum length");
    run.send(&data);
    let tx = run.take_tx().expect("in-order data must receive ACK");

    assert_eq!(u16::from_be_bytes([tx[16], tx[17]]), 40);
    assert_eq!(u32::from_be_bytes(tx[38..42].try_into().unwrap()), local_nxt);
    assert_eq!(
        u32::from_be_bytes(tx[42..46].try_into().unwrap()),
        peer_nxt + payload.len() as u32,
    );
    assert_eq!(tx[47], ACK);
    assert_eq!(tcp_checksum(&tx, 20), 0);
    assert_eq!(&tx[54..60], &[0, 0, 0, 0, 0, 0],
        "pure ACK must not leak received payload into Ethernet padding");
}

#[test]
fn p94e_tcp_c_ignores_out_of_order_or_wrong_ack_payload_then_accepts_exact_segment() {
    let mut run = start_tcp();
    let (peer_nxt, local_nxt) = establish(&mut run);
    let payload = b"order";

    let future = tcp_frame(peer_nxt + 1, local_nxt, ACK, payload);
    run.send(&future);
    assert!(run.take_tx().is_none());

    let wrong_ack = tcp_frame(peer_nxt, local_nxt + 1, ACK, payload);
    run.send(&wrong_ack);
    assert!(run.take_tx().is_none());

    let exact = tcp_frame(peer_nxt, local_nxt, ACK, payload);
    run.send(&exact);
    let tx = run.take_tx().expect("exact in-order segment must be acknowledged");
    assert_eq!(
        u32::from_be_bytes(tx[42..46].try_into().unwrap()),
        peer_nxt + payload.len() as u32,
    );
}

#[test]
fn p94e_tcp_c_fin_consumes_one_sequence_number_and_closes() {
    let mut run = start_tcp();
    let (peer_nxt, local_nxt) = establish(&mut run);
    let payload = b"bye";
    let data = tcp_frame(peer_nxt, local_nxt, ACK, payload);
    run.send(&data);
    let ack = run.take_tx().unwrap();
    let after_data = u32::from_be_bytes(ack[42..46].try_into().unwrap());

    let wrong_fin = tcp_frame(after_data + 1, local_nxt, FIN | ACK, &[]);
    run.send(&wrong_fin);
    assert!(run.take_tx().is_none());

    let fin = tcp_frame(after_data, local_nxt, FIN | ACK, &[]);
    run.send(&fin);
    let final_ack = run.take_tx().expect("in-order FIN must receive final ACK");
    assert_eq!(final_ack[47], ACK);
    assert_eq!(u32::from_be_bytes(final_ack[38..42].try_into().unwrap()), local_nxt);
    assert_eq!(u32::from_be_bytes(final_ack[42..46].try_into().unwrap()), after_data + 1);
    assert_eq!(run.kernel.processes[0].result, Some(ProcessResult::Exited(1)));
}

#[test]
fn p94e_tcp_c_requires_tcp_checksum_and_strict_ipv4_envelope() {
    let mut run = start_tcp();

    let mut zero = tcp_frame(PEER_ISS, 0, SYN, &[]);
    zero[50] = 0;
    zero[51] = 0;
    run.send(&zero);
    assert!(run.take_tx().is_none(), "TCP checksum zero is not an omission marker");

    let mut fragment = tcp_frame(PEER_ISS, 0, SYN, &[]);
    fragment[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
    set_ipv4_checksum(&mut fragment);
    run.send(&fragment);
    assert!(run.take_tx().is_none());

    let mut nonlocal = tcp_frame(PEER_ISS, 0, SYN, &[]);
    nonlocal[30..34].copy_from_slice(&[10, 0, 0, 99]);
    set_tcp_checksum(&mut nonlocal);
    set_ipv4_checksum(&mut nonlocal);
    run.send(&nonlocal);
    assert!(run.take_tx().is_none());

    let mut udp = tcp_frame(PEER_ISS, 0, SYN, &[]);
    udp[23] = 17;
    set_ipv4_checksum(&mut udp);
    run.send(&udp);
    assert!(run.take_tx().is_none());

    let syn = tcp_frame(PEER_ISS, 0, SYN, &[]);
    run.send(&syn);
    assert!(run.take_tx().is_some(), "strict-envelope rejects must not consume LISTEN");
}
