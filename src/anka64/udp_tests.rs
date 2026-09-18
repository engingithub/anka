//! Phase 9.4d executable witnesses for the real Anka UDP service.
//!
//! Protocol code lives in `userspace/system/services/net/udp.c`.  Rust only
//! constructs deterministic virtual-NIC frames, provisions the exact NIC/DMA
//! authority required by the one-shot service, and inspects committed TX bytes.

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

const UDP_REPLIED: u64 = 1;
const NONLOCAL: u64 = 2;
const NO_REPLY: u64 = 3;
const MALFORMED: u64 = 64;

const LOCAL_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const LOCAL_IP: [u8; 4] = [10, 0, 0, 2];
const PEER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const PEER_IP: [u8; 4] = [10, 0, 0, 9];
const SERVICE_PORT: u16 = 49152;
const PEER_PORT: u16 = 34567;

fn ccb_image() -> &'static Vec<u8> {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        bootstrap_development_ccb().expect("phase 9.4d tests must bootstrap canonical CC_B")
    })
}

fn udp_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/services/net/udp.c"
    ))
}

fn udp_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(ccb_image(), udp_source())
            .expect("CC_B must compile the real UDP system service")
    })
}

struct NetRun {
    kernel: Kernel,
    binding: DeviceBinding,
    buffer: ObjectId,
}

fn run_udp(frame: &[u8]) -> NetRun {
    let image = udp_image();
    assert!(!frame.is_empty());
    assert!(frame.len() <= NIC_MAX_FRAME_SIZE);
    assert_eq!(image.lit_start, 0,
        "phase 9.4d UDP source intentionally has no literal segment");
    assert!(image.code_size < NET_BUFFER_VADDR,
        "UDP service code must not overlap its fixed DMA-buffer mapping");

    let mut fabric = Fabric::new(NET_RAM_SIZE);
    let code = fabric.alloc_object(
        "p94d-udp-code",
        image.bytes.len() as u64,
        ObjectKind::Memory,
    );
    assert!(fabric.place_object(code, NET_CODE_PHYS));
    assert!(fabric.initialize_object(code, 0, &image.bytes));
    assert!(fabric.seal_object(code));

    let buffer = fabric.alloc_object(
        "p94d-udp-buffer",
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
        NicController::new(AgentId(943)),
    ).expect("phase 9.4d test NIC registration");

    kernel.boot(&boot).expect("phase 9.4d UDP service boot");

    let rights = DeviceRights(DeviceRights::NIC_RX.0 | DeviceRights::NIC_TX.0);
    let device = kernel.install_device_capability(0, binding.object, rights)
        .expect("phase 9.4d NIC capability");
    let dma = kernel.install_capability(
        0,
        buffer,
        0,
        NET_BUFFER_SIZE,
        Permissions::RW,
    ).expect("phase 9.4d DMA capability");
    assert_eq!(device, CapabilityHandle { slot: 0, generation: 0 });
    assert_eq!(dma, CapabilityHandle { slot: 1, generation: 0 });

    assert!(kernel.inject_nic_rx(binding, frame));
    kernel.run(500_000, 180);

    NetRun { kernel, binding, buffer }
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

fn udp_checksum(frame: &[u8], udp_len: usize) -> u16 {
    let mut bytes = Vec::with_capacity(12 + udp_len);
    bytes.extend_from_slice(&frame[26..30]);
    bytes.extend_from_slice(&frame[30..34]);
    bytes.push(0);
    bytes.push(17);
    bytes.extend_from_slice(&(udp_len as u16).to_be_bytes());
    bytes.extend_from_slice(&frame[34..34 + udp_len]);
    checksum(&bytes)
}

fn set_ipv4_checksum(frame: &mut [u8]) {
    frame[24] = 0;
    frame[25] = 0;
    let sum = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&sum.to_be_bytes());
}

fn set_udp_checksum(frame: &mut [u8]) {
    let udp_len = u16::from_be_bytes([frame[38], frame[39]]) as usize;
    frame[40] = 0;
    frame[41] = 0;
    let mut sum = udp_checksum(frame, udp_len);
    if sum == 0 {
        sum = 0xFFFF;
    }
    frame[40..42].copy_from_slice(&sum.to_be_bytes());
}

fn udp_frame(payload: &[u8], with_checksum: bool) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let frame_len = (14 + total_len).max(60);
    let mut frame = vec![0xA7; frame_len];

    frame[0..6].copy_from_slice(&LOCAL_MAC);
    frame[6..12].copy_from_slice(&PEER_MAC);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[15] = 0;
    frame[16..18].copy_from_slice(&(total_len as u16).to_be_bytes());
    frame[18..20].copy_from_slice(&0x4321u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[22] = 51;
    frame[23] = 17;
    frame[24] = 0;
    frame[25] = 0;
    frame[26..30].copy_from_slice(&PEER_IP);
    frame[30..34].copy_from_slice(&LOCAL_IP);

    frame[34..36].copy_from_slice(&PEER_PORT.to_be_bytes());
    frame[36..38].copy_from_slice(&SERVICE_PORT.to_be_bytes());
    frame[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());
    frame[40] = 0;
    frame[41] = 0;
    frame[42..42 + payload.len()].copy_from_slice(payload);

    if with_checksum {
        set_udp_checksum(&mut frame);
    }
    set_ipv4_checksum(&mut frame);
    frame
}

fn assert_exit(run: &NetRun, expected: u64) {
    assert_eq!(
        run.kernel.processes[0].result,
        Some(ProcessResult::Exited(expected)),
    );
}

fn tx_count(run: &NetRun) -> usize {
    run.kernel.device_registry.lookup(run.binding).unwrap()
        .controller.as_nic().unwrap().tx_frame_count()
}

#[test]
fn p94d_real_udp_c_compiles_with_self_hosted_ccb() {
    let image = udp_image();
    assert!(image.code_size > 0);
    assert_eq!(image.lit_start, 0);
    assert_eq!(image.process_slots_observed, 2,
        "compile-only CC_B must not execute phase 9.4d output");
}

#[test]
fn p94d_udp_c_accepts_ipv4_zero_checksum_as_omitted_and_replies() {
    let request = udp_frame(b"anka udp", false);
    assert_eq!(u16::from_be_bytes([request[40], request[41]]), 0);

    let mut run = run_udp(&request);
    assert_exit(&run, UDP_REPLIED);
    let tx = run.kernel.take_nic_tx(run.binding)
        .expect("zero-checksum IPv4 UDP request must receive one reply");
    let udp_len = u16::from_be_bytes([tx[38], tx[39]]) as usize;
    assert_ne!(u16::from_be_bytes([tx[40], tx[41]]), 0,
        "Anka emits an explicit checksum even when the request omitted one");
    assert_eq!(udp_checksum(&tx, udp_len), 0);
}

#[test]
fn p94d_udp_c_rejects_short_mismatched_and_bad_present_checksum() {
    let frame = udp_frame(b"length", true);

    let mut short = frame.clone();
    short[38..40].copy_from_slice(&7u16.to_be_bytes());
    set_ipv4_checksum(&mut short);
    let run = run_udp(&short);
    assert_exit(&run, MALFORMED);
    assert_eq!(tx_count(&run), 0);

    let mut mismatch = frame.clone();
    let udp_len = u16::from_be_bytes([mismatch[38], mismatch[39]]);
    mismatch[38..40].copy_from_slice(&(udp_len - 1).to_be_bytes());
    set_ipv4_checksum(&mut mismatch);
    let run = run_udp(&mismatch);
    assert_exit(&run, MALFORMED);
    assert_eq!(tx_count(&run), 0);

    let mut badsum = frame.clone();
    badsum[40] ^= 0x01;
    let run = run_udp(&badsum);
    assert_exit(&run, MALFORMED);
    assert_eq!(tx_count(&run), 0);
}

#[test]
fn p94d_udp_c_filters_nonlocal_wrong_protocol_and_wrong_port() {
    let frame = udp_frame(b"filter", true);

    let mut nonlocal = frame.clone();
    nonlocal[30..34].copy_from_slice(&[10, 0, 0, 99]);
    set_udp_checksum(&mut nonlocal);
    set_ipv4_checksum(&mut nonlocal);
    let run = run_udp(&nonlocal);
    assert_exit(&run, NONLOCAL);
    assert_eq!(tx_count(&run), 0);

    let mut icmp = frame.clone();
    icmp[23] = 1;
    set_ipv4_checksum(&mut icmp);
    let run = run_udp(&icmp);
    assert_exit(&run, NO_REPLY);
    assert_eq!(tx_count(&run), 0);

    let mut wrong = frame.clone();
    wrong[36..38].copy_from_slice(&49153u16.to_be_bytes());
    set_udp_checksum(&mut wrong);
    set_ipv4_checksum(&mut wrong);
    let run = run_udp(&wrong);
    assert_exit(&run, NO_REPLY);
    assert_eq!(tx_count(&run), 0);
}

#[test]
fn p94d_udp_c_builds_exact_reply_swaps_ports_and_preserves_payload_padding() {
    let payload = b"Anka64 UDP payload";
    let request = udp_frame(payload, true);
    let total = u16::from_be_bytes([request[16], request[17]]) as usize;
    let udp_len = u16::from_be_bytes([request[38], request[39]]) as usize;
    let padding = request[14 + total..].to_vec();

    let mut run = run_udp(&request);
    assert_exit(&run, UDP_REPLIED);
    let tx = run.kernel.take_nic_tx(run.binding).unwrap();

    assert_eq!(tx.len(), request.len());
    assert_eq!(&tx[0..6], &PEER_MAC);
    assert_eq!(&tx[6..12], &LOCAL_MAC);
    assert_eq!(&tx[12..14], &[0x08, 0x00]);
    assert_eq!(tx[14], 0x45);
    assert_eq!(&tx[20..22], &request[20..22]);
    assert_eq!(tx[22], 64);
    assert_eq!(tx[23], 17);
    assert_eq!(&tx[26..30], &LOCAL_IP);
    assert_eq!(&tx[30..34], &PEER_IP);
    assert_eq!(checksum(&tx[14..34]), 0);

    assert_eq!(u16::from_be_bytes([tx[34], tx[35]]), SERVICE_PORT);
    assert_eq!(u16::from_be_bytes([tx[36], tx[37]]), PEER_PORT);
    assert_eq!(u16::from_be_bytes([tx[38], tx[39]]) as usize, udp_len);
    assert_eq!(&tx[42..42 + payload.len()], payload);
    assert_eq!(udp_checksum(&tx, udp_len), 0);
    assert_eq!(&tx[14 + total..], padding.as_slice());
    assert!(run.kernel.take_nic_tx(run.binding).is_none());
}

#[test]
fn p94d_udp_c_handles_odd_length_payload_and_valid_present_checksum() {
    let payload = b"odd!!";
    let request = udp_frame(payload, true);
    let udp_len = u16::from_be_bytes([request[38], request[39]]) as usize;
    assert_eq!(udp_len, 13);
    assert_eq!(udp_checksum(&request, udp_len), 0);

    let mut run = run_udp(&request);
    assert_exit(&run, UDP_REPLIED);
    let tx = run.kernel.take_nic_tx(run.binding).unwrap();
    assert_eq!(&tx[42..47], payload);
    assert_eq!(udp_checksum(&tx, udp_len), 0,
        "odd trailing UDP byte must contribute in the network-order high byte");
}

#[test]
fn p94d_udp_c_rejects_fragmentation_options_and_truncated_ipv4() {
    let frame = udp_frame(b"shape", true);

    let mut fragment = frame.clone();
    fragment[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
    set_ipv4_checksum(&mut fragment);
    let run = run_udp(&fragment);
    assert_exit(&run, MALFORMED);

    let mut options = frame.clone();
    options[14] = 0x46;
    set_ipv4_checksum(&mut options);
    let run = run_udp(&options);
    assert_exit(&run, MALFORMED);

    let mut trunc = frame.clone();
    let total = u16::from_be_bytes([trunc[16], trunc[17]]) as usize;
    trunc.truncate(14 + total - 1);
    let run = run_udp(&trunc);
    assert_exit(&run, MALFORMED);
}
