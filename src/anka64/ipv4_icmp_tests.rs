//! Phase 9.4c executable witnesses for real Anka IPv4 + ICMP echo services.
//!
//! Protocol code lives in user space:
//! `userspace/system/services/net/ipv4.c` and
//! `userspace/system/services/net/icmp.c`.
//!
//! Rust supplies only deterministic virtual-NIC frames and the exact startup
//! authority required by each one-shot service.  IPv4/ICMP parsing, checksum
//! validation, echo construction, and NIC TX all execute in CC_B-compiled C.

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

const DISPATCH_ICMP: u64 = 1;
const NONLOCAL: u64 = 2;
const NO_REPLY: u64 = 3;
const MALFORMED: u64 = 64;
const ECHO_REPLIED: u64 = 1;

const LOCAL_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const LOCAL_IP: [u8; 4] = [10, 0, 0, 2];
const PEER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const PEER_IP: [u8; 4] = [10, 0, 0, 9];

fn ccb_image() -> &'static Vec<u8> {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE.get_or_init(|| {
        bootstrap_development_ccb()
            .expect("phase 9.4c tests must bootstrap canonical CC_B")
    })
}

fn ipv4_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/services/net/ipv4.c"
    ))
}

fn icmp_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/services/net/icmp.c"
    ))
}

fn ipv4_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(ccb_image(), ipv4_source())
            .expect("CC_B must compile the real IPv4 system service")
    })
}

fn icmp_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        compile_c_with_ccb(ccb_image(), icmp_source())
            .expect("CC_B must compile the real ICMP echo system service")
    })
}

struct NetRun {
    kernel: Kernel,
    binding: DeviceBinding,
    buffer: ObjectId,
}

fn run_service(image: &CompiledCImage, frame: &[u8], allow_tx: bool) -> NetRun {
    assert!(!frame.is_empty());
    assert!(frame.len() <= NIC_MAX_FRAME_SIZE);
    assert_eq!(image.lit_start, 0,
        "phase 9.4c network sources intentionally have no literal segment");
    assert!(image.code_size < NET_BUFFER_VADDR,
        "network service code must not overlap its fixed DMA-buffer mapping");

    let mut fabric = Fabric::new(NET_RAM_SIZE);

    let code = fabric.alloc_object(
        "p94c-network-code",
        image.bytes.len() as u64,
        ObjectKind::Memory,
    );
    assert!(fabric.place_object(code, NET_CODE_PHYS));
    assert!(fabric.initialize_object(code, 0, &image.bytes));
    assert!(fabric.seal_object(code));

    let buffer = fabric.alloc_object(
        "p94c-network-buffer",
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
        NicController::new(AgentId(942)),
    ).expect("phase 9.4c test NIC registration");

    kernel.boot(&boot).expect("phase 9.4c service boot");

    let rights = if allow_tx {
        DeviceRights(DeviceRights::NIC_RX.0 | DeviceRights::NIC_TX.0)
    } else {
        DeviceRights::NIC_RX
    };
    let dma_perms = if allow_tx { Permissions::RW } else { Permissions::WRITE };

    let device = kernel.install_device_capability(0, binding.object, rights)
        .expect("phase 9.4c NIC capability");
    let dma = kernel.install_capability(
        0,
        buffer,
        0,
        NET_BUFFER_SIZE,
        dma_perms,
    ).expect("phase 9.4c DMA capability");
    assert_eq!(device, CapabilityHandle { slot: 0, generation: 0 });
    assert_eq!(dma, CapabilityHandle { slot: 1, generation: 0 });

    assert!(kernel.inject_nic_rx(binding, frame));
    kernel.run(500_000, 160);

    NetRun { kernel, binding, buffer }
}

fn run_ipv4(frame: &[u8]) -> NetRun {
    run_service(ipv4_image(), frame, false)
}

fn run_icmp(frame: &[u8]) -> NetRun {
    run_service(icmp_image(), frame, true)
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

fn set_ipv4_checksum(frame: &mut [u8]) {
    frame[24] = 0;
    frame[25] = 0;
    let sum = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&sum.to_be_bytes());
}

fn set_icmp_checksum(frame: &mut [u8]) {
    let total = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    let ilen = total - 20;
    frame[36] = 0;
    frame[37] = 0;
    let sum = checksum(&frame[34..34 + ilen]);
    frame[36..38].copy_from_slice(&sum.to_be_bytes());
}

fn echo_frame(payload: &[u8]) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let total_len = 20 + icmp_len;
    let frame_len = (14 + total_len).max(60);
    let mut frame = vec![0xA7; frame_len];

    frame[0..6].copy_from_slice(&LOCAL_MAC);
    frame[6..12].copy_from_slice(&PEER_MAC);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);

    frame[14] = 0x45;
    frame[15] = 0;
    frame[16..18].copy_from_slice(&(total_len as u16).to_be_bytes());
    frame[18..20].copy_from_slice(&0x1234u16.to_be_bytes());
    frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // DF; not fragmented.
    frame[22] = 55;
    frame[23] = 1;
    frame[24] = 0;
    frame[25] = 0;
    frame[26..30].copy_from_slice(&PEER_IP);
    frame[30..34].copy_from_slice(&LOCAL_IP);

    frame[34] = 8;
    frame[35] = 0;
    frame[36] = 0;
    frame[37] = 0;
    frame[38..40].copy_from_slice(&0xBEEFu16.to_be_bytes());
    frame[40..42].copy_from_slice(&0x0102u16.to_be_bytes());
    frame[42..42 + payload.len()].copy_from_slice(payload);

    set_icmp_checksum(&mut frame);
    set_ipv4_checksum(&mut frame);
    frame
}

fn assert_exit(run: &NetRun, expected: u64) {
    assert_eq!(
        run.kernel.processes[0].result,
        Some(ProcessResult::Exited(expected)),
    );
}

#[test]
fn p94c_real_ipv4_and_icmp_c_compile_with_self_hosted_ccb() {
    for image in [ipv4_image(), icmp_image()] {
        assert!(image.code_size > 0);
        assert_eq!(image.lit_start, 0);
        assert_eq!(image.process_slots_observed, 2,
            "compile-only CC_B must not execute phase 9.4c output");
    }
}

#[test]
fn p94c_ipv4_c_dispatches_only_local_icmp_after_full_validation() {
    let frame = echo_frame(b"anka");
    let run = run_ipv4(&frame);
    assert_exit(&run, DISPATCH_ICMP);

    let mut nonlocal = frame.clone();
    nonlocal[30..34].copy_from_slice(&[10, 0, 0, 99]);
    set_ipv4_checksum(&mut nonlocal);
    let run = run_ipv4(&nonlocal);
    assert_exit(&run, NONLOCAL);

    let mut udp = frame.clone();
    udp[23] = 17;
    set_ipv4_checksum(&mut udp);
    let run = run_ipv4(&udp);
    assert_exit(&run, NO_REPLY);
}

#[test]
fn p94c_ipv4_c_rejects_options_fragmentation_bad_checksum_and_truncation() {
    let frame = echo_frame(b"shape");

    let mut options = frame.clone();
    options[14] = 0x46;
    set_ipv4_checksum(&mut options);
    let run = run_ipv4(&options);
    assert_exit(&run, MALFORMED);

    let mut fragment = frame.clone();
    fragment[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
    set_ipv4_checksum(&mut fragment);
    let run = run_ipv4(&fragment);
    assert_exit(&run, MALFORMED);

    let mut badsum = frame.clone();
    badsum[24] ^= 0x01;
    let run = run_ipv4(&badsum);
    assert_exit(&run, MALFORMED);

    let mut truncated = frame.clone();
    truncated[16..18].copy_from_slice(&60u16.to_be_bytes());
    set_ipv4_checksum(&mut truncated);
    truncated.truncate(50); // only 36 bytes of IPv4 remain after Ethernet.
    let run = run_ipv4(&truncated);
    assert_exit(&run, MALFORMED);
}

#[test]
fn p94c_icmp_c_rejects_bad_icmp_checksum_short_header_and_echo_reply() {
    let frame = echo_frame(b"echo");

    let mut badsum = frame.clone();
    badsum[36] ^= 0x01;
    let run = run_icmp(&badsum);
    assert_exit(&run, MALFORMED);
    assert_eq!(run.kernel.device_registry.lookup(run.binding).unwrap()
        .controller.as_nic().unwrap().tx_frame_count(), 0);

    let mut short = echo_frame(b"");
    short[16..18].copy_from_slice(&27u16.to_be_bytes());
    set_ipv4_checksum(&mut short);
    let run = run_icmp(&short);
    assert_exit(&run, MALFORMED);
    assert_eq!(run.kernel.device_registry.lookup(run.binding).unwrap()
        .controller.as_nic().unwrap().tx_frame_count(), 0);

    let mut reply = frame.clone();
    reply[34] = 0;
    set_icmp_checksum(&mut reply);
    let run = run_icmp(&reply);
    assert_exit(&run, NO_REPLY);
    assert_eq!(run.kernel.device_registry.lookup(run.binding).unwrap()
        .controller.as_nic().unwrap().tx_frame_count(), 0,
        "an incoming echo reply must not recursively produce another reply");
}

#[test]
fn p94c_icmp_c_builds_exact_echo_reply_and_preserves_payload_and_padding() {
    let payload = b"Anka64 ping payload";
    let request = echo_frame(payload);
    let request_len = request.len();
    let total = u16::from_be_bytes([request[16], request[17]]) as usize;
    let ilen = total - 20;
    let original_padding = request[14 + total..].to_vec();

    let mut run = run_icmp(&request);
    assert_exit(&run, ECHO_REPLIED);

    let tx = run.kernel.take_nic_tx(run.binding)
        .expect("valid local ICMP echo request must commit one NIC TX frame");
    assert_eq!(tx.len(), request_len);
    assert_eq!(&tx[0..6], &PEER_MAC);
    assert_eq!(&tx[6..12], &LOCAL_MAC);
    assert_eq!(&tx[12..14], &[0x08, 0x00]);

    assert_eq!(tx[14], 0x45);
    assert_eq!(u16::from_be_bytes([tx[16], tx[17]]) as usize, total);
    assert_eq!(&tx[20..22], &request[20..22], "DF/nonfragmented field is preserved");
    assert_eq!(tx[22], 64);
    assert_eq!(tx[23], 1);
    assert_eq!(&tx[26..30], &LOCAL_IP);
    assert_eq!(&tx[30..34], &PEER_IP);
    assert_eq!(checksum(&tx[14..34]), 0, "reply IPv4 checksum must validate");

    assert_eq!(tx[34], 0);
    assert_eq!(tx[35], 0);
    assert_eq!(&tx[38..40], &request[38..40], "identifier must be conserved");
    assert_eq!(&tx[40..42], &request[40..42], "sequence must be conserved");
    assert_eq!(&tx[42..42 + payload.len()], payload, "opaque payload must be conserved");
    assert_eq!(checksum(&tx[34..34 + ilen]), 0, "reply ICMP checksum must validate");
    assert_eq!(&tx[14 + total..], original_padding.as_slice(),
        "Ethernet padding outside IPv4 total length must remain untouched");
    assert!(run.kernel.take_nic_tx(run.binding).is_none(),
        "one echo request must produce exactly one echo reply");
}

#[test]
fn p94c_icmp_c_handles_odd_length_echo_payload_checksum() {
    let payload = b"odd!!"; // 5 bytes: ICMP message length is 13 bytes.
    let request = echo_frame(payload);
    let mut run = run_icmp(&request);
    assert_exit(&run, ECHO_REPLIED);

    let tx = run.kernel.take_nic_tx(run.binding).unwrap();
    let total = u16::from_be_bytes([tx[16], tx[17]]) as usize;
    let ilen = total - 20;
    assert_eq!(ilen, 13);
    assert_eq!(&tx[42..47], payload);
    assert_eq!(checksum(&tx[34..34 + ilen]), 0,
        "odd trailing ICMP byte must contribute in the network-order high byte");
}
