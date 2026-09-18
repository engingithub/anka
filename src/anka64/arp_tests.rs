//! Phase 9.4b executable witnesses for the first real Anka ARP service.
//!
//! The ARP parser and reply constructor live in user space:
//! `userspace/system/services/net/arp.c`.
//!
//! Rust supplies only a deterministic virtual-NIC execution environment and
//! opaque test frames.  The guest performs both SYS_NIC_RX and SYS_NIC_TX.

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

const ARP_BUFFER_VADDR: u64 = 0x1_0000;
const ARP_BUFFER_SIZE: u64 = NIC_MAX_FRAME_SIZE as u64;
const ARP_STACK_VADDR: u64 = 0x2_0000;
const ARP_STACK_SIZE: u64 = 0x4000;
const ARP_TRAP_VADDR: u64 = 0x2_4000;
const ARP_CODE_PHYS: u64 = 0x1_0000;
const ARP_BUFFER_PHYS: u64 = 0x3_0000;
const ARP_RAM_SIZE: usize = 0x40_0000;

const ARP_REPLIED: u64 = 1;
const ARP_NONLOCAL: u64 = 2;
const ARP_NO_REPLY: u64 = 3;
const ARP_MALFORMED: u64 = 64;

const LOCAL_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const LOCAL_IP: [u8; 4] = [10, 0, 0, 2];

fn arp_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/services/net/arp.c"
    ))
}

fn arp_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        let ccb = bootstrap_development_ccb()
            .expect("phase 9.4b test must bootstrap canonical CC_B");
        compile_c_with_ccb(&ccb, arp_source())
            .expect("CC_B must compile the real ARP system service")
    })
}

struct ArpRun {
    kernel: Kernel,
    binding: DeviceBinding,
    buffer: ObjectId,
}

fn run_arp_frame(frame: &[u8]) -> ArpRun {
    assert!(!frame.is_empty());
    assert!(frame.len() <= NIC_MAX_FRAME_SIZE);

    let image = arp_image();
    assert_eq!(image.lit_start, 0,
        "phase 9.4b ARP source intentionally has no literal segment");
    assert!(image.code_size < ARP_BUFFER_VADDR,
        "ARP code must not overlap its fixed DMA-buffer mapping");

    let mut fabric = Fabric::new(ARP_RAM_SIZE);

    let code = fabric.alloc_object(
        "p94b-arp-code",
        image.bytes.len() as u64,
        ObjectKind::Memory,
    );
    assert!(fabric.place_object(code, ARP_CODE_PHYS));
    assert!(fabric.initialize_object(code, 0, &image.bytes));
    assert!(fabric.seal_object(code));

    let buffer = fabric.alloc_object(
        "p94b-arp-buffer",
        ARP_BUFFER_SIZE,
        ObjectKind::Memory,
    );
    assert!(fabric.place_object(buffer, ARP_BUFFER_PHYS));
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
            size: ARP_BUFFER_SIZE,
            perms: Permissions::RW,
        }],
        maps: vec![BootMap {
            vaddr: ARP_BUFFER_VADDR,
            size: ARP_BUFFER_SIZE,
            obj: buffer,
            obj_offset: 0,
        }],
        code_vaddr: 0,
        stack_vaddr: ARP_STACK_VADDR,
        stack_size: ARP_STACK_SIZE,
        trap_vaddr: ARP_TRAP_VADDR,
    };

    let mut kernel = Kernel::new(fabric);
    let binding = kernel.register_nic_device(
        NicController::new(AgentId(941)),
    ).expect("test NIC registration");

    kernel.boot(&boot).expect("ARP service boot");

    // Phase 9.4b one-service startup ABI.  The device handle carries exactly
    // RX+TX for this NIC and the memory handle carries exactly RW for this
    // finite DMA buffer.  Neither authority is derived from the service name.
    let device = kernel.install_device_capability(
        0,
        binding.object,
        DeviceRights(DeviceRights::NIC_RX.0 | DeviceRights::NIC_TX.0),
    ).expect("NIC_RX|NIC_TX capability");
    let dma = kernel.install_capability(
        0,
        buffer,
        0,
        ARP_BUFFER_SIZE,
        Permissions::RW,
    ).expect("ARP RW DMA capability");
    assert_eq!(device, CapabilityHandle { slot: 0, generation: 0 });
    assert_eq!(dma, CapabilityHandle { slot: 1, generation: 0 });

    assert!(kernel.inject_nic_rx(binding, frame));
    kernel.run(300_000, 120);

    ArpRun { kernel, binding, buffer }
}

fn arp_frame(
    opcode: u16,
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_ip: [u8; 4],
) -> Vec<u8> {
    let mut frame = vec![0u8; 42];

    frame[0..6].copy_from_slice(&[0xFF; 6]);
    frame[6..12].copy_from_slice(&sender_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x06]);

    frame[14..16].copy_from_slice(&[0x00, 0x01]); // Ethernet
    frame[16..18].copy_from_slice(&[0x08, 0x00]); // IPv4
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&opcode.to_be_bytes());
    frame[22..28].copy_from_slice(&sender_mac);
    frame[28..32].copy_from_slice(&sender_ip);
    frame[32..38].copy_from_slice(&[0; 6]);
    frame[38..42].copy_from_slice(&target_ip);
    frame
}

fn assert_exit(run: &ArpRun, expected: u64) {
    assert_eq!(
        run.kernel.processes[0].result,
        Some(ProcessResult::Exited(expected)),
    );
}

#[test]
fn p94b_real_arp_c_compiles_with_self_hosted_ccb() {
    let image = arp_image();
    assert!(image.code_size > 0);
    assert_eq!(image.lit_start, 0);
    assert_eq!(image.process_slots_observed, 2,
        "compile-only CC_B must not execute the produced ARP program");
}

#[test]
fn p94b_real_arp_c_rejects_short_payload_before_arp_header_access() {
    let frame = vec![0xA5; 41];
    let run = run_arp_frame(&frame);
    assert_exit(&run, ARP_MALFORMED);
    assert!(run.kernel.device_registry.lookup(run.binding).unwrap()
        .controller.as_nic().unwrap().tx_frame_count() == 0);

    let phys = run.kernel.fabric.translate(run.buffer, 0).unwrap();
    assert_eq!(
        run.kernel.fabric.read_physical(phys, frame.len() as u64),
        frame.as_slice(),
        "short frame must arrive through real SYS_NIC_RX before C rejects it",
    );
}

#[test]
fn p94b_real_arp_c_rejects_unsupported_header_without_tx() {
    let mut frame = arp_frame(
        1,
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
        [10, 0, 0, 9],
        LOCAL_IP,
    );
    frame[18] = 5; // HLEN must be exactly 6.

    let run = run_arp_frame(&frame);
    assert_exit(&run, ARP_MALFORMED);
    assert_eq!(run.kernel.device_registry.lookup(run.binding).unwrap()
        .controller.as_nic().unwrap().tx_frame_count(), 0);
}

#[test]
fn p94b_real_arp_c_ignores_nonlocal_request_and_incoming_reply() {
    let request = arp_frame(
        1,
        [0x20, 0x21, 0x22, 0x23, 0x24, 0x25],
        [10, 0, 0, 7],
        [10, 0, 0, 99],
    );
    let run = run_arp_frame(&request);
    assert_exit(&run, ARP_NONLOCAL);
    assert_eq!(run.kernel.device_registry.lookup(run.binding).unwrap()
        .controller.as_nic().unwrap().tx_frame_count(), 0);

    let reply = arp_frame(
        2,
        [0x30, 0x31, 0x32, 0x33, 0x34, 0x35],
        [10, 0, 0, 8],
        LOCAL_IP,
    );
    let run = run_arp_frame(&reply);
    assert_exit(&run, ARP_NO_REPLY);
    assert_eq!(run.kernel.device_registry.lookup(run.binding).unwrap()
        .controller.as_nic().unwrap().tx_frame_count(), 0,
        "an incoming ARP reply must not recursively trigger another reply");
}

#[test]
fn p94b_real_arp_c_builds_and_transmits_exact_local_reply() {
    let sender_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let sender_ip = [10, 0, 0, 9];
    let mut request = arp_frame(1, sender_mac, sender_ip, LOCAL_IP);
    request.resize(60, 0xA7);
    let mut run = run_arp_frame(&request);
    assert_exit(&run, ARP_REPLIED);

    let tx = run.kernel.take_nic_tx(run.binding)
        .expect("local ARP request must produce one committed NIC TX frame");
    assert_eq!(tx.len(), request.len());
    assert_eq!(&tx[0..6], &sender_mac);
    assert_eq!(&tx[6..12], &LOCAL_MAC);
    assert_eq!(&tx[12..14], &[0x08, 0x06]);
    assert_eq!(&tx[14..20], &[0x00, 0x01, 0x08, 0x00, 0x06, 0x04]);
    assert_eq!(&tx[20..22], &[0x00, 0x02]);
    assert_eq!(&tx[22..28], &LOCAL_MAC);
    assert_eq!(&tx[28..32], &LOCAL_IP);
    assert_eq!(&tx[32..38], &sender_mac);
    assert_eq!(&tx[38..42], &sender_ip);
    assert_eq!(&tx[42..], &request[42..],
        "ARP reply must preserve received Ethernet padding bytes");
    assert!(run.kernel.take_nic_tx(run.binding).is_none(),
        "one request must produce exactly one ARP reply");
}

#[test]
fn p94b_real_arp_c_uses_network_order_for_opcode_and_header_fields() {
    let sender_mac = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45];
    let sender_ip = [10, 0, 0, 10];

    let mut reversed_opcode = arp_frame(1, sender_mac, sender_ip, LOCAL_IP);
    reversed_opcode[20] = 1;
    reversed_opcode[21] = 0;
    let run = run_arp_frame(&reversed_opcode);
    assert_exit(&run, ARP_NO_REPLY);
    assert_eq!(run.kernel.device_registry.lookup(run.binding).unwrap()
        .controller.as_nic().unwrap().tx_frame_count(), 0);

    let mut reversed_htype = arp_frame(1, sender_mac, sender_ip, LOCAL_IP);
    reversed_htype[14] = 1;
    reversed_htype[15] = 0;
    let run = run_arp_frame(&reversed_htype);
    assert_exit(&run, ARP_MALFORMED);
    assert_eq!(run.kernel.device_registry.lookup(run.binding).unwrap()
        .controller.as_nic().unwrap().tx_frame_count(), 0);
}
