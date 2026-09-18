//! Phase 9.4a executable witnesses for the first real Anka C network service.
//!
//! The Ethernet parser itself lives in user space:
//! `userspace/system/services/net/ethernet.c`.
//!
//! This module supplies only a deterministic machine environment for tests:
//! a virtual NIC, one mapped DMA buffer, and exact capability-table handles.
//! The C program performs the real SYS_NIC_RX finite-DMA operation before it
//! inspects any frame bytes.

use std::sync::OnceLock;

use super::dev_compiler::{
    bootstrap_development_ccb, compile_c_with_ccb, CompiledCImage,
};
use super::fabric::Fabric;
use super::nic::{NicController, NIC_MAX_FRAME_SIZE};
use super::os::{BootGrant, BootImage, BootInfo, BootMap, Kernel, ProcessResult};
use super::state::{
    AgentId, CapabilityHandle, DeviceRights, ObjectId, ObjectKind, Permissions,
};

const ETHERNET_BUFFER_VADDR: u64 = 0x1_0000;
const ETHERNET_BUFFER_SIZE: u64 = NIC_MAX_FRAME_SIZE as u64;
const ETHERNET_STACK_VADDR: u64 = 0x2_0000;
const ETHERNET_STACK_SIZE: u64 = 0x4000;
const ETHERNET_TRAP_VADDR: u64 = 0x2_4000;
const ETHERNET_CODE_PHYS: u64 = 0x1_0000;
const ETHERNET_BUFFER_PHYS: u64 = 0x3_0000;
const ETHERNET_RAM_SIZE: usize = 0x40_0000;

const DISPATCH_ARP: u64 = 1;
const DISPATCH_IPV4: u64 = 2;
const DISPATCH_UNKNOWN: u64 = 3;
const DISPATCH_MALFORMED: u64 = 64;

fn ethernet_source() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/userspace/system/services/net/ethernet.c"
    ))
}

fn ethernet_image() -> &'static CompiledCImage {
    static IMAGE: OnceLock<CompiledCImage> = OnceLock::new();
    IMAGE.get_or_init(|| {
        let ccb = bootstrap_development_ccb()
            .expect("phase 9.4a test must bootstrap canonical CC_B");
        compile_c_with_ccb(&ccb, ethernet_source())
            .expect("CC_B must compile the real Ethernet system service")
    })
}

struct EthernetRun {
    kernel: Kernel,
    buffer: ObjectId,
}

fn run_ethernet_frame(frame: &[u8]) -> EthernetRun {
    assert!(!frame.is_empty());
    assert!(frame.len() <= NIC_MAX_FRAME_SIZE);

    let image = ethernet_image();
    assert_eq!(image.lit_start, 0,
        "phase 9.4a Ethernet source intentionally has no literal segment");
    assert!(image.code_size < ETHERNET_BUFFER_VADDR,
        "Ethernet code must not overlap its fixed DMA-buffer mapping");

    let mut fabric = Fabric::new(ETHERNET_RAM_SIZE);

    let code = fabric.alloc_object(
        "p94a-ethernet-code",
        image.bytes.len() as u64,
        ObjectKind::Memory,
    );
    assert!(fabric.place_object(code, ETHERNET_CODE_PHYS));
    assert!(fabric.initialize_object(code, 0, &image.bytes));
    assert!(fabric.seal_object(code));

    let buffer = fabric.alloc_object(
        "p94a-ethernet-buffer",
        ETHERNET_BUFFER_SIZE,
        ObjectKind::Memory,
    );
    assert!(fabric.place_object(buffer, ETHERNET_BUFFER_PHYS));
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
            size: ETHERNET_BUFFER_SIZE,
            perms: Permissions::RW,
        }],
        maps: vec![BootMap {
            vaddr: ETHERNET_BUFFER_VADDR,
            size: ETHERNET_BUFFER_SIZE,
            obj: buffer,
            obj_offset: 0,
        }],
        code_vaddr: 0,
        stack_vaddr: ETHERNET_STACK_VADDR,
        stack_size: ETHERNET_STACK_SIZE,
        trap_vaddr: ETHERNET_TRAP_VADDR,
    };

    let mut kernel = Kernel::new(fabric);
    let binding = kernel.register_nic_device(
        NicController::new(AgentId(940)),
    ).expect("test NIC registration");

    kernel.boot(&boot).expect("Ethernet service boot");

    // Phase 9.4a bootstrap convention for this one-service witness:
    // the empty child cap table receives NIC first (slot 0/gen 0) and its
    // exact DMA buffer second (slot 1/gen 0).  The C source names only these
    // handles; paths/names still create no authority.
    let device = kernel.install_device_capability(
        0,
        binding.object,
        DeviceRights::NIC_RX,
    ).expect("NIC_RX capability");
    let dma = kernel.install_capability(
        0,
        buffer,
        0,
        ETHERNET_BUFFER_SIZE,
        Permissions::WRITE,
    ).expect("Ethernet WRITE DMA capability");
    assert_eq!(device, CapabilityHandle { slot: 0, generation: 0 });
    assert_eq!(dma, CapabilityHandle { slot: 1, generation: 0 });

    assert!(kernel.inject_nic_rx(binding, frame));
    kernel.run(200_000, 100);

    EthernetRun { kernel, buffer }
}

fn frame_with_ethertype(len: usize, high: u8, low: u8) -> Vec<u8> {
    assert!(len >= 14);
    let mut frame = vec![0u8; len];
    for i in 0..6 {
        frame[i] = 0x10 + i as u8;
        frame[6 + i] = 0x20 + i as u8;
    }
    frame[12] = high;
    frame[13] = low;
    for (i, byte) in frame.iter_mut().enumerate().skip(14) {
        *byte = (i as u8).wrapping_mul(3).wrapping_add(1);
    }
    frame
}

fn assert_exit(run: &EthernetRun, expected: u64) {
    assert_eq!(
        run.kernel.processes[0].result,
        Some(ProcessResult::Exited(expected)),
    );
}

#[test]
fn p94a_real_ethernet_c_compiles_with_self_hosted_ccb() {
    let image = ethernet_image();
    assert!(image.code_size > 0);
    assert_eq!(image.lit_start, 0);
    assert_eq!(image.process_slots_observed, 2,
        "compile-only CC_B must not execute the produced Ethernet program");
}

#[test]
fn p94a_real_ethernet_c_rejects_truncated_header_after_nic_dma() {
    let frame = vec![0xA5; 13];
    let run = run_ethernet_frame(&frame);
    assert_exit(&run, DISPATCH_MALFORMED);

    let phys = run.kernel.fabric.translate(run.buffer, 0).unwrap();
    assert_eq!(
        run.kernel.fabric.read_physical(phys, frame.len() as u64),
        frame.as_slice(),
        "C parser must inspect bytes delivered by real SYS_NIC_RX DMA",
    );
}

#[test]
fn p94a_real_ethernet_c_extracts_arp_ethertype_in_network_order() {
    let frame = frame_with_ethertype(64, 0x08, 0x06);
    let run = run_ethernet_frame(&frame);
    assert_exit(&run, DISPATCH_ARP);

    let reversed = frame_with_ethertype(64, 0x06, 0x08);
    let run = run_ethernet_frame(&reversed);
    assert_exit(&run, DISPATCH_UNKNOWN);
}

#[test]
fn p94a_real_ethernet_c_dispatches_ipv4_and_accepts_unknown_types() {
    let ipv4 = frame_with_ethertype(128, 0x08, 0x00);
    let run = run_ethernet_frame(&ipv4);
    assert_exit(&run, DISPATCH_IPV4);

    let unknown = frame_with_ethertype(128, 0x88, 0xB5);
    let run = run_ethernet_frame(&unknown);
    assert_exit(&run, DISPATCH_UNKNOWN);
}

#[test]
fn p94a_real_ethernet_c_accepts_maximum_untagged_frame() {
    let frame = frame_with_ethertype(NIC_MAX_FRAME_SIZE, 0x88, 0xB5);
    let run = run_ethernet_frame(&frame);
    assert_exit(&run, DISPATCH_UNKNOWN);

    let phys = run.kernel.fabric.translate(run.buffer, 0).unwrap();
    assert_eq!(
        run.kernel.fabric.read_physical(phys, frame.len() as u64),
        frame.as_slice(),
    );
}
