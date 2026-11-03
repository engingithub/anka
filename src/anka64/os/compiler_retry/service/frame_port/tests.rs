use super::*;
use crate::anka64::{cc2_fixed_point,compiler_adapter::RebuildPublicationAuthority,
    source_bundle::{SourceBundle,SourceBundleMember}};

#[test]
fn s3_frame_driver_commits_rx_and_different_exact_tx_prefix() {
    let rx=vec![0x9f;N];let tx:Vec<_>=(0..60u8).collect();
    let (port,data)=Port::new().unwrap().receive(&rx).unwrap();
    assert_eq!(data,rx);assert!(port.0.idle());
    assert_eq!(port.transmit(&tx).unwrap(),tx);
}
#[test]
fn s3_frame_denies_invalid_offer_and_revoked_device() {
    for n in [0,13,N+1] {assert!(offer(&ProcessResult::Exited(1),&vec![0;n]).is_err());}
    for code in [0,2,3,64,71] {assert!(offer(&ProcessResult::Exited(code),&[0;60]).is_err());}
    assert!(offer(&ProcessResult::ProtectionFault,&[0;60]).is_err());
    let(mut port,_)=Port::new().unwrap().receive(&[0;60]).unwrap();
    let dev=port.0.dev.object;port.0.k.fabric.revoke(dev);
    assert!(port.transmit(&[0;60]).is_err());
}

const LOCAL:[u8;6]=[2,0,0,0,0,2];
const PEER:[u8;6]=[0x52,0x54,0,0x12,0x34,0x56];
const IP:[u8;4]=[10,0,0,2];
const REMOTE:[u8;4]=[10,0,0,9];
fn arp()->(Vec<u8>,Vec<u8>) {
    let mut r=vec![0xa7;60];r[..6].fill(255);r[6..12].copy_from_slice(&PEER);
    r[12..22].copy_from_slice(&[8,6,0,1,8,0,6,4,0,1]);
    r[22..28].copy_from_slice(&PEER);r[28..32].copy_from_slice(&REMOTE);
    r[32..38].fill(0);r[38..42].copy_from_slice(&IP);
    let mut e=r.clone();e[..6].copy_from_slice(&PEER);e[6..12].copy_from_slice(&LOCAL);
    e[21]=2;e[22..28].copy_from_slice(&LOCAL);e[28..32].copy_from_slice(&IP);
    e[32..38].copy_from_slice(&PEER);e[38..42].copy_from_slice(&REMOTE);
    (r,e)
}
fn checksum(data:&[u8])->[u8;2] {
    let mut sum=0u32;
    for pair in data.chunks(2){sum+=u16::from_be_bytes([pair[0],*pair.get(1).unwrap_or(&0)]) as u32;}
    while sum>65535 {sum=(sum&65535)+(sum>>16);}(!(sum as u16)).to_be_bytes()
}
fn echo(reply:bool,n:usize)->Vec<u8> {
    let size=42+n;let mut f=vec![0u8;size.max(60)];
    f[..6].copy_from_slice(if reply{&PEER}else{&LOCAL});f[6..12].copy_from_slice(if reply{&LOCAL}else{&PEER});
    f[12..16].copy_from_slice(&[8,0,0x45,0]);f[16..18].copy_from_slice(&((size-14) as u16).to_be_bytes());
    f[18..22].copy_from_slice(&[0x12,0x34,0x40,0]);f[22]=if reply{64}else{29};f[23]=1;
    f[26..30].copy_from_slice(if reply{&IP}else{&REMOTE});f[30..34].copy_from_slice(if reply{&REMOTE}else{&IP});
    let ip=checksum(&f[14..34]);f[24..26].copy_from_slice(&ip);
    f[34]=if reply{0}else{8};f[38..42].copy_from_slice(&[0x98,0x76,0x54,0x32]);
    for (i,x) in f[42..size].iter_mut().enumerate(){*x=(i*17) as u8;}
    let icmp=checksum(&f[34..size]);f[36..38].copy_from_slice(&icmp);f[size..].fill(0xa7);f
}

#[test]
#[ignore="one real guest bootstrap, protected Ethernet service, and virtual NIC DMA"]
fn s3_frame_real_ethernet_arp_icmp_and_udp() {
    let exec=DeveloperExecutionAuthority::provision();let publish=RebuildPublicationAuthority::provision();
    let net=DeveloperFrameAuthority::provision();let input=DeveloperInputAuthority::provision();
    let lineage=cc2_fixed_point::witness_cc2_fixed_point(Some(&exec),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankacc2_stage3.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankapp.c")),
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/compiler/ankald.c"))).unwrap();
    let mut s=RebuildService::new(&lineage,&exec).unwrap();
    let source=SourceBundle::new("frame.c",[
        SourceBundleMember::new("frame.c",include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/system/services/net/frame_service.c")).to_vec()).unwrap(),
        SourceBundleMember::new("stdlib.h",include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/userspace/include/stdlib.h")).to_vec()).unwrap(),
    ]).unwrap();
    let job=s.submit(&source,0x40000,super::super::WORK,&exec,&publish).unwrap();
    let start=std::time::Instant::now();let mut last=start;
    let module=loop {
        assert!(start.elapsed().as_secs()<300,"frame service compiler deadline");
        if let Some(e)=s.poll(job,&exec,&publish).unwrap(){break e;}
        if last.elapsed().as_secs()>=5{eprintln!("S3 frame compile: {}s",start.elapsed().as_secs());last=std::time::Instant::now();}
    };
    let epoch=s.link(&[module],&exec,&publish).unwrap();let (request,reply)=arp();
    let mut foreign=request.clone();foreign[41]=99;
    let mut bad_sum=echo(false,3);bad_sum[43]^=1;
    let mut fragment=echo(false,3);fragment[20]=0x20;fragment[24..26].fill(0);
    let sum=checksum(&fragment[14..34]);fragment[24..26].copy_from_slice(&sum);
    let mut trunc=echo(false,3);trunc.truncate(43);
    let before=s.kernel.fabric.scoped_pointers.total_reserved_bytes();
    for (label,rx,code,want) in [
        ("ARP",request.clone(),1,reply.clone()),("foreign",foreign,2,vec![]),
        ("ARP reply",reply,3,vec![]),("runt",vec![0;13],64,vec![]),
        ("EtherType",vec![0;14],3,vec![]),("echo",echo(false,3),1,echo(true,3)),
        ("MTU",echo(false,N-42),1,echo(true,N-42)),("checksum",bad_sum,64,vec![]),
        ("fragment",fragment,64,vec![]),("length",trunc,64,vec![])].into_iter().chain(crate::anka64::udp_tests::udp_parity_cases()) {
        let mut wire=None;
        let result=s.run_frame(epoch,&exec,&input,&net,&rx,|bytes|{wire=Some((bytes.len(),bytes==want.as_slice()));Ok(())})
            .unwrap_or_else(|e|panic!("{label}: {e}"));
        assert_eq!(result,ProcessResult::Exited(code),"{label}");assert_eq!(wire,Some((want.len(),true)),"{label}");
        assert!(s.kernel.linked_compiler_receipt(epoch).is_ok());assert_eq!(s.kernel.fabric.scoped_pointers.total_reserved_bytes(),before);
    }
    eprintln!("S3/S5 passed: 10 Ethernet/ARP/ICMP and 17 UDP parity exchanges; exact virtual NIC TX, drops, receipts and refunds");
}
