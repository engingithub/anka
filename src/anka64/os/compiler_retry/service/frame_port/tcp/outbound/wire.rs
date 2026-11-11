//! Fixed Ethernet/IPv4/TCP development route. No options, fragments or offload.
use std::net::{Ipv4Addr,SocketAddr};
use super::N;
pub(super) const SYN:u8=2;
pub(super) const FIN:u8=1;
pub(super) const ACK:u8=16;
pub(super) const PSH:u8=8;
#[derive(Clone,Copy,PartialEq,Eq)]
pub(super) struct End {mac:[u8;6],ip:[u8;4],port:u16}
impl End {pub(super) fn addr(self)->SocketAddr{(Ipv4Addr::from(self.ip),self.port).into()}}
pub(super) const LOCAL:End=End{mac:[2,0,0,0,0,2],ip:[10,0,0,2],port:49154};
pub(super) const STORAGE:End=End{mac:[2,0,0,0,0,1],ip:[10,0,0,1],port:49155};
fn sum(mut n:u32,b:&[u8])->u32{for w in b.chunks(2){n+=u16::from_be_bytes([w[0],*w.get(1).unwrap_or(&0)]) as u32;}n}
fn checksum(mut n:u32)->u16{while n>>16!=0{n=(n&65535)+(n>>16);}!(n as u16)}
fn pseudo(src:End,dst:End,len:usize)->u32{sum(sum(6+len as u32,&src.ip),&dst.ip)}
pub(super) struct Segment<'a>{pub seq:u32,pub ack:u32,pub flags:u8,pub window:u16,pub body:&'a [u8]}
pub(super) fn make(src:End,dst:End,s:Segment<'_>)->Vec<u8>{
    let total=40+s.body.len();let mut b=vec![0;(14+total).max(60)];
    b[..6].copy_from_slice(&dst.mac);b[6..12].copy_from_slice(&src.mac);b[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    b[14]=0x45;b[16..18].copy_from_slice(&(total as u16).to_be_bytes());b[22]=64;b[23]=6;
    b[26..30].copy_from_slice(&src.ip);b[30..34].copy_from_slice(&dst.ip);
    let ip=checksum(sum(0,&b[14..34]));b[24..26].copy_from_slice(&ip.to_be_bytes());
    b[34..36].copy_from_slice(&src.port.to_be_bytes());b[36..38].copy_from_slice(&dst.port.to_be_bytes());
    b[38..42].copy_from_slice(&s.seq.to_be_bytes());b[42..46].copy_from_slice(&s.ack.to_be_bytes());
    b[46]=0x50;b[47]=s.flags;b[48..50].copy_from_slice(&s.window.to_be_bytes());b[54..14+total].copy_from_slice(s.body);
    let tcp=checksum(sum(pseudo(src,dst,total-20),&b[34..14+total]));b[50..52].copy_from_slice(&tcp.to_be_bytes());b
}
pub(super) fn parse<'a>(src:End,dst:End,b:&'a [u8])->Option<Segment<'a>>{
    if !(54..=N).contains(&b.len()) || b[..6]!=dst.mac || b[6..12]!=src.mac || b[12..14]!=[8,0]
        || b[14]!=0x45 || b[22]==0 || b[23]!=6 || (b[20]&!0x40)!=0 || b[21]!=0
        || b[26..30]!=src.ip || b[30..34]!=dst.ip || b[34..36]!=src.port.to_be_bytes()
        || b[36..38]!=dst.port.to_be_bytes() || b[46]!=0x50 || b[52..54]!=[0,0] {return None;}
    let n=u16::from_be_bytes([b[16],b[17]]) as usize;
    if n<40 || 14+n>b.len() || b.len()>(14+n).max(60)
        || checksum(sum(0,&b[14..34]))!=0 || checksum(sum(pseudo(src,dst,n-20),&b[34..14+n]))!=0{return None;}
    Some(Segment{seq:u32::from_be_bytes(b[38..42].try_into().ok()?),ack:u32::from_be_bytes(b[42..46].try_into().ok()?),
        flags:b[47],window:u16::from_be_bytes([b[48],b[49]]),body:&b[54..14+n]})
}
