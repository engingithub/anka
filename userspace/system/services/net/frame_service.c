#include "stdlib.h"
int dispatch(char *p,int n);

int main() {
    char *frame=malloc(1514);
    char extra[1];
    int n=0;
    int result=64;
    if (frame==0) { return 70; }
    n=read_bytes(frame,1514);
    if ((0<n) & (n<=1514)) {
        if (read_bytes(extra,1)==0) { result=dispatch(frame,n); }
    }
    if (result==1) {
        if (write_bytes(frame,n)!=n) { result=71; }
    }
    free(frame);
    return result;
}

int net16(char *p) { return ((*p)<<8) | (*(p+1)); }
int set16(char *p,int n) { *p=(n>>8)&255; *(p+1)=n&255; return 0; }
int copyoct(char *dst,int delta,int n) {
    int i=0;
    while (i<n) { *(dst+i)=*(dst+(delta+i)); i=i+1; }
    return 0;
}
int maclocal(char *p) { *p=2; *(p+1)=0; *(p+2)=0; *(p+3)=0; *(p+4)=0; *(p+5)=2; return 0; }
int iplocal(char *p) { return (net16(p)==2560) & (net16(p+2)==2); }
int putlocal(char *p) { set16(p,2560); set16(p+2,2); return 0; }
int sum16(char *p,int len) {
    int i=0; int sum=0;
    while (i+1<len) { sum=sum+net16(p+i); sum=(sum&65535)+(sum>>16); i=i+2; }
    if (i<len) { sum=sum+((*(p+i))<<8); sum=(sum&65535)+(sum>>16); }
    return 65535-sum;
}
int arpframe(char *p,int n) {
    if (n<42) { return 64; }
    if ((net16(p+14)!=1) | (net16(p+16)!=2048) | (net16(p+18)!=1540)) { return 64; }
    if (net16(p+20)!=1) { return 3; }
    if (iplocal(p+38)==0) { return 2; }
    copyoct(p,22,6); copyoct(p+32,0-10,10);
    maclocal(p+6); maclocal(p+22); putlocal(p+28); set16(p+20,2);
    return 1;
}
int replyip(char *p) {
    copyoct(p,6,6); maclocal(p+6);
    copyoct(p+30,0-4,4); putlocal(p+26); *(p+22)=64;
    set16(p+24,0); set16(p+24,sum16(p+14,20));
    return 0;
}
int udpsum(char *p,int len) {
    int sum=65535-sum16(p+26,8);
    sum=sum+17+len;
    sum=sum+(65535-sum16(p+34,len));
    sum=(sum&65535)+(sum>>16);
    sum=(sum&65535)+(sum>>16);
    return 65535-sum;
}
int udpecho(char *p,int len) {
    int src=0; int check=0;
    if (len<8) { return 64; }
    if (net16(p+38)!=len) { return 64; }
    if (net16(p+36)!=49152) { return 3; }
    if (net16(p+40)!=0) {
        if (udpsum(p,len)!=0) { return 64; }
    }
    src=net16(p+34);
    replyip(p); set16(p+34,49152); set16(p+36,src);
    set16(p+40,0); check=udpsum(p,len);
    if (check==0) { check=65535; }
    set16(p+40,check);
    return 1;
}
int ipframe(char *p,int n) {
    int total=0; int ilen=0;
    if (n<34) { return 64; }
    if (*(p+14)!=69) { return 64; }
    total=net16(p+16);
    if ((total<20) | (n-14<total)) { return 64; }
    if ((net16(p+20)&16383)!=0) { return 64; }
    if (sum16(p+14,20)!=0) { return 64; }
    if (iplocal(p+30)==0) { return 2; }
    if (*(p+23)==17) { return udpecho(p,total-20); }
    if (*(p+23)!=1) { return 3; }
    ilen=total-20;
    if (ilen<8) { return 64; }
    if (sum16(p+34,ilen)!=0) { return 64; }
    if (net16(p+34)!=2048) { return 3; }
    replyip(p);
    set16(p+34,0); set16(p+36,0); set16(p+36,sum16(p+34,ilen));
    return 1;
}
int dispatch(char *p,int n) {
    int kind=0;
    if ((n<14) | (1514<n)) { return 64; }
    kind=net16(p+12);
    if (kind==2054) { return arpframe(p,n); }
    if (kind==2048) { return ipframe(p,n); }
    return 3;
}
