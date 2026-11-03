#include "stdlib.h"
int transit(char *x,int n);
int emitrec(char *x,int action,int n);

int main() {
    char *x=malloc(3063);
    char extra[1];
    int n=0; int action=0; int result=70;
    if (x==0) {return 70;}
    if (read_bytes(x,35)==35) {
        n=read_bytes(x+35,1514);
        if ((0<n) & (n<=1514)) {
            if (read_bytes(extra,1)==0) {
                action=transit(x,n);
                if (action==0) {result=0;} else {result=emitrec(x,action,n);}
            }
        }
    }
    free(x);return result;
}
int nw(char *p) {return ((*p)<<8)|(*(p+1));}
int dw(char *p) {return (nw(p)<<16)|nw(p+2);}
int putw(char *p,int v) {*p=(v>>8)&255;*(p+1)=v&255;return 0;}
int putd(char *p,int v) {putw(p,v>>16);putw(p+2,v);return 0;}
int foldsum(char *p,int n,int sum) {
    int i=0;
    while (i+1<n) {sum=sum+nw(p+i);sum=(sum&65535)+(sum>>16);i=i+2;}
    if (i<n) {sum=sum+((*(p+i))<<8);}
    while (65535<sum) {sum=(sum&65535)+(sum>>16);}
    return 65535-sum;
}
int tcpcheck(char *p,int n) {return foldsum(p+34,n,nw(p+26)+nw(p+28)+nw(p+30)+nw(p+32)+6+n);}
int transit(char *x,int n) {
    char *s=x+3;char *p=x+35;
    int total=0;int len=0;int flags=0;int seq=0;int ack=0;int i=0;
    if (*x==2) {
        if (((*s)!=2) | (*(s+2)!=0) | (1024<n)) {return 0;}
        return 6;
    }
    if ((*x!=1) | (n<54)) {return 0;}
    if ((nw(p)!=512) | (nw(p+2)!=0) | (nw(p+4)!=2)) {return 0;}
    if ((nw(p+12)!=2048) | (*(p+14)!=69) | (*(p+23)!=6)) {return 0;}
    total=nw(p+16);
    if ((total<40) | (n-14<total) | ((nw(p+20)&49151)!=0)) {return 0;}
    if ((dw(p+30)!=167772162) | (nw(p+36)!=49153) | (*(p+46)!=80)) {return 0;}
    if (foldsum(p+14,20,0)!=0) {return 0;}
    if (tcpcheck(p,total-20)!=0) {return 0;}
    seq=dw(p+38);ack=dw(p+42);len=total-40;flags=*(p+47);
    if (*s==0) {
        if ((flags!=2) | (len!=0) | (nw(p+34)==0)) {return 0;}
        while (i<6) {*(s+(4+i))=*(p+(6+i));i=i+1;}
        putw(s+10,nw(p+34));putd(s+12,dw(p+26));putd(s+16,seq+1);
        putd(s+20,0x414e4b42);*s=1;return 1;
    }
    if ((*s!=1) & (*s!=2)) {return 0;}
    while (i<6) {if (*(s+(4+i))!=*(p+(6+i))) {return 0;}i=i+1;}
    if ((nw(s+10)!=nw(p+34)) | (dw(s+12)!=dw(p+26))) {return 0;}
    if ((seq!=dw(s+16)) | (ack!=dw(s+20))) {return 0;}
    if (*s==1) {
        if ((flags!=16) | (len!=0)) {return 0;}
        *s=2;return 2;
    }
    if ((flags==17) & (len==0) & (*(s+1)==0)) {
        *(s+1)=1;putd(s+16,seq+1);if (*(s+2)!=0) {*s=3;} return 4;
    }
    if ((flags==16) & (len==0)) {
        if ((*(s+1)!=0) & (*(s+2)!=0)) {*s=3;}
        return 5;
    }
    if ((*(s+1)!=0) | (*(s+2)!=0) | ((flags!=16) & (flags!=24))) {return 0;}
    if ((len==0) | (1024<len) | (nw(x+1)<len)) {return 0;}
    putd(s+16,seq+len);return 3;
}
int emitrec(char *x,int action,int n) {
    char *s=x+3;char *p=x+35;char *q=x+1549;
    char h[6];int wire=0;int data=0;int payload=0;int i=0;int flags=16;int seq=dw(s+20);
    if (action==3) {data=nw(p+16)-40;}
    if ((action!=2) & (action!=5)) {
        if (action==1) {flags=18;seq=seq-1;}
        if (action==6) {payload=n;flags=25;*(s+2)=1;putd(s+20,seq+n+1);}
        while (i<60) {*(q+i)=0;i=i+1;}i=0;
        while (i<6) {*(q+i)=*(s+(4+i));i=i+1;}
        putw(q+6,512);putw(q+8,0);putw(q+10,2);putw(q+12,2048);
        *(q+14)=69;putw(q+16,40+payload);putw(q+20,16384);*(q+22)=64;*(q+23)=6;
        putd(q+26,167772162);putd(q+30,dw(s+12));
        putw(q+34,49153);putw(q+36,nw(s+10));putd(q+38,seq);putd(q+42,dw(s+16));
        *(q+46)=80;*(q+47)=flags;putw(q+48,4096);
        i=0;while(i<payload) {*(q+(54+i))=*(p+i);i=i+1;}
        putw(q+50,tcpcheck(q,20+payload));putw(q+24,foldsum(q+14,20,0));
        wire=54+payload;if(wire<60){wire=60;}
    }
    *h=action;*(h+1)=0;putw(h+2,wire);putw(h+4,data);
    if (write_bytes(h,6)!=6) {return 71;}
    if (write_bytes(s,32)!=32) {return 71;}
    if (0<data) {if (write_bytes(p+54,data)!=data) {return 71;}}
    if (0<wire) {if (write_bytes(q,wire)!=wire) {return 71;}}
    return 1;
}
