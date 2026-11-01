int main(int **cx,int *reply);
int *qptr(int **cx,int a);
int qdir(int **cx,int slot);
int q0(int **cx,int c);
int q1(int **cx);
int q2(int **cx);
int q3(int **cx,int bo);
int q4(int **cx);
int q7(int **cx,int g,int m);
int q8(int **cx);
int q9(int n);
int q10(int **cx,int g);
int q11(int **cx);
int q12(int **cx);
int q13(int **cx);
int q14(int **cx);
int q15(int **cx,int az,int bk);
int q16(int i,int x);
int q20(int **cx,int g,int m);
int q21(int **cx,int g,int d);
int q22(int **cx,int g,int m);
int q23(int **cx,int g,int m);
int q24(int **cx,int d);
int q25(int **cx,int d);
int q26(int **cx);
int q27(int **cx,int g,int d);
int q28(int **cx,int g,int m);
int q29(int **cx,int g,int i);
int q30(int **cx,int g,int m);
int q31(int **cx,int g,int m);
int q32(int u,int bg,int ag,int bw);
int q33(int u,int bg,int o,int am);
int q35(int **cx,int ao);
int q36(int **cx,int c,int y);
int q37(int **cx,int i);
int q60(int **cx,int d,int e);
int q61(int **cx,int reg,int d);
int q62(int **cx,int reg,int d);
int q38(int **cx,int g,int m);
int q39(int **cx,int a);
int q40(int **cx,int g,int y);
int q41(int **cx,int c,int fi);
int q42(int **cx,int bh,int ae);
int q43(int **cx,int g,int d);
int q44(int **cx,int g,int m);
int q45(int **cx,int vi);
int q46(int **cx,int s,int d);
int q47(int **cx,int bu);
int q48(int **cx);
int q49(int **cx,int bv);
int q50(int **cx);
int q67(int **cx);
int q52(int **cx,int fi,int k);
int q53(int **cx,int w,int ns);
int q54(int **cx);
int q55(int **cx,int i);
int q56(int **cx,int fi);
int q57(int d);
int q58(int **cx,int fi);
int q59(int **cx);
int q63(int **cx);
int q66(int **cx);
int q64(int **cx,int d,int mode);
int q65(int **cx,int sc);
int main(int **cx,int *reply){
int *h=0;
int *w=0;
int n=0;
int capacity=0;
int error=0;
int status=0;
int cursor=0;
int i=0;
int ignored=0;
int extent=0;
int count=0;
int stride=0;
int request=0;
h=*(cx+34);
w=*(cx+18);
if((*h!=1094930994)|(*(h+1)!=2)|(*(h+2)!=128)|(*(h+11)!=5)|(*(h+12)!=128)|(*(h+14)!=128)|(*(h+15)<0)|(1<*(h+15))){
ignored=syscall(0,1,0,0);return 1;}
if((*(h+16)!=1)|(*(h+17)!=1)|(*(h+32)!=2)|(*(h+33)!=3)|(*(h+48)!=3)|(*(h+49)!=3)|(*(h+64)!=15)|(*(h+65)!=1)|(*(h+80)!=16)|(*(h+81)!=3)){
ignored=syscall(0,1,0,0);return 1;}
request=768;
if(*(h+15)==1){request=1024;}
if((*(h+13)!=request)|(*(h+70)!=request)){
ignored=syscall(0,1,0,0);return 1;}
if(*(h+15)==0){
if(*(h+38)!=24576){ignored=syscall(0,1,0,0);return 1;}}
else{
if((*(h+38)<24576)|(1048576<*(h+38))|((*(h+38)&4095)!=0)){
ignored=syscall(0,1,0,0);return 1;}
i=0;extent=24576;
while(i<8){
stride=80;
if(i==1){stride=16;}
if(i==2){stride=40;}
if(i==3){stride=24;}
if(i==4){stride=48;}
if(i==5){stride=40;}
if(i==6){stride=24;}
if(i==7){stride=64;}
count=*(h+97+i*4);
if((count<=0)|(4096<count)|(*(h+96+i*4)!=extent)|(*(h+98+i*4)!=stride)|(*(h+99+i*4)!=0)){
ignored=syscall(0,1,0,0);return 1;}
if((i==7)&(count!=*(h+97))){ignored=syscall(0,1,0,0);return 1;}
extent=extent+count*stride;
if(*(h+38)<extent){ignored=syscall(0,1,0,0);return 1;}
i=i+1;}
if(((extent+4095)&(0-4096))!=*(h+38)){ignored=syscall(0,1,0,0);return 1;}}
n=*(h+23);capacity=*(h+54);
if((n<0)|((*(h+15)==0)&(65528<n))|(1048568<n)|(*(h+22)<n)|(*(h+22)<8)|((*(h+22)&7)!=0)|(capacity<4096)|((capacity&4095)!=0)|(*(h+86)!=128)){
ignored=syscall(0,1,0,0);return 1;}
*w=0;*(w+1)=n;*(w+9)=112;*(w+26)=(0-1);
*(w+2413)=capacity;*(w+2415)=capacity;*(w+2416)=2;
q14(cx);
while((*(w+4)!=0)&(*(w+3)==0)){q54(cx);}
if(*(w+3)==0){q59(cx);}
error=*(w+3);cursor=*w;
if(n<cursor){cursor=n;}
i=0;
while(i<16){*(reply+i)=0;i=i+1;}
*reply=1094930994;*(reply+1)=2;
*(reply+2)=*(h+3);*(reply+3)=*(h+4);
*(reply+8)=cursor;
i=0;
while(i<5){*(reply+10+i)=*(h+6+i);i=i+1;}
if(error==0){*(reply+7)=*(w+9);*(reply+8)=n;}
else{
if(error==17){*(reply+4)=1;*(reply+5)=3;*(reply+6)=*(w+3024);}
else{
if(error==20){*(reply+4)=1;*(reply+5)=*(w+3025);*(reply+6)=*(w+3026);}
else{
status=2;
if((error==8)|(error==12)|(error==13)|(error==16)|(error==19)){status=3;}
*(reply+4)=status;*(reply+9)=error;
}
}
}
ignored=syscall(0,0,0,0);
return 0;}
int qdir(int **cx,int slot){
int *h=0;
int value=0;
h=*(cx+34);
if(slot==32){return 49152+*(h+38);}
if(*(h+15)==1){
value=*(h+96+slot);
if((slot&3)==0){value=value+49152;}
return value;}
if(slot==0){return 61936;}
if(slot==1){return 64;}
if(slot==4){return 52584;}
if(slot==5){return 128;}
if(slot==8){return 60520;}
if(slot==9){return 32;}
if(slot==12){return 54632;}
if(slot==13){return 32;}
if(slot==16){return 55400;}
if(slot==17){return 16;}
if(slot==20){return 56168;}
if(slot==21){return 64;}
if(slot==24){return 58984;}
if(slot==25){return 64;}
if(slot==28){return 68528;}
if(slot==29){return 64;}
return 0;}
int *qptr(int **cx,int a){
int *p=0;
int *w=0;
int *h=0;
int offset=0;
int out=0;
h=*(cx+34);
w=*(cx+18);
out=49152+*(h+38);
if((a<49152)|((a&7)!=0)){return 0;}
if(a<out){return w+((a-49152)>>3);}
p=*(cx+26);
offset=a-out;
if(*(h+54)-8<offset){
if(*(w+3)==0){q3(cx,19);}
return p;}
return p+(offset>>3);}

int q0(int **cx,int c){
int *s=0;
int *w=0;
int length=0;
int value=0;
s=*(cx+10);
w=*(cx+18);
length=*(w+1);
if((c<0)|(length<=c)){return 0;}
value=*(s+(c>>3));
return (value>>((c&7)*8))&255;}
int q1(int **cx){
int c=0;
c=*qptr(cx,49152);
if((*qptr(cx,49160)<=c)){
return 0;
}
return q0(cx,c);
}
int q2(int **cx){
*qptr(cx,49152)=(*qptr(cx,49152)+1);
return 0;
}
int q3(int **cx,int bo){
int *w=0;
int *h=0;
int table=0;
int count=0;
int f=0;
int t=0;
int c=0;
int back=0;
int extra=8;
int need=0;
int maximum=9223372036854775807;
w=*(cx+18);
if(*(w+3)!=0){return 0;}
if((20<=bo)&(bo<=26)){
h=*(cx+34);table=bo-20;
count=qdir(cx,table*4+1);
bo=8;
if((*(h+15)==1)&(count<4096)){
*(w+3025)=32+table;*(w+3026)=count+1;bo=20;}
}
if((bo==17)|(bo==18)){
f=*(w+9);t=*(w+2413);c=*(w+2415);
if(bo==18){extra=56;}
bo=19;
if((0<=f)&(f<=t)&(t<=c)&(c<=maximum)){
back=c-t;
if(back<=maximum-f){
need=f+back;
if(extra<=maximum-need){
need=need+extra;
if(c<need){*(w+3024)=need;bo=17;}
}
}
}
}
*(w+3)=bo;
return 0;}
int q4(int **cx){
int *s=0;
int *w=0;
int c=0;
int length=0;
int value=0;
int n=0;
s=*(cx+10);
w=*(cx+18);
c=*w;
length=*(w+1);
if(c<0){return 0;}
while((c<length)&(*(w+3)==0)){
value=*(s+(c>>3));
if(((c&7)==0)&(8<=length-c)&(value==2314885530818453536)){
c=c+8;
}
else{
n=(value>>((c&7)*8))&255;
if((n==0)|(32<n)){return 0;}
c=c+1;
}
*w=c;
}
return 0;
}

int q7(int **cx,int g,int m){
int h=0;
int c=0;
int j=0;
h=0;
c=0;
j=3;
while(((c<m)&(*qptr(cx,49176)==0))){
h=((h<<5)|(q0(cx,(g+c))-96));
c=(c+1);
}
if(((m==3)&(h==9684))){
j=1;
}
if(((m==6)&(h==(22094|(18612<<15))))){
j=2;
}
if(((m==6)&(h==(21620|(20114<<15))))){
j=15;
}
if(((m==7)&(h==((4262|(26117<<15))|(20<<30))))){
j=16;
}
if(((m==4)&(h==(15021|(5<<15))))){
j=17;
}
if(((m==4)&(h==(15652|(22<<15))))){
j=18;
}
if(((m==4)&(h==(8242|(3<<15))))){
j=19;
}
if(((m==6)&(h==(5606|(19770<<15))))){
j=23;
}
if(((m==2)&(h==294))){
j=24;
}
if(((m==4)&(h==(12901|(5<<15))))){
j=25;
}
if(((m==5)&(h==(9605|(744<<15))))){
j=26;
}
if(((m==7)&(h==((1420|(26211<<15))|(19<<30))))){
j=34;
}
if((m==11)){
if((((((((((((q0(cx,(g+0))==119)&(q0(cx,(g+1))==114))&(q0(cx,(g+2))==105))&(q0(cx,(g+3))==116))&(q0(cx,(g+4))==101))&(q0(cx,(g+5))==95))&(q0(cx,(g+6))==98))&(q0(cx,(g+7))==121))&(q0(cx,(g+8))==116))&(q0(cx,(g+9))==101))&(q0(cx,(g+10))==115))){
j=35;
}
}
if((m==10)){
if(((((((((((q0(cx,(g+0))==114)&(q0(cx,(g+1))==101))&(q0(cx,(g+2))==97))&(q0(cx,(g+3))==100))&(q0(cx,(g+4))==95))&(q0(cx,(g+5))==98))&(q0(cx,(g+6))==121))&(q0(cx,(g+7))==116))&(q0(cx,(g+8))==101))&(q0(cx,(g+9))==115))){
j=36;
}
}
if((m==6)){
if(((((((q0(cx,g)==109)&(q0(cx,(g+1))==97))&(q0(cx,(g+2))==108))&(q0(cx,(g+3))==108))&(q0(cx,(g+4))==111))&(q0(cx,(g+5))==99))){
j=37;
}
}
if((m==4)){
if(((((q0(cx,g)==102)&(q0(cx,(g+1))==114))&(q0(cx,(g+2))==101))&(q0(cx,(g+3))==101))){
j=38;
}
}
return j;
}
int q8(int **cx){
int g=0;
int m=0;
int n=0;
g=*qptr(cx,49152);
m=0;
n=q1(cx);
while(((((((65<=n)&(n<=90))|((97<=n)&(n<=122))|(n==95))|((48<=n)&(n<=57)))==1)&(*qptr(cx,49176)==0))){
m=(m+1);
if((63<m)){
q3(cx,2);
return 0;
}
q2(cx);
n=q1(cx);
}
*qptr(cx,49200)=g;
*qptr(cx,49208)=m;
*qptr(cx,49184)=q7(cx,g,m);
return 0;
}
int q9(int n){
int i=0;
i=(0-1);
if(((48<=n)&(n<=57))){
i=(n-48);
}
if(((65<=n)&(n<=70))){
i=(n-55);
}
if(((97<=n)&(n<=102))){
i=(n-87);
}
return i;
}
int q10(int **cx,int g){
int ad=0;
int i=0;
int c=0;
int ab=0;
ad=0;
while(((ad<4)&(*qptr(cx,49176)==0))){
i=0;
c=0;
while(((c<5)&(*qptr(cx,49176)==0))){
i=((i*10)+(q0(cx,((g+(ad*5))+c))-48));
c=(c+1);
}
ab=0;
if((ad==0)){
ab=18446;
}
if((ad==1)){
ab=74407;
}
if((ad==2)){
ab=37095;
}
if((ad==3)){
ab=51615;
}
if((i<ab)){
return 1;
}
if((ab<i)){
return 0;
}
ad=(ad+1);
}
return 1;
}
int q11(int **cx){
int i=0;
int l=0;
int ah=0;
int aq=0;
int n=0;
int r=0;
i=0;
l=0;
ah=0;
aq=0;
n=q1(cx);
r=0;
while((((48<=n)&(n<=57))&(*qptr(cx,49176)==0))){
r=(n-48);
if((aq==0)){
if((r!=0)){
aq=1;
ah=*qptr(cx,49152);
l=1;
}
}
else {
l=(l+1);
}
i=((i*10)+r);
q2(cx);
n=q1(cx);
}
if((20<l)){
q3(cx,3);
return 0;
}
if((l==20)){
if((q10(cx,ah)==0)){
q3(cx,3);
return 0;
}
}
*qptr(cx,49192)=i;
*qptr(cx,49184)=4;
return 0;
}
int q12(int **cx){
int i=0;
int l=0;
int aq=0;
int bq=0;
int r=0;
int n=0;
i=0;
l=0;
aq=0;
bq=0;
r=0;
n=0;
q2(cx);
q2(cx);
n=q1(cx);
r=q9(n);
while(((0<=r)&(*qptr(cx,49176)==0))){
bq=1;
if((aq==0)){
if((r!=0)){
aq=1;
l=1;
}
}
else {
l=(l+1);
}
i=((i<<4)|r);
q2(cx);
n=q1(cx);
r=q9(n);
}
if((bq==0)){
q3(cx,3);
return 0;
}
if((16<l)){
q3(cx,3);
return 0;
}
*qptr(cx,49192)=i;
*qptr(cx,49184)=4;
return 0;
}
int q13(int **cx){
int c=0;
int n=0;
c=*qptr(cx,49152);
if((q0(cx,c)==48)){
if(((c+1)<*qptr(cx,49160))){
n=q0(cx,(c+1));
if(((n==120)|(n==88))){
return q12(cx);
}
}
}
return q11(cx);
}
int q14(int **cx){
int n=0;
int j=0;
q4(cx);
if((*qptr(cx,49176)!=0)){
*qptr(cx,49184)=0;
return 0;
}
if((*qptr(cx,49160)<=*qptr(cx,49152))){
*qptr(cx,49184)=0;
return 0;
}
n=q1(cx);
if(((((65<=n)&(n<=90))|((97<=n)&(n<=122))|(n==95))==1)){
return q8(cx);
}
if(((48<=n)&(n<=57))){
return q13(cx);
}
j=0;
if((n==40)){
j=5;
}
if((n==41)){
j=6;
}
if((n==123)){
j=7;
}
if((n==125)){
j=8;
}
if((n==59)){
j=9;
}
if((n==44)){
j=10;
}
if((n==42)){
j=11;
}
if((n==38)){
j=12;
}
if((n==91)){
j=13;
}
if((n==93)){
j=14;
}
if((n==43)){
j=21;
}
if((n==46)){j=40;}
if((n==45)){
q2(cx);
if(q1(cx)==62){q2(cx);*qptr(cx,49184)=39;return 0;}
*qptr(cx,49184)=22;return 0;
}
if((n==124)){
j=33;
}
if((n==61)){
q2(cx);
if((q1(cx)==61)){
q2(cx);
j=29;
}
else {
j=20;
}
*qptr(cx,49184)=j;
return 0;
}
if((n==60)){
q2(cx);
n=q1(cx);
if((n==61)){
q2(cx);
j=28;
}
else {
if((n==60)){
q2(cx);
j=31;
}
else {
j=27;
}
}
*qptr(cx,49184)=j;
return 0;
}
if((n==62)){
q2(cx);
if((q1(cx)==62)){
q2(cx);
*qptr(cx,49184)=32;
return 0;
}
q3(cx,1);
*qptr(cx,49184)=0;
return 0;
}
if((n==33)){
q2(cx);
if((q1(cx)==61)){
q2(cx);
*qptr(cx,49184)=30;
return 0;
}
q3(cx,1);
*qptr(cx,49184)=0;
return 0;
}
if((j!=0)){
*qptr(cx,49184)=j;
q2(cx);
return 0;
}
q3(cx,1);
*qptr(cx,49184)=0;
return 0;
}
int q15(int **cx,int az,int bk){
int bl=0;
int br=0;
int c=0;
bl=az&255;az=az>>8;br=bk&255;bk=bk>>8;
if((bl!=br)){
return 0;
}
c=0;
while(((c<bl)&(*qptr(cx,49176)==0))){
if((q0(cx,(az+c))!=q0(cx,(bk+c)))){
return 0;
}
c=(c+1);
}
return 1;
}
int q16(int i,int x){
return (((i+x)-1)&(0-x));
}
int q20(int **cx,int g,int m){
int e=0;
int c=0;
int a=0;
e=0;
c=0;
a=0;
e=*qptr(cx,49264);
c=0;
a=0;
while(((c<e)&(*qptr(cx,49176)==0))){
a=(qdir(cx,12)+(c*24));
if((q15(cx,((g<<8)|m),((*qptr(cx,a)<<8)|*qptr(cx,(a+8))))==1)){
return *qptr(cx,(a+16));
}
c=(c+1);
}
return 0;
}
int q21(int **cx,int g,int d){
int m=0;
int e=0;
int a=0;
m=g&255;g=g>>8;
e=0;
a=0;
if((q20(cx,g,m)!=0)){
q3(cx,10);
return 0;
}
e=*qptr(cx,49264);
if((qdir(cx,13)<=e)){
q3(cx,23);
return 0;
}
a=(qdir(cx,12)+(e*24));
*qptr(cx,a)=g;
*qptr(cx,(a+8))=m;
*qptr(cx,(a+16))=d;
*qptr(cx,49264)=(e+1);
return 0;
}
int q22(int **cx,int g,int m){
int e=0;
int c=0;
int a=0;
e=0;
c=0;
a=0;
e=*qptr(cx,49272);
c=0;
a=0;
while(((c<e)&(*qptr(cx,49176)==0))){
a=(qdir(cx,16)+(c*48));
if((q15(cx,((g<<8)|m),((*qptr(cx,a)<<8)|*qptr(cx,(a+8))))==1)){
return c;
}
c=(c+1);
}
return (0-1);
}
int q23(int **cx,int g,int m){
int bs=0;
int e=0;
int a=0;
bs=0;
e=0;
a=0;
bs=q22(cx,g,m);
if((0<=bs)){
return bs;
}
e=*qptr(cx,49272);
if((qdir(cx,17)<=e)){
q3(cx,24);
return (0-1);
}
a=(qdir(cx,16)+(e*48));
*qptr(cx,a)=g;
*qptr(cx,(a+8))=m;
*qptr(cx,(a+16))=*qptr(cx,49280);
*qptr(cx,(a+24))=0;
*qptr(cx,(a+32))=0;
*qptr(cx,(a+40))=1;
*qptr(cx,49272)=(e+1);
return e;
}
int q24(int **cx,int d){
int ar=0;
int a=0;
ar=0;
a=0;
ar=0;
if((d==1)){
ar=8;
}
if((d==2)){
ar=1;
}
if((65536<=d)){
ar=8;
{
ar=16;
}
}
if(((100<=d)&(d<4196))){
if((d-100)==*qptr(cx,49360)){return 0;}
a=(qdir(cx,16)+((d-100)*48));
ar=*qptr(cx,(a+32));
}
return ar;
}
int q25(int **cx,int d){
int x=0;
int a=0;
x=0;
a=0;
x=1;
if((d==1)){
x=8;
}
if((65536<=d)){
x=8;
{
x=16;
}
}
if(((100<=d)&(d<4196))){
a=(qdir(cx,16)+((d-100)*48));
x=*qptr(cx,(a+40))&65535;
}
return x;
}
int q26(int **cx){
int d=0;
int j=0;
int i=0;
int et=0;
d=0;
j=0;
i=0;
et=0;
d=0;
j=*qptr(cx,49184);
if((j==1)){
d=1;
q14(cx);
}
if((j==19)){
d=2;
q14(cx);
}
if((j==18)){
d=3;
q14(cx);
}
if((j==15)){
q14(cx);
if((*qptr(cx,49184)!=3)){
q3(cx,10);
return 0;
}
i=q22(cx,*qptr(cx,49200),*qptr(cx,49208));
if((i<0)&(0<=*qptr(cx,49360))){i=q23(cx,*qptr(cx,49200),*qptr(cx,49208));}
if((i<0)){
q3(cx,10);
return 0;
}
d=(100+i);
q14(cx);
}
if((j==17)){
q14(cx);
if((*qptr(cx,49184)!=3)){
q3(cx,10);
return 0;
}
et=q20(cx,*qptr(cx,49200),*qptr(cx,49208));
if((et!=(0-1))){
q3(cx,10);
return 0;
}
d=1;
q14(cx);
}
if(((j==3)&(d==0))){
d=q20(cx,*qptr(cx,49200),*qptr(cx,49208));
if((d<=0)){
q3(cx,10);
return 0;
}
q14(cx);
}
if((d==0)){
q3(cx,10);
return 0;
}
while(((*qptr(cx,49184)==11)&(*qptr(cx,49176)==0))){
if(4294901760<=d){q3(cx,16);return 0;}
d=(65536+d);
q14(cx);
}
return d;
}
int q27(int **cx,int g,int d){
int m=0;
int e=0;
int i=0;
int sb=0;
int f=0;
int az=0;
int c=0;
int a=0;
int ba=0;
int al=0;
int sz=0;
int s=0;
m=g&255;g=g>>8;e=d>>32;d=d&4294967295;
i=0;
sb=0;
f=0;
az=0;
c=0;
a=0;
ba=0;
al=0;
sz=0;
s=0;
i=*qptr(cx,49360);
sb=(qdir(cx,16)+(i*48));
f=*qptr(cx,(sb+24));
az=*qptr(cx,(sb+16));
c=0;
a=0;
while(((c<f)&(*qptr(cx,49176)==0))){
a=(qdir(cx,20)+((az+c)*40));
if((q15(cx,((g<<8)|m),((*qptr(cx,a)<<8)|*qptr(cx,(a+8))))==1)){
q3(cx,10);
return 0;
}
c=(c+1);
}
ba=*qptr(cx,49280);
if((qdir(cx,21)<=ba)){
q3(cx,25);
return 0;
}
al=q25(cx,d);
sz=q24(cx,d);
if((((sz==0)|(e<=0))|(1024<e))){
q3(cx,13);
return 0;
}
s=q16(*qptr(cx,(sb+32)),al);
if((8192<(s+(sz*e)))){
q3(cx,13);
return 0;
}
a=(qdir(cx,20)+(ba*40));
*qptr(cx,a)=g;
*qptr(cx,(a+8))=m;
*qptr(cx,(a+16))=d;
*qptr(cx,(a+24))=s;
*qptr(cx,(a+32))=e;
*qptr(cx,49280)=(ba+1);
*qptr(cx,(sb+24))=(f+1);
*qptr(cx,(sb+32))=(s+(sz*e));
if((*qptr(cx,(sb+40))<al)){
*qptr(cx,(sb+40))=al;
}
return 0;
}
int q28(int **cx,int g,int m){
int i=0;
int sb=0;
int d=0;
int ns=0;
int nl=0;
int e=0;
i=0;
sb=0;
d=0;
ns=0;
nl=0;
e=0;
i=q23(cx,g,m);
if((i<0)){
return 0;
}
sb=(qdir(cx,16)+(i*48));
if((*qptr(cx,49184)==9)){q14(cx);return 0;}
if((0<*qptr(cx,(sb+24)))){
q3(cx,10);
return 0;
}
if((*qptr(cx,49184)!=7)){
q3(cx,10);
return 0;
}
*qptr(cx,49360)=i;
*qptr(cx,(sb+16))=*qptr(cx,49280);
q14(cx);
while((((*qptr(cx,49184)!=8)&(*qptr(cx,49176)==0))&(*qptr(cx,49176)==0))){
d=q26(cx);
if((*qptr(cx,49184)!=3)){
q3(cx,10);
return 0;
}
ns=*qptr(cx,49200);
nl=*qptr(cx,49208);
q14(cx);
e=1;
if((*qptr(cx,49184)==13)){
q14(cx);
if((*qptr(cx,49184)!=4)){
q3(cx,10);
return 0;
}
e=*qptr(cx,49192);
q14(cx);
if((*qptr(cx,49184)!=14)){
q3(cx,10);
return 0;
}
q14(cx);
}
if((*qptr(cx,49184)!=9)){
q3(cx,10);
return 0;
}
q14(cx);
q27(cx,((ns<<8)|nl),(d|(e<<32)));
}
if((*qptr(cx,49184)!=8)){
q3(cx,10);
return 0;
}
q14(cx);
if((*qptr(cx,49184)!=9)){
q3(cx,10);
return 0;
}
q14(cx);
if(*qptr(cx,(sb+24))==0){q3(cx,13);return 0;}
*qptr(cx,(sb+32))=q16(*qptr(cx,(sb+32)),*qptr(cx,(sb+40)));
e=1;ns=0;
while(ns<*qptr(cx,(sb+24))){
d=*qptr(cx,(qdir(cx,20)+((*qptr(cx,(sb+16))+ns)*40)+16));
if((100<=d)&(d<4196)){
nl=(*qptr(cx,(qdir(cx,16)+(d-100)*48+40))>>16)+1;
if(e<nl){e=nl;}}
ns=ns+1;}
*qptr(cx,(sb+40))=*qptr(cx,(sb+40))|(e<<16);
*qptr(cx,49360)=(0-1);
return 0;
}
int q29(int **cx,int g,int i){
int m=0;
int e=0;
int c=0;
int a=0;
m=g&255;g=g>>8;
e=0;
c=0;
a=0;
e=*qptr(cx,49312);
c=0;
a=0;
while(((c<e)&(*qptr(cx,49176)==0))){
a=(qdir(cx,24)+(c*24));
if((q15(cx,((g<<8)|m),((*qptr(cx,a)<<8)|*qptr(cx,(a+8))))==1)){
q3(cx,10);
return 0;
}
c=(c+1);
}
if((qdir(cx,25)<=e)){
q3(cx,26);
return 0;
}
a=(qdir(cx,24)+(e*24));
*qptr(cx,a)=g;
*qptr(cx,(a+8))=m;
*qptr(cx,(a+16))=i;
*qptr(cx,49312)=(e+1);
return 0;
}
int q30(int **cx,int g,int m){
int e=0;
int c=0;
int a=0;
e=0;
c=0;
a=0;
e=*qptr(cx,49312);
c=0;
a=0;
while(((c<e)&(*qptr(cx,49176)==0))){
a=(qdir(cx,24)+(c*24));
if((q15(cx,((g<<8)|m),((*qptr(cx,a)<<8)|*qptr(cx,(a+8))))==1)){
return *qptr(cx,(a+16));
}
c=(c+1);
}
return (0-1);
}
int q31(int **cx,int g,int m){
int i=0;
int ns=0;
int nl=0;
i=0;
ns=0;
nl=0;
q21(cx,((g<<8)|m),(0-1));
if((*qptr(cx,49184)!=7)){
q3(cx,10);
return 0;
}
q14(cx);
i=0;
while((((*qptr(cx,49184)!=8)&(*qptr(cx,49176)==0))&(*qptr(cx,49176)==0))){
if((*qptr(cx,49184)!=3)){
q3(cx,10);
return 0;
}
ns=*qptr(cx,49200);
nl=*qptr(cx,49208);
q14(cx);
if((*qptr(cx,49184)==20)){
q14(cx);
if((*qptr(cx,49184)!=4)){
q3(cx,10);
return 0;
}
i=*qptr(cx,49192);
q14(cx);
}
q29(cx,((ns<<8)|nl),i);
i=(i+1);
if((*qptr(cx,49184)==10)){
q14(cx);
}
}
if((*qptr(cx,49184)!=8)){
q3(cx,10);
return 0;
}
q14(cx);
if((*qptr(cx,49184)!=9)){
q3(cx,10);
return 0;
}
q14(cx);
return 0;
}
int q32(int u,int bg,int ag,int bw){
return ((((u<<26)|(bg<<22))|(ag<<18))|((bw<<46)>>46));
}
int q33(int u,int bg,int o,int am){
return ((((u<<26)|(bg<<22))|(o<<18))|(am<<14));
}
int q35(int **cx,int ao){
int c=0;
int an=0;
if(*qptr(cx,49176)!=0){return 0;}
c=*qptr(cx,49224);
if(((*qptr(cx,68456)-c)<8)){
q3(cx,17);
return 0;
}
an=(ao|((63<<26)<<32));
*qptr(cx,((qdir(cx,32)+0)+c))=an;
*qptr(cx,49224)=(c+8);
return 0;
}
int q36(int **cx,int c,int y){
int v=0;
int ao=0;
int an=0;
v=((y>>2)-(c>>2));
ao=((50<<26)|((v<<42)>>42));
an=(ao|((63<<26)<<32));
*qptr(cx,((qdir(cx,32)+0)+c))=an;
return 0;
}
int q37(int **cx,int i){
int c=0;
int ak=0;
int bb=0;
if(((((0-131071)-1)<=i)&(i<=131071))){
q35(cx,q32(22,4,0,i));
return 0;
}
c=0;
ak=0;
bb=0;
q35(cx,q32(22,4,0,0));
q35(cx,q32(22,5,0,4));
while(((c<16)&(*qptr(cx,49176)==0))){
q35(cx,q33(6,4,4,5));
ak=((15-c)*4);
bb=((i>>ak)&15);
q35(cx,q32(22,0,0,bb));
q35(cx,q33(4,4,4,0));
c=(c+1);
}
return 0;
}
int q60(int **cx,int d,int e){
int n=0;
int z=0;
int length=0;
int a=0;
int end=0;
int r=0;
int at=0;
if(*qptr(cx,49176)!=0){return 0;}
n=*qptr(cx,68512);
if((4096<=n)){
q3(cx,8);
return 0;
}
z=(q24(cx,d)*e);
length=z;
if(((z==0)|(((65536<=(d))==1)&(1<e)))){
q3(cx,9);
return 0;
}
a=q25(cx,d);
if((z<8)){
z=8;
}
end=q16((*qptr(cx,49296)+z),a);
if((8192<end)){
q3(cx,13);
return 0;
}
*qptr(cx,49296)=end;
if((*qptr(cx,68456)-*qptr(cx,49224))<56){q3(cx,18);return 0;}
r=*qptr(cx,68456)-48;
*qptr(cx,68456)=r;
at=((qdir(cx,32)+0)+r);
*qptr(cx,at)=n;
*qptr(cx,(at+8))=*qptr(cx,68504);
*qptr(cx,(at+16))=(0-end);
*qptr(cx,(at+24))=length;
*qptr(cx,(at+32))=a;
*qptr(cx,(at+40))=(1+((65536<=(d))*2));
*qptr(cx,68504)=at;
*qptr(cx,68512)=(n+1);
return n;
}
int q61(int **cx,int reg,int d){
int slot=0;
slot=reg>>8;reg=reg&255;
q35(cx,q32(45,8,0,slot));
if(((65536<=(d))==1)){
q35(cx,q32(41,reg,8,0));
}
else {
q35(cx,(q33(43,reg,8,0)+((d!=2)*3)));
}
return 0;
}
int q62(int **cx,int reg,int d){
int slot=0;
slot=reg>>8;reg=reg&255;
q35(cx,q32(45,8,0,slot));
if(((65536<=(d))==1)){
q35(cx,q32(40,reg,8,0));
}
else {
q35(cx,(q33(42,reg,8,0)+((d!=2)*3)));
}
return 0;
}
int q38(int **cx,int g,int m){
int e=0;
int c=0;
int a=0;
e=0;
c=0;
a=0;
e=*qptr(cx,49240);
c=0;
a=0;
while(((c<e)&(*qptr(cx,49176)==0))){
a=(qdir(cx,0)+(c*80));
if((q15(cx,((g<<8)|m),((*qptr(cx,a)<<8)|*qptr(cx,(a+8))))==1)){
return c;
}
c=(c+1);
}
return (0-1);
}
int q39(int **cx,int a){
int w=0;
int k=0;
int c=0;
w=*qptr(cx,49344);k=*qptr(cx,49352);
c=0;
if((*qptr(cx,(a+32))!=w)){
return 0;
}
if((*qptr(cx,(a+40))!=k)){
return 0;
}
c=0;
while(((c<k)&(*qptr(cx,49176)==0))){
if((*qptr(cx,((a+48)+(c*8)))!=*qptr(cx,(61800+(c*8))))){
return 0;
}
c=(c+1);
}
return 1;
}
int q40(int **cx,int g,int y){
int m=0;
int aw=0;
int w=0;
int k=0;
int fi=0;
int a=0;
int e=0;
int c=0;
m=g&255;g=g>>8;aw=y&1;y=y&(0-8);
w=0;
k=0;
fi=0;
a=0;
e=0;
c=0;
w=*qptr(cx,49344);
k=*qptr(cx,49352);
fi=q38(cx,g,m);
a=0;
if((0<=fi)){
a=(qdir(cx,0)+(fi*80));
if((q39(cx,a)==0)){
q3(cx,11);
return fi;
}
if((aw==1)){
if((*qptr(cx,(a+24))==1)){
q3(cx,5);
return fi;
}
*qptr(cx,(a+24))=1;
*qptr(cx,(a+16))=y;
}
return fi;
}
e=*qptr(cx,49240);
if((qdir(cx,1)<=e)){
q3(cx,20);
return 0;
}
a=(qdir(cx,0)+(e*80));
*qptr(cx,a)=g;
*qptr(cx,(a+8))=m;
*qptr(cx,(a+16))=y;
*qptr(cx,(a+24))=aw;
*qptr(cx,(a+32))=w;
*qptr(cx,(a+40))=k;
c=0;
while(((c<4)&(*qptr(cx,49176)==0))){
*qptr(cx,((a+48)+(c*8)))=*qptr(cx,(61800+(c*8)));
c=(c+1);
}
*qptr(cx,49240)=(e+1);
return e;
}
int q41(int **cx,int c,int fi){
int e=0;
int c6=0;
int a=0;
e=0;
c6=0;
a=0;
e=*qptr(cx,49248);
if((qdir(cx,5)<=e)){
q3(cx,21);
return 0;
}
c6=(qdir(cx,0)+(fi*80));
if((*qptr(cx,(c6+24))==0)){
*qptr(cx,(c6+24))=2;
}
a=(qdir(cx,4)+(e*16));
*qptr(cx,a)=c;
*qptr(cx,(a+8))=fi;
*qptr(cx,49248)=(e+1);
return 0;
}
int q42(int **cx,int bh,int ae){
if((bh==ae)){
return 1;
}
if(((bh==1)&(ae==2))){
return 1;
}
if(((bh==2)&(ae==1))){
return 1;
}
{
if(((((65536<=(bh))==1)&((65536<=(ae))==1))&((bh==65539)|(ae==65539)))){
return 1;
}
if(((((65536<=(bh))==1)&(ae==1))&(*qptr(cx,49368)==1))){
return 1;
}
}
return 0;
}
int q43(int **cx,int g,int d){
int m=0;
int e=0;
int vc=0;
int array=0;
int c=0;
int a=0;
int slot=0;
int sz=0;
int al=0;
int aj=0;
int bi=0;
m=g&255;g=g>>8;e=d>>32;d=d&4294967295;
vc=0;
array=0;
c=0;
a=0;
slot=0;
sz=0;
al=0;
aj=0;
bi=0;
array=0;
if((1&(4096<=e))){
array=1;
e=(e-4096);
}
vc=*qptr(cx,49288);
c=0;
a=0;
while(((c<vc)&(*qptr(cx,49176)==0))){
a=(qdir(cx,8)+(c*40));
if((q15(cx,((g<<8)|m),((*qptr(cx,a)<<8)|*qptr(cx,(a+8))))==1)){
q3(cx,10);
return 0;
}
c=(c+1);
}
if((qdir(cx,9)<=vc)){
q3(cx,22);
return 0;
}
if(((d==3)|(e<=0))){
q3(cx,9);
return 0;
}
if((1024<e)){
q3(cx,13);
return 0;
}
{
if(((100<=d)&(d<4196))){
q3(cx,9);
return 0;
}
slot=q60(cx,d,e);
a=(qdir(cx,8)+(vc*40));
*qptr(cx,a)=g;
*qptr(cx,(a+8))=m;
*qptr(cx,(a+16))=d;
*qptr(cx,(a+24))=slot;
*qptr(cx,(a+32))=(e+(array*4096));
*qptr(cx,49288)=(vc+1);
return slot;
}
sz=(q24(cx,d)*e);
al=q25(cx,d);
aj=q16(*qptr(cx,49296),al);
bi=sz;
if((bi<8)){
bi=8;
}
aj=(aj+bi);
if((8192<aj)){
q3(cx,13);
return 0;
}
*qptr(cx,49296)=aj;
a=(qdir(cx,8)+(vc*40));
*qptr(cx,a)=g;
*qptr(cx,(a+8))=m;
*qptr(cx,(a+16))=d;
*qptr(cx,(a+24))=(0-aj);
*qptr(cx,(a+32))=e;
*qptr(cx,49288)=(vc+1);
return (0-aj);
}
int q44(int **cx,int g,int m){
int vc=0;
int c=0;
int a=0;
vc=0;
c=0;
a=0;
vc=*qptr(cx,49288);
c=0;
a=0;
while(((c<vc)&(*qptr(cx,49176)==0))){
a=(qdir(cx,8)+(c*40));
if((q15(cx,((g<<8)|m),((*qptr(cx,a)<<8)|*qptr(cx,(a+8))))==1)){
return c;
}
c=(c+1);
}
return (0-1);
}
int q45(int **cx,int vi){
int a=0;
int d=0;
int e=0;
int s=0;
a=0;
d=0;
e=0;
s=0;
a=(qdir(cx,8)+(vi*40));
d=*qptr(cx,(a+16));
e=*qptr(cx,(a+32));
s=*qptr(cx,(a+24));
{
if((1<e)){
q35(cx,q32(45,4,0,s));
if(4294901760<=d){q3(cx,16);return 0;}
*qptr(cx,49320)=(65536+d);
return 0;
}
q62(cx,(4|(s<<8)),d);
*qptr(cx,49320)=d;
return 0;
}
if((1<e)){
q35(cx,q32(16,4,13,s));
if(4294901760<=d){q3(cx,16);return 0;}
*qptr(cx,49320)=(65536+d);
return 0;
}
if(((q24(cx,d)!=8)&(d!=2))){
q3(cx,9);
return 0;
}
q35(cx,q32((32+((d==2)*4)),4,13,s));
*qptr(cx,49320)=d;
return 0;
}
int q46(int **cx,int s,int d){
{
return q61(cx,(4|(s<<8)),d);
}
q35(cx,q32((33+((d==2)*4)),4,13,s));
return 0;
}
int q47(int **cx,int bu){
int o=0;
int s=0;
int sz=0;
int at=0;
int u=0;
int z=0;
int am=0;
int ax=0;
int nz=0;
int lz=0;
int handled=0;
int packed=0;
o=0;
s=0;
sz=0;
at=0;
u=0;
z=0;
am=0;
ax=0;
nz=0;
lz=0;
handled=0;
packed=0;
packed=q63(cx);
o=(packed&4294967295);
nz=(packed>>32);
while(((*qptr(cx,49176)==0)&(*qptr(cx,49176)==0))){
u=*qptr(cx,49184);
z=0;
if((u==33)){
z=1;
}
if((u==12)){
z=2;
}
if(((u==29)|(u==30))){
z=3;
}
if(((u==27)|(u==28))){
z=4;
}
if(((u==31)|(u==32))){
z=5;
}
if(((u==21)|(u==22))){
z=6;
}
if((u==11)){
z=7;
}
if((z<bu)){
*qptr(cx,49368)=nz;
*qptr(cx,49320)=o;
return o;
}
s=0;
{
s=q60(cx,o,1);
q61(cx,(4|(s<<8)),o);
}
q14(cx);
lz=nz;
nz=0;
handled=0;
am=q47(cx,(z+1));
{
q62(cx,(6|(s<<8)),o);
if((((u==29)|(u==30))&(((65536<=(o))==1)|((65536<=(am))==1)))){
if(((65536<=(o))==0)){
if(((o!=1)|(lz!=1))){
q3(cx,9);
return 0;
}
q35(cx,q32(22,7,0,0));
}
if(((65536<=(am))==0)){
if(((am!=1)|(*qptr(cx,49368)!=1))){
q3(cx,9);
return 0;
}
q35(cx,q32(22,5,0,0));
}
if(((((65536<=(o))==1)&((65536<=(am))==1))&(q42(cx,o,am)==0))){
q3(cx,9);
return 0;
}
q35(cx,q33(5,12,6,4));
q35(cx,q33(5,10,7,5));
q35(cx,q33(4,12,12,10));
q35(cx,q32(21,0,12,0));
q35(cx,q32(22,4,0,0));
q35(cx,(((48<<26)|((u==29)<<22))|4));
q35(cx,q32(22,4,0,1));
o=1;
handled=1;
}
else {
if(((65536<=(o))==1)){
if((((u!=21)&(u!=22))|((am!=1)&(am!=2)))){
q3(cx,9);
return 0;
}
sz=q24(cx,(o-65536));
if((sz==0)){
q3(cx,9);
return 0;
}
q35(cx,q33(10,12,4,0));
if((u==22)){
q37(cx,(1<<63));
q35(cx,q33(9,0,12,4));
q35(cx,(((48<<26)|(1<<22))|6));
q35(cx,q32(22,10,0,0));
q35(cx,q33(39,4,10,12));
q35(cx,q32(22,4,0,0));
q35(cx,q33(2,12,4,12));
}
q35(cx,q33(39,4,6,12));
at=1;
while(((at<sz)&(*qptr(cx,49176)==0))){
q35(cx,q33(39,4,4,12));
at=(at+1);
}
}
else {
if(((65536<=(am))==1)){
if(((u!=21)|((o!=1)&(o!=2)))){
q3(cx,9);
return 0;
}
sz=q24(cx,(am-65536));
if((sz==0)){
q3(cx,9);
return 0;
}
q35(cx,q33(10,12,6,0));
at=0;
while(((at<sz)&(*qptr(cx,49176)==0))){
q35(cx,q33(39,4,4,12));
at=(at+1);
}
o=am;
}
else {
if((((o!=1)&(o!=2))|((am!=1)&(am!=2)))){
q3(cx,9);
return 0;
}
q35(cx,q33(10,5,6,0));
}
}
}
}
if((((65536<=(o))==0)&(handled==0))){
if((u==11)){
q35(cx,q33(11,4,5,4));
}
if((u==21)){
q35(cx,q33(1,4,5,4));
}
if((u==22)){
q35(cx,q33(2,4,5,4));
}
if((u==31)){
q35(cx,q33(6,4,5,4));
}
if((u==32)){
q35(cx,q33(7,4,5,4));
}
if((u==12)){
q35(cx,q33(3,4,5,4));
}
if((u==33)){
q35(cx,q33(4,4,5,4));
}
if(((((u==27)|(u==28))|(u==29))|(u==30))){
q35(cx,q33(9,0,5,4));
q35(cx,q32(22,4,0,0));
ax=0;
if((u==27)){
ax=3;
}
if((u==28)){
ax=5;
}
if((u==29)){
ax=1;
}
if((u==30)){
ax=0;
}
q35(cx,(((48<<26)|(ax<<22))|4));
q35(cx,q32(22,4,0,1));
}
o=1;
}
}
*qptr(cx,49368)=nz;
*qptr(cx,49320)=o;
return o;
}
int q48(int **cx){
int k=0;
int d=0;
int ns=0;
int nl=0;
k=0;
d=0;
ns=0;
nl=0;
k=0;
if((*qptr(cx,49184)==6)){
return 0;
}
if((*qptr(cx,49184)==18)){
q4(cx);
if((q1(cx)==41)){
q14(cx);
return 0;
}
}
while((((*qptr(cx,49184)!=6)&(*qptr(cx,49176)==0))&(*qptr(cx,49176)==0))){
if((4<=k)){
q3(cx,12);
return k;
}
d=q26(cx);
if(((d==3)|((100<=d)&(d<4196)))){
q3(cx,12);
return k;
}
ns=0;
nl=0;
if((*qptr(cx,49184)==3)){
ns=*qptr(cx,49200);
nl=*qptr(cx,49208);
q14(cx);
}
if((*qptr(cx,49184)==13)){
q14(cx);
if((*qptr(cx,49184)!=14)){
q3(cx,12);
return k;
}
q14(cx);
if(4294901760<=d){q3(cx,16);return 0;}
d=(65536+d);
}
*qptr(cx,(61800+(k*8)))=d;
*qptr(cx,(61832+(k*8)))=ns;
*qptr(cx,(61864+(k*8)))=nl;
k=(k+1);
if((*qptr(cx,49184)==10)){
q14(cx);
}
else {
if((*qptr(cx,49184)!=6)){
q3(cx,12);
return k;
}
}
}
return k;
}
int q49(int **cx,int bv){
{
q35(cx,(46<<26));
q35(cx,(56<<26));
return 0;
}
q35(cx,q32(32,14,13,8));
q35(cx,q32(32,5,13,0));
q35(cx,q32(16,15,13,16));
q35(cx,q33(10,13,5,0));
q35(cx,(56<<26));
return 0;
}
int q50(int **cx){
int j=0;
int ay=0;
j=*qptr(cx,49184);
if((j==7)){
{
*qptr(cx,68520)=(*qptr(cx,68520)+1);
}
q14(cx);
while(((((*qptr(cx,49184)!=8)&(*qptr(cx,49184)!=0))&(*qptr(cx,49176)==0))&(*qptr(cx,49176)==0))){
ay=(ay|q50(cx));
}
if((*qptr(cx,49184)!=8)){
q3(cx,4);
return ay;
}
q14(cx);
{
*qptr(cx,68520)=(*qptr(cx,68520)-1);
}
return ay;
}
return q67(cx);
}
int q67(int **cx){
int j=0;
int ay=0;
int bj=0;
int d=0;
int ns=0;
int nl=0;
int e=0;
int s=0;
int ae=0;
int ct=0;
int bp=0;
int tr=0;
int jp=0;
int q=0;
int v=0;
int lp=0;
int xp=0;
int cp=0;
int bd=0;
int at=0;
int dt=0;
int fi=0;
int c6=0;
int k=0;
int ap=0;
int vi=0;
int vb=0;
int vt=0;
j=0;
ay=0;
bj=0;
d=0;
ns=0;
nl=0;
e=0;
s=0;
ae=0;
ct=0;
bp=0;
tr=0;
jp=0;
q=0;
v=0;
lp=0;
xp=0;
cp=0;
bd=0;
at=0;
dt=0;
fi=0;
c6=0;
k=0;
ap=0;
vi=0;
vb=0;
vt=0;
j=*qptr(cx,49184);
if(((j==37)|(j==38))){
q47(cx,1);
if((*qptr(cx,49184)!=9)){
q3(cx,10);
return 0;
}
q14(cx);
return 0;
}
ay=0;
bj=0;
d=0;
ns=0;
nl=0;
e=0;
s=0;
ae=0;
ct=0;
bp=0;
tr=0;
jp=0;
q=0;
v=0;
lp=0;
xp=0;
cp=0;
bd=0;
at=0;
dt=0;
fi=0;
c6=0;
k=0;
ap=0;
vi=0;
vb=0;
vt=0;

if((((((j==1)|(j==19))|(j==15))|(j==17))|(j==18))){
bj=1;
}
if((j==3)){
if((0<q20(cx,*qptr(cx,49200),*qptr(cx,49208)))){
bj=1;
}
}
if((bj==1)){
if((1&(0<*qptr(cx,68520)))){
q3(cx,9);
return 0;
}
d=q26(cx);
if((*qptr(cx,49184)!=3)){
q3(cx,10);
return 0;
}
ns=*qptr(cx,49200);
nl=*qptr(cx,49208);
q14(cx);
e=1;
if((*qptr(cx,49184)==13)){
q14(cx);
if((*qptr(cx,49184)!=4)){
q3(cx,10);
return 0;
}
e=*qptr(cx,49192);
q14(cx);
if((*qptr(cx,49184)!=14)){
q3(cx,10);
return 0;
}
q14(cx);
{
e=(e+4096);
}
}
s=q43(cx,((ns<<8)|nl),(d|(e<<32)));
if((*qptr(cx,49184)==20)){
if((1<e)){
q3(cx,9);
return 0;
}
q14(cx);
ae=q47(cx,1);
if((q42(cx,d,ae)==0)){
q3(cx,9);
return 0;
}
q46(cx,s,d);
}
if((*qptr(cx,49184)!=9)){
q3(cx,10);
return 0;
}
q14(cx);
return 0;
}
if((j==2)){
q14(cx);
if((*qptr(cx,49344)==3)){
if((*qptr(cx,49184)!=9)){
q3(cx,9);
return 0;
}
q14(cx);
q35(cx,q32(22,0,0,0));
}
else {
ae=q47(cx,1);
if((q42(cx,*qptr(cx,49344),ae)==0)){
q3(cx,9);
return 0;
}
if((*qptr(cx,49184)!=9)){
q3(cx,4);
return 0;
}
q14(cx);
if((1&((65536<=(*qptr(cx,49344)))==1))){
q35(cx,q33(38,0,4,0));
}
else {
q35(cx,q33(10,0,4,0));
}
}
q49(cx,0);
return 1;
}
if((j==24)){
q14(cx);
if((*qptr(cx,49184)!=5)){
q3(cx,4);
return 0;
}
q14(cx);
ct=q47(cx,1);
if((((ct!=1)&(ct!=2))&(((65536<=(ct))==0)|0))){
q3(cx,9);
return 0;
}
if((*qptr(cx,49184)!=6)){
q3(cx,4);
return 0;
}
q14(cx);
q35(cx,q32(21,0,4,0));
bp=*qptr(cx,49224);
q35(cx,(48<<26));
{
*qptr(cx,68520)=(*qptr(cx,68520)+1);
}
tr=q50(cx);
{
*qptr(cx,68520)=(*qptr(cx,68520)-1);
}
if((*qptr(cx,49184)==25)){
jp=*qptr(cx,49224);
q35(cx,((48<<26)|(15<<22)));
q=*qptr(cx,49224);
v=((q-bp)>>2);
*qptr(cx,((qdir(cx,32)+0)+bp))=(((48<<26)|((v<<42)>>42))|((63<<26)<<32));
q14(cx);
{
*qptr(cx,68520)=(*qptr(cx,68520)+1);
}
d=q50(cx);
{
*qptr(cx,68520)=(*qptr(cx,68520)-1);
}
q=*qptr(cx,49224);
v=((q-jp)>>2);
*qptr(cx,((qdir(cx,32)+0)+jp))=((((48<<26)|(15<<22))|((v<<42)>>42))|((63<<26)<<32));
return (tr&d);
}
q=*qptr(cx,49224);
v=((q-bp)>>2);
*qptr(cx,((qdir(cx,32)+0)+bp))=(((48<<26)|((v<<42)>>42))|((63<<26)<<32));
return 0;
}
if((j==26)){
q14(cx);
if((*qptr(cx,49184)!=5)){
q3(cx,4);
return 0;
}
q14(cx);
lp=*qptr(cx,49224);
ct=q47(cx,1);
if((((ct!=1)&(ct!=2))&(((65536<=(ct))==0)|0))){
q3(cx,9);
return 0;
}
if((*qptr(cx,49184)!=6)){
q3(cx,4);
return 0;
}
q14(cx);
q35(cx,q32(21,0,4,0));
xp=*qptr(cx,49224);
q35(cx,(48<<26));
{
*qptr(cx,68520)=(*qptr(cx,68520)+1);
}
q50(cx);
{
*qptr(cx,68520)=(*qptr(cx,68520)-1);
}
cp=*qptr(cx,49224);
bd=((lp-cp)>>2);
q35(cx,(((48<<26)|(15<<22))|((bd<<42)>>42)));
q=*qptr(cx,49224);
v=((q-xp)>>2);
*qptr(cx,((qdir(cx,32)+0)+xp))=(((48<<26)|((v<<42)>>42))|((63<<26)<<32));
return 0;
}
if((j==11)){
q14(cx);
at=q47(cx,1);
dt=0;
if(((65536<=(at))==1)){
dt=(at-65536);
}
else {
{
q3(cx,9);
return 0;
}
}
if((((dt!=1)&(dt!=2))&(((65536<=(dt))==0)|0))){
q3(cx,9);
return 0;
}
xp=0;
{
xp=q60(cx,at,1);
q61(cx,(4|(xp<<8)),at);
}
if((*qptr(cx,49184)!=20)){
q3(cx,10);
return 0;
}
q14(cx);
ae=q47(cx,1);
if((q42(cx,dt,ae)==0)){
q3(cx,9);
return 0;
}
{
q62(cx,(6|(xp<<8)),at);
if(((65536<=(dt))==1)){
q35(cx,q32(41,4,6,0));
}
else {
q35(cx,(q33(43,4,6,0)+((dt!=2)*3)));
}
}
if((*qptr(cx,49184)!=9)){
q3(cx,10);
return 0;
}
q14(cx);
return 0;
}
if((j==3)){
ns=*qptr(cx,49200);
nl=*qptr(cx,49208);
q14(cx);
if((*qptr(cx,49184)==5)){
*qptr(cx,49152)=ns;
q14(cx);
q47(cx,1);
if(*qptr(cx,49184)!=9){q3(cx,10);return 0;}
q14(cx);return 0;
}
if(*qptr(cx,49184)==39){
vi=q44(cx,ns,nl);
if(vi<0){q3(cx,9);return 0;}
q45(cx,vi);at=q64(cx,*qptr(cx,49320),1);
if((65536<=(at))==0){q3(cx,9);return 0;}
dt=at-65536;
if(*qptr(cx,49184)!=20){q3(cx,10);return 0;}
xp=q60(cx,at,1);q61(cx,(4|(xp<<8)),at);
q14(cx);ae=q47(cx,1);
if(q42(cx,dt,ae)==0){q3(cx,9);return 0;}
q62(cx,(6|(xp<<8)),at);
if((65536<=(dt))==1){q35(cx,q32(41,4,6,0));}
else{q35(cx,q33(43,4,6,0)+((dt!=2)*3));}
if(*qptr(cx,49184)!=9){q3(cx,10);return 0;}
q14(cx);return 0;
}
if((*qptr(cx,49184)!=20)){
q3(cx,10);
return 0;
}
vi=q44(cx,ns,nl);
if((vi<0)){
q3(cx,9);
return 0;
}
vb=(qdir(cx,8)+(vi*40));
vt=*qptr(cx,(vb+16));
s=*qptr(cx,(vb+24));
if((1<*qptr(cx,(vb+32)))){
q3(cx,9);
return 0;
}
q14(cx);
ae=q47(cx,1);
if((q42(cx,vt,ae)==0)){
q3(cx,9);
return 0;
}
q46(cx,s,vt);
if((*qptr(cx,49184)!=9)){
q3(cx,10);
return 0;
}
q14(cx);
return 0;
}
q3(cx,10);
return 0;
}
int q52(int **cx,int fi,int k){
int c6=0;
int c=0;
int ns=0;
int nl=0;
int d=0;
int s=0;
int c5=0;
int reg=0;
int ay=0;
int record=0;
c6=0;
c=0;
ns=0;
nl=0;
d=0;
s=0;
c5=0;
reg=0;
ay=0;
record=0;
c6=(qdir(cx,0)+(fi*80));
*qptr(cx,49288)=0;
*qptr(cx,49296)=0;
{
*qptr(cx,68504)=0;
*qptr(cx,68512)=0;
*qptr(cx,68520)=0;
}
c=0;
while(((c<k)&(*qptr(cx,49176)==0))){
ns=*qptr(cx,(61832+(c*8)));
nl=*qptr(cx,(61864+(c*8)));
d=*qptr(cx,(61800+(c*8)));
s=q43(cx,((ns<<8)|nl),(d|(1<<32)));
*qptr(cx,(61904+(c*8)))=s;
c=(c+1);
}
c5=*qptr(cx,49224);
{
q35(cx,(44<<26));
}
q35(cx,(63<<26));
q35(cx,(63<<26));
q35(cx,(63<<26));
c=0;
reg=0;
while(((c<k)&(*qptr(cx,49176)==0))){
{
d=*qptr(cx,(61800+(c*8)));
if(((65536<=(d))==1)){
reg=q16(reg,2);
}
if((4<((reg+1)+(65536<=(d))))){
q3(cx,12);
return 0;
}
q61(cx,(reg|(*qptr(cx,(61904+(c*8)))<<8)),d);
reg=((reg+1)+(65536<=(d)));
}
c=(c+1);
}
ay=0;
while(((((*qptr(cx,49184)!=8)&(*qptr(cx,49184)!=0))&(*qptr(cx,49176)==0))&(*qptr(cx,49176)==0))){
ay=(ay|q50(cx));
}
{
record=(qdir(cx,28)+(fi*64));
*qptr(cx,record)=(c5-112);
*qptr(cx,(record+8))=(*qptr(cx,49224)-112);
*qptr(cx,(record+16))=q16((*qptr(cx,49296)+16),16);
*qptr(cx,(record+24))=*qptr(cx,68512);
*qptr(cx,(record+32))=*qptr(cx,68504);
}
if((*qptr(cx,49184)!=8)){
q3(cx,4);
return 0;
}
q14(cx);
if((ay==0)){
q3(cx,4);
return 0;
}
return 0;
}
int q53(int **cx,int w,int ns){
int nl=0;
int k=0;
int c=0;
int fi=0;
nl=ns&255;ns=ns>>8;
k=0;
c=0;
fi=0;
*qptr(cx,49344)=w;
if((((100<=w)&(w<4196))==1)){
q3(cx,12);
return 0;
}
if((*qptr(cx,49184)!=5)){
q3(cx,10);
return 0;
}
q14(cx);
k=q48(cx);
*qptr(cx,49352)=k;
if((*qptr(cx,49184)!=6)){
q3(cx,12);
return 0;
}
q14(cx);
if((*qptr(cx,49184)==9)){
q40(cx,((ns<<8)|nl),(0|0));
q14(cx);
return 0;
}
if((*qptr(cx,49184)!=7)){
q3(cx,10);
return 0;
}
c=0;
while(((c<k)&(*qptr(cx,49176)==0))){
if((*qptr(cx,(61832+(c*8)))==0)){
q3(cx,12);
return 0;
}
c=(c+1);
}
fi=q40(cx,((ns<<8)|nl),(1|*qptr(cx,49224)));
q14(cx);
q52(cx,fi,k);
return 0;
}
int q54(int **cx){
int d=0;
int bx=0;
int by=0;
int bz=0;
int ca=0;
int cb=0;
int cc=0;
int w=0;
int cd=0;
int cf=0;
int builtin=0;
d=0;
bx=0;
by=0;
bz=0;
ca=0;
cb=0;
cc=0;
w=0;
cd=0;
cf=0;
builtin=0;
if((*qptr(cx,49184)==16)){
q14(cx);
d=q26(cx);
if((*qptr(cx,49184)!=3)){
q3(cx,10);
return 0;
}
bx=*qptr(cx,49200);
by=*qptr(cx,49208);
q14(cx);
if((*qptr(cx,49184)!=9)){
q3(cx,10);
return 0;
}
q14(cx);
q21(cx,((bx<<8)|by),d);
return 0;
}
if((*qptr(cx,49184)==15)){
q14(cx);
if((*qptr(cx,49184)!=3)){
q3(cx,10);
return 0;
}
bz=*qptr(cx,49200);
ca=*qptr(cx,49208);
q14(cx);
if((*qptr(cx,49184)==7)|(*qptr(cx,49184)==9)){return q28(cx,bz,ca);}
d=q23(cx,bz,ca);if(d<0){return 0;}d=d+100;
while((*qptr(cx,49184)==11)&(*qptr(cx,49176)==0)){
if(4294901760<=d){q3(cx,16);return 0;}d=d+65536;q14(cx);}
if(*qptr(cx,49184)!=3){q3(cx,10);return 0;}
bx=*qptr(cx,49200);by=*qptr(cx,49208);q14(cx);
return q53(cx,d,(bx<<8)|by);
}
if((*qptr(cx,49184)==17)){
q14(cx);
if((*qptr(cx,49184)!=3)){
q3(cx,10);
return 0;
}
cb=*qptr(cx,49200);
cc=*qptr(cx,49208);
q14(cx);
if((*qptr(cx,49184)!=7)){
q3(cx,10);
return 0;
}
return q31(cx,cb,cc);
}
w=q26(cx);
if(((*qptr(cx,49184)==37)|(*qptr(cx,49184)==38))){
builtin=*qptr(cx,49184);
if(((0|((builtin==37)&(w!=65539)))|((builtin==38)&(w!=3)))){
q3(cx,9);
return 0;
}
q14(cx);
if((*qptr(cx,49184)!=5)){
q3(cx,10);
return 0;
}
q14(cx);
d=q48(cx);
if(((((d!=1)|((builtin==37)&(*qptr(cx,61800)!=1)))|((builtin==38)&(*qptr(cx,61800)!=65539)))|(*qptr(cx,49184)!=6))){
q3(cx,12);
return 0;
}
q14(cx);
if((*qptr(cx,49184)!=9)){
q3(cx,10);
return 0;
}
q14(cx);
return 0;
}
if((*qptr(cx,49184)!=3)){
q3(cx,10);
return 0;
}
cd=*qptr(cx,49200);
cf=*qptr(cx,49208);
q14(cx);
if((*qptr(cx,49184)!=5)){
q3(cx,14);
return 0;
}
return q53(cx,w,((cd<<8)|cf));
}
int q55(int **cx,int i){
int c=0;
if(*qptr(cx,49176)!=0){return 0;}
c=0;
c=*qptr(cx,49224);
if(((*qptr(cx,68456)-c)<8)){
q3(cx,17);
return 0;
}
*qptr(cx,((qdir(cx,32)+0)+c))=i;
*qptr(cx,49224)=(c+8);
return 0;
}
int q56(int **cx,int fi){
int i=0;
int p=0;
int c6=0;
i=0;
p=0;
c6=0;
i=0;
p=0;
while(((p<fi)&(*qptr(cx,49176)==0))){
c6=(qdir(cx,0)+(p*80));
if((*qptr(cx,(c6+24))!=0)){
i=(i+1);
}
p=(p+1);
}
return i;
}
int q57(int d){
int base=0;
base=d&65535;
if((base==1)|(base==2)|(base==3)){return 1;}
if((65536<=d)&(100<=base)&(base<4196)&((d>>16)<=63)){return 1;}
return 0;
}

int q58(int **cx,int fi){
int c6=0;
int a2=0;
int ln=0;
int n=0;
int wd=0;
int c=0;
int at=0;
int e=0;
int rt=0;
int qi=0;
int p=0;
c6=0;
a2=0;
ln=0;
n=0;
wd=0;
c=0;
at=0;
e=0;
rt=0;
qi=0;
p=0;
c6=(qdir(cx,0)+(fi*80));
a2=*qptr(cx,c6);
ln=*qptr(cx,(c6+8));
q55(cx,ln);
n=0;
while(((n<8)&(*qptr(cx,49176)==0))){
wd=0;
c=0;
while(((c<8)&(*qptr(cx,49176)==0))){
at=((n*8)+c);
if((at<ln)){
wd=(wd|(q0(cx,(a2+at))<<(c*8)));
}
c=(c+1);
}
q55(cx,wd);
n=(n+1);
}
e=*qptr(cx,(c6+24));
rt=*qptr(cx,(c6+32));
if((q57(rt)==0)){
q3(cx,16);
return 0;
}
qi=0;
while(((qi<*qptr(cx,(c6+40)))&(*qptr(cx,49176)==0))){
if((q57(*qptr(cx,((c6+48)+(qi*8))))==0)){
q3(cx,16);
return 0;
}
qi=(qi+1);
}
q55(cx,e);
q55(cx,1);
if((e==1)){
q55(cx,1);
q55(cx,(*qptr(cx,(c6+16))-112));
}
else {
q55(cx,0);
q55(cx,0);
}
q55(cx,0);
wd=rt&65535;if(100<=wd){wd=4;}
q55(cx,((rt>>16)*1000)+wd);
q55(cx,*qptr(cx,(c6+40)));
p=0;
while(((p<4)&(*qptr(cx,49176)==0))){
if((p<*qptr(cx,(c6+40)))){
rt=*qptr(cx,((c6+48)+(p*8)));
wd=rt&65535;if(100<=wd){wd=4;}
q55(cx,((rt>>16)*1000)+wd);
}
else {
q55(cx,0);
}
p=(p+1);
}
return 0;
}
int q59(int **cx){
int typed=0;
int nc=0;
int p=0;
int b=0;
int fx=0;
int t=0;
int ce=0;
int litlen=0;
int fi=0;
int fn=0;
int rec=0;
int index=0;
int local=0;
int previous=0;
int next=0;
int count=0;
int so=0;
int f=0;
int sc=0;
int t2=0;
int ro=0;
int g=0;
int b2=0;
int f2=0;
int t3=0;
int cg=0;
int mg=0;
int frames=0;
int ordinal=0;
nc=0;
p=0;
b=0;
fx=0;
t=0;
ce=0;
litlen=0;
fi=0;
fn=0;
rec=0;
index=0;
local=0;
so=0;
f=0;
sc=0;
t2=0;
ro=0;
g=0;
b2=0;
f2=0;
t3=0;
cg=0;
mg=0;
frames=0;
ordinal=0;
nc=*qptr(cx,49248);
p=0;
while(((p<nc)&(*qptr(cx,49176)==0))){
b=(qdir(cx,4)+(p*16));
fx=*qptr(cx,(b+8));
t=(qdir(cx,0)+(fx*80));
if((*qptr(cx,(t+24))==1)){
q36(cx,*qptr(cx,b),*qptr(cx,(t+16)));
}
else {
if((*qptr(cx,(t+24))!=2)){
q3(cx,7);
return 0;
}
}
p=(p+1);
}
ce=*qptr(cx,49224);
if((ce<=112)){
q3(cx,15);
return 0;
}
litlen=0;
{
fi=0;
while(((fi<*qptr(cx,49240))&(*qptr(cx,49176)==0))){
fn=(qdir(cx,0)+(fi*80));
if((*qptr(cx,(fn+24))==1)){
frames=(frames+1);
}
fi=(fi+1);
}
q55(cx,(12343|(20529<<16)));
q55(cx,2);
q55(cx,(ce-112));
q55(cx,frames);
fi=0;
while(((fi<*qptr(cx,49240))&(*qptr(cx,49176)==0))){
fn=(qdir(cx,0)+(fi*80));
if((*qptr(cx,(fn+24))==1)){
rec=(qdir(cx,28)+(fi*64));
*qptr(cx,(((qdir(cx,32)+0)+112)+*qptr(cx,rec)))=(((44<<26)|ordinal)|((63<<26)<<32));
q55(cx,*qptr(cx,rec));
q55(cx,*qptr(cx,(rec+8)));
q55(cx,*qptr(cx,(rec+16)));
count=*qptr(cx,(rec+24));
q55(cx,count);
local=*qptr(cx,(rec+32));
previous=0;
index=count;
while(((0<index)&(*qptr(cx,49176)==0))){
if(local==0){q3(cx,19);return 0;}
if(*qptr(cx,local)!=(index-1)){q3(cx,19);return 0;}
next=*qptr(cx,(local+8));
*qptr(cx,(local+8))=previous;
previous=local;
local=next;
index=index-1;
}
if(*qptr(cx,49176)!=0){return 0;}
if(local!=0){q3(cx,19);return 0;}
*qptr(cx,(rec+32))=previous;
local=previous;
index=0;
while(((index<count)&(*qptr(cx,49176)==0))){
q55(cx,(*qptr(cx,(rec+16))+*qptr(cx,(local+16))));
q55(cx,*qptr(cx,(local+24)));
q55(cx,*qptr(cx,(local+32)));
q55(cx,*qptr(cx,(local+40)));
local=*qptr(cx,(local+8));
index=(index+1);
}
ordinal=(ordinal+1);
}
fi=(fi+1);
}
litlen=(*qptr(cx,49224)-ce);
}
so=*qptr(cx,49224);
f=*qptr(cx,49240);
sc=0;
p=0;
while(((p<f)&(*qptr(cx,49176)==0))){
t2=(qdir(cx,0)+(p*80));
if((*qptr(cx,(t2+24))!=0)){
q58(cx,p);
sc=(sc+1);
}
p=(p+1);
}
ro=*qptr(cx,49224);
g=0;
p=0;
while(((p<nc)&(*qptr(cx,49176)==0))){
b2=(qdir(cx,4)+(p*16));
f2=*qptr(cx,(b2+8));
t3=(qdir(cx,0)+(f2*80));
if((*qptr(cx,(t3+24))==2)){
q55(cx,1);
q55(cx,(*qptr(cx,b2)-112));
q55(cx,8);
q55(cx,1);
q55(cx,q56(cx,f2));
q55(cx,0);
g=(g+1);
}
p=(p+1);
}
typed=q65(cx,sc);
cg=*qptr(cx,49224);
mg=((((((65|(78<<8))|(75<<16))|(65<<24))|(79<<32))|(77<<40))|(49<<48));
*qptr(cx,(qdir(cx,32)+0))=mg;
*qptr(cx,(qdir(cx,32)+8))=1+typed;
*qptr(cx,(qdir(cx,32)+16))=112;
*qptr(cx,(qdir(cx,32)+24))=cg;
*qptr(cx,(qdir(cx,32)+32))=112;
*qptr(cx,(qdir(cx,32)+40))=(ce-112);
*qptr(cx,(qdir(cx,32)+48))=8;
*qptr(cx,(qdir(cx,32)+56))=ce;
*qptr(cx,(qdir(cx,32)+64))=litlen;
*qptr(cx,(qdir(cx,32)+72))=8;
*qptr(cx,(qdir(cx,32)+80))=so;
*qptr(cx,(qdir(cx,32)+88))=sc;
*qptr(cx,(qdir(cx,32)+96))=ro;
*qptr(cx,(qdir(cx,32)+104))=g;
return 0;
}
int q63(int **cx){
int j=*qptr(cx,49184);
int o=0;
int nz=0;
int ns=0;
int nl=0;
int vi=0;
int value=0;
if(j==4){
value=*qptr(cx,49192);q14(cx);q37(cx,value);
if(value==0){q35(cx,q32(22,5,0,0));nz=1;}
o=1;
}
else if(j==5){
q14(cx);o=q47(cx,1);nz=*qptr(cx,49368);
if(*qptr(cx,49184)!=6){q3(cx,4);return 0;}
q14(cx);
}
else if(j==3){
ns=*qptr(cx,49200);nl=*qptr(cx,49208);q14(cx);
if(*qptr(cx,49184)==5){
*qptr(cx,49152)=ns;q14(cx);o=q66(cx);
}
else{
vi=q44(cx,ns,nl);
if(0<=vi){q45(cx,vi);o=*qptr(cx,49320);}
else{vi=q30(cx,ns,nl);if(vi<0){q3(cx,9);return 0;}q37(cx,vi);o=1;}
}
}
else{o=q66(cx);}
if((*qptr(cx,49184)==39)|(*qptr(cx,49184)==40)){o=q64(cx,o,0);nz=0;}
return o|(nz<<32);
}
int q66(int **cx){
int j=0;
int o=0;
int ns=0;
int nl=0;
int vi=0;
int a=0;
int d=0;
int s=0;
int dt=0;
int i=0;
int sz=0;
int t0=0;
int t1=0;
int t2=0;
int t3=0;
int at=0;
int t=0;
int ai=0;
int fi=0;
int c6=0;
int k=0;
int ap=0;
int cp=0;
j=0;
o=0;
ns=0;
nl=0;
vi=0;
a=0;
d=0;
s=0;
dt=0;
i=0;
sz=0;
t0=0;
t1=0;
t2=0;
t3=0;
at=0;
t=0;
ai=0;
fi=0;
c6=0;
k=0;
ap=0;
cp=0;
j=*qptr(cx,49184);
if(((j==37)|(j==38))){
{
}
q14(cx);
if((*qptr(cx,49184)!=5)){
q3(cx,4);
return 0;
}
q14(cx);
at=q47(cx,1);
if((j==37)){
if(((at!=1)&(at!=2))){
q3(cx,9);
return 0;
}
q35(cx,q33(10,1,4,0));
q35(cx,q32(22,2,0,0));
q35(cx,q32(22,3,0,0));
}
else {
if((((65536<=(at))==0)&((at!=1)|(*qptr(cx,49368)!=1)))){
q3(cx,9);
return 0;
}
q35(cx,q33(38,2,4,0));
q35(cx,q32(22,1,0,0));
}
if((*qptr(cx,49184)!=6)){
q3(cx,12);
return 0;
}
q14(cx);
q35(cx,q32(22,0,0,(21+(j==38))));
q35(cx,q32(22,4,0,0));
q35(cx,q32(22,5,0,0));
q35(cx,(57<<26));
if((j==37)){
q35(cx,q33(38,4,0,0));
o=(65536+3);
}
else {
o=3;
}
}
else {
o=0;
ns=0;
nl=0;
vi=0;
a=0;
d=0;
if((j==12)){
q14(cx);
if((*qptr(cx,49184)!=3)){
q3(cx,4);
return 0;
}
vi=q44(cx,*qptr(cx,49200),*qptr(cx,49208));
if((vi<0)){
q3(cx,9);
return 0;
}
a=(qdir(cx,8)+(vi*40));
d=*qptr(cx,(a+16));
s=*qptr(cx,(a+24));
q14(cx);
if(*qptr(cx,49184)==39){
q45(cx,vi);o=q64(cx,d,1);return o;
}
{
q35(cx,q32(45,4,0,s));
}
if(4294901760<=d){q3(cx,16);return 0;}
o=(65536+d);
}
else {
if((j==11)){
q14(cx);
dt=q47(cx,8);
if(((65536<=(dt))==1)){
dt=(dt-65536);
}
else {
{
q3(cx,9);
return 0;
}
}
if((((dt!=1)&(dt!=2))&(((65536<=(dt))==0)|0))&((dt<100)|(4196<=dt))){
q3(cx,9);
return 0;
}
{
if((100<=dt)&(dt<4196)){
if(q24(cx,dt)==0){q3(cx,9);return 0;}
}
else if(((65536<=(dt))==1)){
q35(cx,q32(40,4,4,0));
}
else {
q35(cx,(q33(42,4,4,0)+((dt!=2)*3)));
}
}
o=dt;
}
else {
if((j==4)){q3(cx,4);return 0;}
else {
if((j==23)){
q14(cx);
if((*qptr(cx,49184)!=5)){
q3(cx,4);
return 0;
}
q14(cx);
dt=q26(cx);
i=1;
if((*qptr(cx,49184)==13)){
q14(cx);
if((*qptr(cx,49184)!=4)){
q3(cx,4);
return 0;
}
i=*qptr(cx,49192);
q14(cx);
if((*qptr(cx,49184)!=14)){
q3(cx,4);
return 0;
}
q14(cx);
}
if((*qptr(cx,49184)!=6)){
q3(cx,4);
return 0;
}
q14(cx);
sz=q24(cx,dt);
if((((sz==0)|(i<=0))|(1024<i))){
q3(cx,9);
return 0;
}
q37(cx,(sz*i));
o=1;
}
else {
if((((j==34)|(j==35))|(j==36))){
{
}
q14(cx);
if((*qptr(cx,49184)!=5)){
q3(cx,4);
return 0;
}
q14(cx);
if(((j==35)|(j==36))){
at=q47(cx,1);
if((at!=(65536+2))){
q3(cx,9);
return 0;
}
t0=q60(cx,at,1);
q61(cx,(4|(t0<<8)),at);
if((*qptr(cx,49184)!=10)){
q3(cx,12);
return 0;
}
q14(cx);
at=q47(cx,1);
if(((at!=1)&(at!=2))){
q3(cx,9);
return 0;
}
t1=q60(cx,1,1);
q61(cx,(4|(t1<<8)),1);
if((*qptr(cx,49184)!=6)){
q3(cx,12);
return 0;
}
q14(cx);
q62(cx,(2|(t0<<8)),(65536+2));
q62(cx,(4|(t1<<8)),1);
q35(cx,q32(22,0,0,(1+((j==36)*19))));
q35(cx,q32(22,1,0,0));
q35(cx,q32(22,5,0,0));
q35(cx,(57<<26));
q35(cx,q33(10,4,0,0));
o=1;
}
else {
ap=0;
t0=0;
t1=0;
t2=0;
t3=0;
while(((ap<4)&(*qptr(cx,49176)==0))){
at=q47(cx,1);
if(((at!=1)&(at!=2))){
q3(cx,9);
return 0;
}
{
t=q60(cx,1,1);
q61(cx,(4|(t<<8)),1);
if((ap==0)){
t0=t;
}
if((ap==1)){
t1=t;
}
if((ap==2)){
t2=t;
}
if((ap==3)){
t3=t;
}
}
ap=(ap+1);
if((ap<4)){
if((*qptr(cx,49184)!=10)){
q3(cx,12);
return 0;
}
q14(cx);
}
}
if((*qptr(cx,49184)!=6)){
q3(cx,12);
return 0;
}
q14(cx);
ai=0;
while(((ai<4)&(*qptr(cx,49176)==0))){
{
t=t0;
if((ai==1)){
t=t1;
}
if((ai==2)){
t=t2;
}
if((ai==3)){
t=t3;
}
q62(cx,(ai|(t<<8)),1);
}
ai=(ai+1);
}
{
}
q35(cx,(57<<26));
q35(cx,q33(10,4,0,0));
o=1;
}
}
else {
if((j==3)){
ns=*qptr(cx,49200);
nl=*qptr(cx,49208);
q14(cx);
if((*qptr(cx,49184)==5)){
fi=q38(cx,ns,nl);
if((fi<0)){
q3(cx,7);
return 0;
}
c6=(qdir(cx,0)+(fi*80));
k=*qptr(cx,(c6+40));
ap=0;
ai=0;
t0=0;
t1=0;
t2=0;
t3=0;
q14(cx);
while(((ap<k)&(*qptr(cx,49176)==0))){
at=q47(cx,1);
if((q42(cx,*qptr(cx,((c6+48)+(ap*8))),at)==0)){
q3(cx,9);
return 0;
}
if((1&((65536<=(*qptr(cx,((c6+48)+(ap*8)))))==1))){
at=*qptr(cx,((c6+48)+(ap*8)));
}
{
t=q60(cx,at,1);
q61(cx,(4|(t<<8)),at);
if((ap==0)){
t0=t;
}
if((ap==1)){
t1=t;
}
if((ap==2)){
t2=t;
}
if((ap==3)){
t3=t;
}
}
ap=(ap+1);
if((ap<k)){
if((*qptr(cx,49184)!=10)){
q3(cx,12);
return 0;
}
q14(cx);
}
}
if((*qptr(cx,49184)!=6)){
q3(cx,12);
return 0;
}
q14(cx);
ap=0;
while(((ap<k)&(*qptr(cx,49176)==0))){
{
t=t0;
if((ap==1)){
t=t1;
}
if((ap==2)){
t=t2;
}
if((ap==3)){
t=t3;
}
d=*qptr(cx,((c6+48)+(ap*8)));
if(((65536<=(d))==1)){
ai=q16(ai,2);
}
if((4<((ai+1)+(65536<=(d))))){
q3(cx,12);
return 0;
}
q62(cx,(ai|(t<<8)),d);
ai=((ai+1)+(65536<=(d)));
}
ap=(ap+1);
}
{
}
cp=*qptr(cx,49224);
q35(cx,(50<<26));
if((*qptr(cx,(c6+24))==1)){
q36(cx,cp,*qptr(cx,(c6+16)));
}
else {
q41(cx,cp,fi);
}
if((1&((65536<=(*qptr(cx,(c6+32))))==1))){
q35(cx,q33(38,4,0,0));
}
else {
q35(cx,q33(10,4,0,0));
}
o=*qptr(cx,(c6+32));
}
else {
vi=q44(cx,ns,nl);
if((0<=vi)){
q45(cx,vi);
o=*qptr(cx,49320);
}
else {
vi=q30(cx,ns,nl);
if((0<=vi)){
q37(cx,vi);
o=1;
}
else {
q3(cx,9);
return 0;
}
}
}
}
else {
if((j==5)){q3(cx,4);return 0;}
else {
q3(cx,4);
return 0;
}
}
}
}
}
}
}
}
return o;
}

int q64(int **cx,int d,int mode){
int token=0;
int sb=0;
int field=0;
int count=0;
int index=0;
int found=0;
int name=0;
int length=0;
int offset=0;
int size=0;
int width=0;
int array=0;
while(((*qptr(cx,49184)==39)|(*qptr(cx,49184)==40))&(*qptr(cx,49176)==0)){
token=*qptr(cx,49184);
if(token==39){
if((d<65636)|(69732<=d)){q3(cx,9);return 0;}
d=d-65536;
}
if((d<100)|(4196<=d)){q3(cx,9);return 0;}
sb=qdir(cx,16)+(d-100)*48;
size=q24(cx,d);
if(size==0){q3(cx,9);return 0;}
q14(cx);
if(*qptr(cx,49184)!=3){q3(cx,4);return 0;}
name=*qptr(cx,49200);length=*qptr(cx,49208);
count=*qptr(cx,(sb+24));index=0;found=0;
while(index<count){
field=qdir(cx,20)+(*qptr(cx,(sb+16))+index)*40;
if(q15(cx,(name<<8)|length,(*qptr(cx,field)<<8)|*qptr(cx,(field+8)))==1){found=field;}
index=index+1;
}
if(found==0){q3(cx,9);return 0;}
d=*qptr(cx,(found+16));offset=*qptr(cx,(found+24));array=*qptr(cx,(found+32));
width=q24(cx,d)*array;
if((width<=0)|(offset<0)|(size<offset)|(size-offset<width)){q3(cx,9);return 0;}
q35(cx,q33(38,6,4,0));q37(cx,offset);q35(cx,q33(39,4,6,4));
q14(cx);
if((mode==1)&(*qptr(cx,49184)!=39)&(*qptr(cx,49184)!=40)){
if((array!=1)|((100<=d)&(d<4196))|(4294901760<=d)){q3(cx,9);return 0;}
return d+65536;
}
if(1<array){
if(4294901760<=d){q3(cx,16);return 0;}
d=d+65536;
}
else if((65536<=(d))==1){q35(cx,q32(40,4,4,0));}
else if((d==1)|(d==2)){q35(cx,q33(42,4,4,0)+((d!=2)*3));}
else if((d<100)|(4196<=d)){q3(cx,9);return 0;}
}
return d;
}

int q65(int **cx,int sc){
int ti=0;
int tj=0;
int tk=0;
int tr=0;
int td=0;
int tref=0;
int tag=0;
int name=0;
int len=0;
int byte=0;
int word=0;
int changed=0;
int trailer=0;
int typecount=0;
int fi=0;
int f=0;
int rec=0;
int t2=0;
int count=0;
f=*qptr(cx,49240);
typecount=0;changed=1;
fi=0;while(fi<f){rec=qdir(cx,0)+fi*80;
if(*qptr(cx,rec+24)!=0){tk=0;while(tk<=*qptr(cx,rec+40)){
tref=*qptr(cx,rec+32);if(0<tk){tref=*qptr(cx,rec+40+tk*8);}
tag=tref&65535;
if((100<=tag)&(tag<4196)){tr=qdir(cx,16)+(tag-100)*48;*qptr(cx,tr+40)=*qptr(cx,tr+40)|(1<<32);}
tk=tk+1;}}
fi=fi+1;}
while(changed!=0){changed=0;fi=0;
while(fi<*qptr(cx,49272)){rec=qdir(cx,16)+fi*48;
if((*qptr(cx,rec+40)&(1<<32))!=0){tk=0;
while(tk<*qptr(cx,rec+24)){
tr=qdir(cx,20)+(*qptr(cx,rec+16)+tk)*40;tag=*qptr(cx,tr+16)&65535;
if((100<=tag)&(tag<4196)){tr=qdir(cx,16)+(tag-100)*48;
if((*qptr(cx,tr+40)&(1<<32))==0){*qptr(cx,tr+40)=*qptr(cx,tr+40)|(1<<32);changed=1;}}
tk=tk+1;}}
fi=fi+1;}}
fi=0;while(fi<*qptr(cx,49272)){
if((*qptr(cx,qdir(cx,16)+fi*48+40)&(1<<32))!=0){typecount=typecount+1;}fi=fi+1;}
if(0<typecount){
trailer=*qptr(cx,49224);
q55(cx,13890492266401345);q55(cx,1);q55(cx,0);q55(cx,typecount);q55(cx,sc);
fi=0;while(fi<*qptr(cx,49272)){
rec=qdir(cx,16)+fi*48;
if((*qptr(cx,rec+40)&(1<<32))!=0){
name=*qptr(cx,rec);len=*qptr(cx,rec+8);
ti=0;while(ti<8){word=0;tj=0;while(tj<8){byte=ti*8+tj;
if(byte<len){word=word|(q0(cx,name+byte)<<(tj*8));}tj=tj+1;}
q55(cx,word);ti=ti+1;}

count=*qptr(cx,rec+24);q55(cx,0<count);q55(cx,*qptr(cx,rec+32));
if(count==0){q55(cx,0);}else{q55(cx,*qptr(cx,rec+40)&65535);}
q55(cx,count);if(count==0){q55(cx,0);}else{q55(cx,(*qptr(cx,rec+40)>>16)&65535);}q55(cx,0);
tk=0;while(tk<count){t2=qdir(cx,20)+(*qptr(cx,rec+16)+tk)*40;
name=*qptr(cx,t2);len=*qptr(cx,t2+8);
ti=0;while(ti<8){word=0;tj=0;while(tj<8){byte=ti*8+tj;
if(byte<len){word=word|(q0(cx,name+byte)<<(tj*8));}tj=tj+1;}
q55(cx,word);ti=ti+1;}

tref=*qptr(cx,t2+16);
tag=tref&65535;td=tref>>16;
if(63<td){q3(cx,16);return 0;}
name=0;len=0;
if(100<=tag){tr=qdir(cx,16)+(tag-100)*48;name=*qptr(cx,tr);len=*qptr(cx,tr+8);tag=4;}
q55(cx,tag);q55(cx,td);
ti=0;while(ti<8){word=0;tj=0;while(tj<8){byte=ti*8+tj;
if(byte<len){word=word|(q0(cx,name+byte)<<(tj*8));}tj=tj+1;}
q55(cx,word);ti=ti+1;}

q55(cx,*qptr(cx,t2+24));q55(cx,*qptr(cx,t2+32));tk=tk+1;}}
fi=fi+1;}
fi=0;while(fi<f){rec=qdir(cx,0)+fi*80;
if(*qptr(cx,rec+24)!=0){name=*qptr(cx,rec);len=*qptr(cx,rec+8);
ti=0;while(ti<8){word=0;tj=0;while(tj<8){byte=ti*8+tj;
if(byte<len){word=word|(q0(cx,name+byte)<<(tj*8));}tj=tj+1;}
q55(cx,word);ti=ti+1;}

q55(cx,*qptr(cx,rec+24));q55(cx,*qptr(cx,rec+40));tk=0;
while(tk<5){tref=0;
if(tk==0){tref=*qptr(cx,rec+32);}else{if(tk<=*qptr(cx,rec+40)){tref=*qptr(cx,rec+40+tk*8);}}
tag=tref&65535;td=tref>>16;
if(63<td){q3(cx,16);return 0;}
name=0;len=0;
if(100<=tag){tr=qdir(cx,16)+(tag-100)*48;name=*qptr(cx,tr);len=*qptr(cx,tr+8);tag=4;}
q55(cx,tag);q55(cx,td);
ti=0;while(ti<8){word=0;tj=0;while(tj<8){byte=ti*8+tj;
if(byte<len){word=word|(q0(cx,name+byte)<<(tj*8));}tj=tj+1;}
q55(cx,word);ti=ti+1;}

tk=tk+1;}}
fi=fi+1;}
*qptr(cx,qdir(cx,32)+trailer+16)=*qptr(cx,49224)-trailer;
}
return 0<typecount;
}
