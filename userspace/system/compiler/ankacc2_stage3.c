int q0(int c){
int bf=c&(0-8);
int ao=*(*49168+bf);
int ak=(c&7)*8;
return(ao>>ak)&255;}
int q1(){
int c=*49152;
if(*49160<=c){
return 0;}
return q0(c);}
int q2(){
*49152=*49152+1;
return 0;}
int q3(int bo){
if(*49176==0){
*49176=bo;}
return 0;}
int q4(){
int n=q1();
while((0<n)&(n<=32)){
q2();
n=q1();}
return 0;}
int q5(int n){
int b6=0;
if((65<=n)&(n<=90)){
b6=1;}
if((97<=n)&(n<=122)){
b6=1;}
if(n==95){
b6=1;}
return b6;}
int q6(int n){
int b6=q5(n);
if((48<=n)&(n<=57)){
b6=1;}
return b6;}
int q7(int g,int m){
int h=0;
int c=0;
int j=3;
while(c<m){
h=(h<<5)|(q0(g+c)-96);
c=c+1;}
if((m==3)&(h==9684)){j=1;}
if((m==6)&(h==(22094|(18612<<15)))){j=2;}
if((m==6)&(h==(21620|(20114<<15)))){j=15;}
if((m==7)&(h==(4262|(26117<<15)|(20<<30)))){j=16;}
if((m==4)&(h==(15021|(5<<15)))){j=17;}
if((m==4)&(h==(15652|(22<<15)))){j=18;}
if((m==4)&(h==(8242|(3<<15)))){j=19;}
if((m==6)&(h==(5606|(19770<<15)))){j=23;}
if((m==2)&(h==294)){j=24;}
if((m==4)&(h==(12901|(5<<15)))){j=25;}
if((m==5)&(h==(9605|(744<<15)))){j=26;}
if((m==7)&(h==(1420|(26211<<15)|(19<<30)))){j=34;}
return j;}
int q8(){
int g=*49152;
int m=0;
int n=q1();
while(q6(n)==1){
m=m+1;
if(63<m){
q3(2);
return 0;}
q2();
n=q1();}
*49200=g;
*49208=m;
*49184=q7(g,m);
return 0;}
int q9(int n){
int i=0-1;
if((48<=n)&(n<=57)){
i=n-48;}
if((65<=n)&(n<=70)){
i=n-55;}
if((97<=n)&(n<=102)){
i=n-87;}
return i;}
int q10(int g){
int ad=0;
while(ad<4){
int i=0;
int c=0;
while(c<5){
i=i*10+(q0(g+ad*5+c)-48);
c=c+1;}
int ab=0;
if(ad==0){
ab=18446;}
if(ad==1){
ab=74407;}
if(ad==2){
ab=37095;}
if(ad==3){
ab=51615;}
if(i<ab){
return 1;}
if(ab<i){
return 0;}
ad=ad+1;}
return 1;}
int q11(){
int i=0;
int l=0;
int ah=0;
int aq=0;
int n=q1();
int r=0;
while((48<=n)&(n<=57)){
r=n-48;
if(aq==0){
if(r!=0){
aq=1;
ah=*49152;
l=1;}
}
else{
l=l+1;}
i=i*10+r;
q2();
n=q1();}
if(20<l){
q3(3);
return 0;}
if(l==20){
if(q10(ah)==0){
q3(3);
return 0;}
}
*49192=i;
*49184=4;
return 0;}
int q12(){
int i=0;
int l=0;
int aq=0;
int bq=0;
int r=0;
int n=0;
q2();
q2();
n=q1();
r=q9(n);
while(0<=r){
bq=1;
if(aq==0){
if(r!=0){
aq=1;
l=1;}
}
else{
l=l+1;}
i=(i<<4)|r;
q2();
n=q1();
r=q9(n);}
if(bq==0){
q3(3);
return 0;}
if(16<l){
q3(3);
return 0;}
*49192=i;
*49184=4;
return 0;}
int q13(){
int c=*49152;
if(q0(c)==48){
if(c+1<*49160){
int n=q0(c+1);
if((n==120)|(n==88)){
return q12();}
}
}
return q11();}
int q14(){
q4();
if(*49176!=0){*49184=0;return 0;}
if(*49160<=*49152){*49184=0;return 0;}
int n=q1();
if(q5(n)==1){return q8();}
if((48<=n)&(n<=57)){return q13();}
int j=0;
if(n==40){j=5;}
if(n==41){j=6;}
if(n==123){j=7;}
if(n==125){j=8;}
if(n==59){j=9;}
if(n==44){j=10;}
if(n==42){j=11;}
if(n==38){j=12;}
if(n==91){j=13;}
if(n==93){j=14;}
if(n==43){j=21;}
if(n==45){j=22;}
if(n==124){j=33;}
if(n==61){
q2();
if(q1()==61){q2();j=29;}else{j=20;}
*49184=j;return 0;}
if(n==60){
q2();
n=q1();
if(n==61){q2();j=28;}
else{if(n==60){q2();j=31;}else{j=27;}}
*49184=j;return 0;}
if(n==62){
q2();
if(q1()==62){q2();*49184=32;return 0;}
q3(1);*49184=0;return 0;}
if(n==33){
q2();
if(q1()==61){q2();*49184=30;return 0;}
q3(1);*49184=0;return 0;}
if(j!=0){*49184=j;q2();return 0;}
q3(1);*49184=0;return 0;}
int q15(int az,int bl,int bk,int br){
if(bl!=br){
return 0;}
int c=0;
while(c<bl){
if(q0(az+c)!=q0(bk+c)){
return 0;}
c=c+1;}
return 1;}
int q16(int i,int x){
return(i+x-1)&(0-x);}
int q17(int d){
return 1000+d;}
int q18(int d){
if(1000<=d){
return 1;}
return 0;}
int q19(int d){
return d-1000;}
int q20(int g,int m){
int e=*49264;
int c=0;
int a=0;
while(c<e){
a=54632+c*24;
if(q15(g,m,*a,*(a+8))==1){
return*(a+16);}
c=c+1;}
return 0;}
int q21(int g,int m,int d){
if(q20(g,m)!=0){
q3(10);
return 0;}
int e=*49264;
if(32<=e){
q3(8);
return 0;}
int a=54632+e*24;
*a=g;
*(a+8)=m;
*(a+16)=d;
*49264=e+1;
return 0;}
int q22(int g,int m){
int e=*49272;
int c=0;
int a=0;
while(c<e){
a=55400+c*48;
if(q15(g,m,*a,*(a+8))==1){
return c;}
c=c+1;}
return 0-1;}
int q23(int g,int m){
int bs=q22(g,m);
if(0<=bs){
return bs;}
int e=*49272;
if(16<=e){
q3(8);
return 0-1;}
int a=55400+e*48;
*a=g;
*(a+8)=m;
*(a+16)=*49280;
*(a+24)=0;
*(a+32)=0;
*(a+40)=1;
*49272=e+1;
return e;}
int q24(int d){
int ar=0;
if(d==1){
ar=8;}
if(d==2){
ar=1;}
if(1000<=d){
ar=8;}
if((100<=d)&(d<116)){
int a=55400+(d-100)*48;
ar=*(a+32);}
return ar;}
int q25(int d){
int x=1;
if(d==1){
x=8;}
if(1000<=d){
x=8;}
if((100<=d)&(d<116)){
int a=55400+(d-100)*48;
x=*(a+40);}
return x;}
int q26(){
int d=0;
int j=*49184;
if(j==1){
d=1;
q14();}
if(j==19){
d=2;
q14();}
if(j==18){
d=3;
q14();}
if(j==15){
q14();
if(*49184!=3){
q3(10);
return 0;}
int i=q22(*49200,*49208);
if(i<0){
q3(10);
return 0;}
d=100+i;
q14();}
if(j==17){
q14();
if(*49184!=3){
q3(10);
return 0;}
int et=q20(*49200,*49208);
if(et!=(0-1)){
q3(10);
return 0;}
d=1;
q14();}
if((j==3)&(d==0)){
d=q20(*49200,*49208);
if(d<=0){
q3(10);
return 0;}
q14();}
if(d==0){
q3(10);
return 0;}
while(*49184==11){
d=q17(d);
q14();}
return d;}
int q27(int g,int m,int d,int e){
int i=*49360;
int sb=55400+i*48;
int f=*(sb+24);
int az=*(sb+16);
int c=0;
int a=0;
while(c<f){
a=56168+(az+c)*40;
if(q15(g,m,*a,*(a+8))==1){
q3(10);
return 0;}
c=c+1;}
int ba=*49280;
if(64<=ba){
q3(8);
return 0;}
int al=q25(d);
int sz=q24(d);
if((sz==0)|(e<=0)|(1024<e)){
q3(13);
return 0;}
int s=q16(*(sb+32),al);
if(8192<s+sz*e){
q3(13);
return 0;}
a=56168+ba*40;
*a=g;
*(a+8)=m;
*(a+16)=d;
*(a+24)=s;
*(a+32)=e;
*49280=ba+1;
*(sb+24)=f+1;
*(sb+32)=s+sz*e;
if(*(sb+40)<al){
*(sb+40)=al;}
return 0;}
int q28(int g,int m){
int i=q23(g,m);
*49360=i;
if(i<0){
return 0;}
int sb=55400+i*48;
if(0<*(sb+24)){
q3(10);
return 0;}
if(*49184!=7){
q3(10);
return 0;}
q14();
while((*49184!=8)&(*49176==0)){
int d=q26();
if(*49184!=3){
q3(10);
return 0;}
int ns=*49200;
int nl=*49208;
q14();
int e=1;
if(*49184==13){
q14();
if(*49184!=4){
q3(10);
return 0;}
e=*49192;
q14();
if(*49184!=14){
q3(10);
return 0;}
q14();}
if(*49184!=9){
q3(10);
return 0;}
q14();
q27(ns,nl,d,e);}
if(*49184!=8){
q3(10);
return 0;}
q14();
if(*49184!=9){
q3(10);
return 0;}
q14();
*(sb+32)=q16(*(sb+32),*(sb+40));
return 0;}
int q29(int g,int m,int i){
int e=*49312;
int c=0;
int a=0;
while(c<e){
a=58984+c*24;
if(q15(g,m,*a,*(a+8))==1){
q3(10);
return 0;}
c=c+1;}
if(64<=e){
q3(8);
return 0;}
a=58984+e*24;
*a=g;
*(a+8)=m;
*(a+16)=i;
*49312=e+1;
return 0;}
int q30(int g,int m){
int e=*49312;
int c=0;
int a=0;
while(c<e){
a=58984+c*24;
if(q15(g,m,*a,*(a+8))==1){
return*(a+16);}
c=c+1;}
return 0-1;}
int q31(int g,int m){
q21(g,m,0-1);
if(*49184!=7){
q3(10);
return 0;}
q14();
int i=0;
while((*49184!=8)&(*49176==0)){
if(*49184!=3){
q3(10);
return 0;}
int ns=*49200;
int nl=*49208;
q14();
if(*49184==20){
q14();
if(*49184!=4){
q3(10);
return 0;}
i=*49192;
q14();}
q29(ns,nl,i);
i=i+1;
if(*49184==10){
q14();}
}
if(*49184!=8){
q3(10);
return 0;}
q14();
if(*49184!=9){
q3(10);
return 0;}
q14();
return 0;}
int q32(int u,int bg,int ag,int bw){
return(u<<26)|(bg<<22)|(ag<<18)|((bw<<46)>>46);}
int q33(int u,int bg,int o,int am){
return(u<<26)|(bg<<22)|(o<<18)|(am<<14);}
int q34(int u){
return u<<26;}
int q35(int ao){
int c=*49224;
if(*68472<c+8){
q3(8);
return 0;}
int an=ao|((63<<26)<<32);
*(73728+c)=an;
*49224=c+8;
return 0;}
int q36(int c,int y){
int v=(y>>2)-(c>>2);
int ao=(50<<26)|((v<<42)>>42);
int an=ao|((63<<26)<<32);
*(73728+c)=an;
return 0;}
int q37(int i){
if(((0-131071-1)<=i)&(i<=131071)){
q35(q32(22,4,0,i));
return 0;}
int c=0;
int ak=0;
int bb=0;
q35(q32(22,4,0,0));
q35(q32(22,5,0,4));
while(c<16){
q35(q33(6,4,4,5));
ak=(15-c)*4;
bb=(i>>ak)&15;
q35(q32(22,0,0,bb));
q35(q33(4,4,4,0));
c=c+1;}
return 0;}
int q38(int g,int m){
int e=*49240;
int c=0;
int a=0;
while(c<e){
a=61936+c*80;
if(q15(g,m,*a,*(a+8))==1){
return c;}
c=c+1;}
return 0-1;}
int q39(int a,int w,int k){
if(*(a+32)!=w){
return 0;}
if(*(a+40)!=k){
return 0;}
int c=0;
while(c<k){
if(*(a+48+c*8)!=*(61800+c*8)){
return 0;}
c=c+1;}
return 1;}
int q40(int g,int m,int aw,int y){
int w=*49344;
int k=*49352;
int fi=q38(g,m);
int a=0;
if(0<=fi){
a=61936+fi*80;
if(q39(a,w,k)==0){
q3(11);
return fi;}
if(aw==1){
if(*(a+24)==1){
q3(5);
return fi;}
*(a+24)=1;
*(a+16)=y;}
return fi;}
int e=*49240;
if(64<=e){
q3(8);
return 0;}
a=61936+e*80;
*a=g;
*(a+8)=m;
*(a+16)=y;
*(a+24)=aw;
*(a+32)=w;
*(a+40)=k;
int c=0;
while(c<4){
*(a+48+c*8)=*(61800+c*8);
c=c+1;}
*49240=e+1;
return e;}
int q41(int c,int fi){
int e=*49248;
if(128<=e){
q3(8);
return 0;}
int c6=61936+fi*80;
if(*(c6+24)==0){
*(c6+24)=2;}
int a=52584+e*16;
*a=c;
*(a+8)=fi;
*49248=e+1;
return 0;}
int q42(int bh,int ae){
if(bh==ae){
return 1;}
if((bh==1)&(ae==2)){
return 1;}
if((bh==2)&(ae==1)){
return 1;}
return 0;}
int q43(int g,int m,int d,int e){
int vc=*49288;
int c=0;
int a=0;
while(c<vc){
a=60520+c*40;
if(q15(g,m,*a,*(a+8))==1){
q3(10);
return 0;}
c=c+1;}
if(32<=vc){
q3(8);
return 0;}
if((d==3)|(e<=0)){
q3(9);
return 0;}
if(1024<e){
q3(13);
return 0;}
int sz=q24(d)*e;
int al=q25(d);
int aj=q16(*49296,al);
int bi=sz;
if(bi<8){
bi=8;}
aj=aj+bi;
if(8192<aj){
q3(13);
return 0;}
*49296=aj;
a=60520+vc*40;
*a=g;
*(a+8)=m;
*(a+16)=d;
*(a+24)=0-aj;
*(a+32)=e;
*49288=vc+1;
return 0-aj;}
int q44(int g,int m){
int vc=*49288;
int c=0;
int a=0;
while(c<vc){
a=60520+c*40;
if(q15(g,m,*a,*(a+8))==1){
return c;}
c=c+1;}
return 0-1;}
int q45(int vi){
int a=60520+vi*40;
int d=*(a+16);
int e=*(a+32);
int s=*(a+24);
if(1<e){
q35(q32(16,4,13,s));
*49320=q17(d);
return 0;}
if((q24(d)!=8)&(d!=2)){
q3(9);
return 0;}
q35(q32(32+(d==2)*4,4,13,s));
*49320=d;
return 0;}
int q46(int s,int d){
q35(q32(33+(d==2)*4,4,13,s));
return 0;}
int q47(int bu){
int j=*49184;
int o=0;
int ns=0;
int nl=0;
int vi=0;
int a=0;
int d=0;
if(j==12){
q14();
if(*49184!=3){q3(4);return 0;}
vi=q44(*49200,*49208);
if(vi<0){q3(9);return 0;}
a=60520+vi*40;
d=*(a+16);
int s=*(a+24);
q14();
q35(q32(16,4,13,s));
o=q17(d);}
else{
if(j==11){
q14();
int r=q47(8);
int dt=0;
if(q18(r)==1){dt=q19(r);}
else{
if((r==1)&(*68480==1)){dt=1;}
else{q3(9);return 0;}}
if((dt!=1)&(dt!=2)){q3(9);return 0;}
q35(q32(32+(dt==2)*4,4,4,0));
o=dt;}
else{
if(j==4){
int i=*49192;
q14();
q37(i);
o=1;}
else{
if(j==23){
q14();
if(*49184!=5){q3(4);return 0;}
q14();
int bm=q26();
int e=1;
if(*49184==13){
q14();
if(*49184!=4){q3(4);return 0;}
e=*49192;
q14();
if(*49184!=14){q3(4);return 0;}
q14();}
if(*49184!=6){q3(4);return 0;}
q14();
int sz=q24(bm);
if((sz==0)|(e<=0)|(1024<e)){q3(9);return 0;}
q37(sz*e);
o=1;}
else{
if(j==34){
q14();
if(*49184!=5){q3(4);return 0;}
q14();
int a3=0;
while(a3<4){
int at=q47(1);
if((at!=1)&(at!=2)){q3(9);return 0;}
q35(q32(17,15,15,8));
q35(q32(33,4,15,0));
a3=a3+1;
if(a3<4){
if(*49184!=10){q3(12);return 0;}
q14();}}
if(*49184!=6){q3(12);return 0;}
q14();
int ai=0;
while(ai<4){
q35(q32(32,ai,15,(3-ai)*8));
ai=ai+1;}
q35(q32(16,15,15,32));
q35(q34(57));
q35(q33(10,4,0,0));
o=1;}
else{
if(j==3){
ns=*49200;
nl=*49208;
q14();
if(*49184==5){
int fi=q38(ns,nl);
if(fi<0){q3(7);return 0;}
int c6=61936+fi*80;
int k=*(c6+40);
int ap=0;
q14();
while(ap<k){
int bt=q47(1);
if(q42(*(c6+48+ap*8),bt)==0){q3(9);return 0;}
q35(q32(17,15,15,8));
q35(q32(33,4,15,0));
ap=ap+1;
if(ap<k){
if(*49184!=10){q3(12);return 0;}
q14();}}
if(*49184!=6){q3(12);return 0;}
q14();
ap=0;
while(ap<k){
q35(q32(32,ap,15,(k-1-ap)*8));
ap=ap+1;}
if(0<k){q35(q32(16,15,15,k*8));}
int cp=*49224;
q35(50<<26);
if(*(c6+24)==1){q36(cp,*(c6+16));}
else{q41(cp,fi);}
q35(q33(10,4,0,0));
o=*(c6+32);}
else{
vi=q44(ns,nl);
if(0<=vi){q45(vi);o=*49320;}
else{
int cv=q30(ns,nl);
if(0<=cv){q37(cv);o=1;}
else{q3(9);return 0;}}}}
else{
if(j==5){
q14();
o=q47(1);
if(*49184!=6){q3(4);return 0;}
q14();}
else{q3(4);return 0;}}}}}}}
while(*49176==0){
int u=*49184;
int z=0;
if(u==33){z=1;}
if(u==12){z=2;}
if((u==29)|(u==30)){z=3;}
if((u==27)|(u==28)){z=4;}
if((u==31)|(u==32)){z=5;}
if((u==21)|(u==22)){z=6;}
if(u==11){z=7;}
if(z<bu){*49320=o;return o;}
q35(q32(17,15,15,8));
q35(q32(33,4,15,0));
q14();
int am=q47(z+1);
q35(q32(32,5,15,0));
q35(q32(16,15,15,8));
if(((o!=1)&(o!=2))|((am!=1)&(am!=2))){q3(9);return 0;}
if(u==11){q35(q33(11,4,5,4));}
if(u==21){q35(q33(1,4,5,4));}
if(u==22){q35(q33(2,4,5,4));}
if(u==31){q35(q33(6,4,5,4));}
if(u==32){q35(q33(7,4,5,4));}
if(u==12){q35(q33(3,4,5,4));}
if(u==33){q35(q33(4,4,5,4));}
if((u==27)|(u==28)|(u==29)|(u==30)){
q35(q33(9,0,5,4));
q35(q32(22,4,0,0));
int ax=0;
if(u==27){ax=3;}
if(u==28){ax=5;}
if(u==29){ax=1;}
if(u==30){ax=0;}
q35((48<<26)|(ax<<22)|4);
q35(q32(22,4,0,1));}
o=1;}
*49320=o;
return o;}
int q48(){
int k=0;
if(*49184==6){
return 0;}
if(*49184==18){
q14();
if(*49184==6){
return 0;}
q3(12);
return 0;}
while((*49184!=6)&(*49176==0)){
if(4<=k){
q3(12);
return k;}
int d=q26();
if((d==3)|((100<=d)&(d<116))){
q3(12);
return k;}
int ns=0;
int nl=0;
if(*49184==3){
ns=*49200;
nl=*49208;
q14();}
if(*49184==13){
q14();
if(*49184!=14){
q3(12);
return k;}
q14();
d=q17(d);}
*(61800+k*8)=d;
*(61832+k*8)=ns;
*(61864+k*8)=nl;
k=k+1;
if(*49184==10){
q14();}
else{
if(*49184!=6){
q3(12);
return k;}
}
}
return k;}
int q49(int bv){
q35(q32(32,14,13,8));
q35(q32(32,5,13,0));
q35(q32(16,15,13,16));
q35(q33(10,13,5,0));
q35(q34(56));
return 0;}
int q50(){
int j=*49184;
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
if(j==7){
q14();
while((*49184!=8)&(*49184!=0)&(*49176==0)){ay=ay|q50();}
if(*49184!=8){q3(4);return ay;}
q14();
return ay;}
if((j==1)|(j==19)|(j==15)|(j==17)){bj=1;}
if(j==3){if(0<q20(*49200,*49208)){bj=1;}}
if(bj==1){
d=q26();
if(*49184!=3){q3(10);return 0;}
ns=*49200;
nl=*49208;
q14();
e=1;
if(*49184==13){
q14();
if(*49184!=4){q3(10);return 0;}
e=*49192;
q14();
if(*49184!=14){q3(10);return 0;}
q14();}
s=q43(ns,nl,d,e);
if(*49184==20){
if(1<e){q3(9);return 0;}
q14();
ae=q47(1);
if(q42(d,ae)==0){q3(9);return 0;}
q46(s,d);}
if(*49184!=9){q3(10);return 0;}
q14();
return 0;}
if(j==2){
q14();
if(*49344==3){
if(*49184!=9){q3(9);return 0;}
q14();
q35(q32(22,0,0,0));}
else{
ae=q47(1);
if(q42(*49344,ae)==0){q3(9);return 0;}
if(*49184!=9){q3(4);return 0;}
q14();
q35(q33(10,0,4,0));}
q49(0);
return 1;}
if(j==24){
q14();
if(*49184!=5){q3(4);return 0;}
q14();
ct=q47(1);
if((ct!=1)&(ct!=2)){q3(9);return 0;}
if(*49184!=6){q3(4);return 0;}
q14();
q35(q32(21,0,4,0));
bp=*49224;
q35(48<<26);
tr=q50();
if(*49184==25){
jp=*49224;
q35((48<<26)|(15<<22));
q=*49224;
v=(q-bp)>>2;
*(73728+bp)=((48<<26)|((v<<42)>>42))|((63<<26)<<32);
q14();
d=q50();
q=*49224;
v=(q-jp)>>2;
*(73728+jp)=((48<<26)|(15<<22)|((v<<42)>>42))|((63<<26)<<32);
return tr&d;}
q=*49224;
v=(q-bp)>>2;
*(73728+bp)=((48<<26)|((v<<42)>>42))|((63<<26)<<32);
return 0;}
if(j==26){
q14();
if(*49184!=5){q3(4);return 0;}
q14();
lp=*49224;
ct=q47(1);
if((ct!=1)&(ct!=2)){q3(9);return 0;}
if(*49184!=6){q3(4);return 0;}
q14();
q35(q32(21,0,4,0));
xp=*49224;
q35(48<<26);
q50();
cp=*49224;
bd=(lp-cp)>>2;
q35((48<<26)|(15<<22)|((bd<<42)>>42));
q=*49224;
v=(q-xp)>>2;
*(73728+xp)=((48<<26)|((v<<42)>>42))|((63<<26)<<32);
return 0;}
if(j==11){
q14();
at=q47(1);
dt=0;
if(q18(at)==1){dt=q19(at);}
else{if((at==1)&(*68480==1)){dt=1;}else{q3(9);return 0;}}
if((dt!=1)&(dt!=2)){q3(9);return 0;}
q35(q32(17,15,15,8));
q35(q32(33,4,15,0));
if(*49184!=20){q3(10);return 0;}
q14();
ae=q47(1);
if(q42(dt,ae)==0){q3(9);return 0;}
q35(q32(32,5,15,0));
q35(q32(16,15,15,8));
if(*49184!=9){q3(10);return 0;}
q14();
q35(q32(33+(dt==2)*4,4,5,0));
return 0;}
if(j==3){
ns=*49200;
nl=*49208;
q14();
if(*49184==5){
fi=q38(ns,nl);
if(fi<0){q3(7);return 0;}
c6=61936+fi*80;
k=*(c6+40);
ap=0;
q14();
while(ap<k){
at=q47(1);
if(q42(*(c6+48+ap*8),at)==0){q3(9);return 0;}
q35(q32(17,15,15,8));q35(q32(33,4,15,0));
ap=ap+1;
if(ap<k){if(*49184!=10){q3(12);return 0;}q14();}}
if(*49184!=6){q3(12);return 0;}
q14();
ap=0;
while(ap<k){q35(q32(32,ap,15,(k-1-ap)*8));ap=ap+1;}
if(0<k){q35(q32(16,15,15,k*8));}
cp=*49224;
q35(50<<26);
if(*(c6+24)==1){q36(cp,*(c6+16));}else{q41(cp,fi);}
if(*49184!=9){q3(10);return 0;}
q14();
return 0;}
if(*49184!=20){q3(10);return 0;}
vi=q44(ns,nl);
if(vi<0){q3(9);return 0;}
vb=60520+vi*40;
vt=*(vb+16);
s=*(vb+24);
if(1<*(vb+32)){q3(9);return 0;}
q14();
ae=q47(1);
if(q42(vt,ae)==0){q3(9);return 0;}
q46(s,vt);
if(*49184!=9){q3(10);return 0;}
q14();
return 0;}
q3(10);
return 0;}
int q51(int c5,int bn){
int w=q16(bn+16,16);
int bc=(63<<26)<<32;
int a=73728+c5;
*a=q32(17,15,15,w)|bc;
*(a+8)=q32(33,14,15,w-8)|bc;
*(a+16)=q32(33,13,15,w-16)|bc;
*(a+24)=q32(16,13,15,w-16)|bc;
return w;}
int q52(int fi,int k){
int c6=61936+fi*80;
*49288=0;
*49296=0;
int c=0;
while(c<k){
int ns=*(61832+c*8);
int nl=*(61864+c*8);
int d=*(61800+c*8);
int s=q43(ns,nl,d,1);
*(61900+c*8)=s;
c=c+1;}
int c5=*49224;
q35(q34(63));q35(q34(63));q35(q34(63));q35(q34(63));
c=0;
while(c<k){q35(q32(33,c,13,*(61900+c*8)));c=c+1;}
int ay=0;
while((*49184!=8)&(*49184!=0)&(*49176==0)){ay=ay|q50();}
q51(c5,*49296);
if(*49184!=8){q3(4);return 0;}
q14();
if(ay==0){q3(4);return 0;}
return 0;}
int q53(int w,int ns,int nl){
*49344=w;
if(((100<=w)&(w<116))==1){
q3(12);
return 0;}
if(*49184!=5){
q3(10);
return 0;}
q14();
int k=q48();
*49352=k;
if(*49184!=6){
q3(12);
return 0;}
q14();
if(*49184==9){
q40(ns,nl,0,0);
q14();
return 0;}
if(*49184!=7){
q3(10);
return 0;}
int c=0;
while(c<k){
if(*(61832+c*8)==0){
q3(12);
return 0;}
c=c+1;}
int fi=q40(ns,nl,1,*49224);
q14();
q52(fi,k);
return 0;}
int q54(){
if(*49184==16){
q14();
int d=q26();
if(*49184!=3){
q3(10);
return 0;}
int bx=*49200;
int by=*49208;
q14();
if(*49184!=9){
q3(10);
return 0;}
q14();
q21(bx,by,d);
return 0;}
if(*49184==15){
q14();
if(*49184!=3){
q3(10);
return 0;}
int bz=*49200;
int ca=*49208;
q14();
if(*49184!=7){
q3(10);
return 0;}
return q28(bz,ca);}
if(*49184==17){
q14();
if(*49184!=3){
q3(10);
return 0;}
int cb=*49200;
int cc=*49208;
q14();
if(*49184!=7){
q3(10);
return 0;}
return q31(cb,cc);}
int w=q26();
if(*49184!=3){
q3(10);
return 0;}
int cd=*49200;
int cf=*49208;
q14();
if(*49184!=5){
q3(14);
return 0;}
return q53(w,cd,cf);}
int q55(int i){
int c=*49224;
if(*68472<c+8){
q3(8);
return 0;}
*(73728+c)=i;
*49224=c+8;
return 0;}
int q56(int fi){
int i=0;
int p=0;
while(p<fi){
int c6=61936+p*80;
if(*(c6+24)!=0){
i=i+1;}
p=p+1;}
return i;}
int q57(int d){
while(1000<=d){
d=d-1000;}
if((d==1)|(d==2)|(d==3)){
return 1;}
return 0;}
int q58(int fi){
int c6=61936+fi*80;
int a2=*c6;
int ln=*(c6+8);
q55(ln);
int n=0;
while(n<8){
int wd=0;
int c=0;
while(c<8){
int at=n*8+c;
if(at<ln){
wd=wd|(q0(a2+at)<<(c*8));}
c=c+1;}
q55(wd);
n=n+1;}
int e=*(c6+24);
int rt=*(c6+32);
if(q57(rt)==0){
q3(16);
return 0;}
int qi=0;
while(qi<*(c6+40)){
if(q57(*(c6+48+qi*8))==0){
q3(16);
return 0;}
qi=qi+1;}
q55(e);
q55(1);
if(e==1){
q55(1);
q55(*(c6+16)-112);}
else{
q55(0);
q55(0);}
q55(0);
q55(rt);
q55(*(c6+40));
int p=0;
while(p<4){
if(p<*(c6+40)){
q55(*(c6+48+p*8));}
else{
q55(0);}
p=p+1;}
return 0;}
int q59(){
int nc=*49248;
int p=0;
while(p<nc){
int b=52584+p*16;
int fx=*(b+8);
int t=61936+fx*80;
if(*(t+24)==1){
q36(*b,*(t+16));}
else{
if(*(t+24)!=2){
q3(7);
return 0;}
}
p=p+1;}
int ce=*49224;
if(ce<=112){
q3(15);
return 0;}
int so=ce;
int f=*49240;
int sc=0;
p=0;
while(p<f){
int t2=61936+p*80;
if(*(t2+24)!=0){
q58(p);
sc=sc+1;}
p=p+1;}
int ro=*49224;
int g=0;
p=0;
while(p<nc){
int b2=52584+p*16;
int f2=*(b2+8);
int t3=61936+f2*80;
if(*(t3+24)==2){
q55(1);
q55(*b2-112);
q55(8);
q55(1);
q55(q56(f2));
q55(0);
g=g+1;}
p=p+1;}
int cg=*49224;
int mg=65|(78<<8)|(75<<16)|(65<<24)|(79<<32)|(77<<40)|(49<<48);
*73728=mg;
*73736=1;
*73744=112;
*73752=cg;
*73760=112;
*73768=ce-112;
*73776=8;
*73784=ce;
*73792=0;
*73800=8;
*73808=so;
*73816=sc;
*73824=ro;
*73832=g;
return 0;}
int main(){
int ag=28672;
int be=*ag;
if(20472<be){
return 0-1;}
*49152=0;
*49160=be;
*49168=ag+8;
*49176=0;
*49184=0;
*49192=0;
*49200=0;
*49208=0;
*49224=112;
*49240=0;
*49248=0;
*49264=0;
*49272=0;
*49280=0;
*49288=0;
*49296=0;
*49312=0;
*49320=0;
*49344=0;
*49352=0;
*49360=0;
*68456=*68472;
q14();
while((*49184!=0)&(*49176==0)){
q54();}
if(*49176==0){
q59();}
if(*49176!=0){
return 0-1;}
int ci=syscall(5,73728,0,0);
return 0;}
