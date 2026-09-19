int readbyte(int pos){
int aligned=pos&(0-8);
int word=*(*49168+aligned);
int shift=(pos&7)*8;
return(word>>shift)&255;
}

int peekchar(){
int pos=*49152;
if(*49160<=pos){
return 0;
}
return readbyte(pos);
}

int advance(){
*49152=*49152+1;
return 0;
}

int seterror(int code){
if(*49176==0){
*49176=code;
}
return 0;
}

int skipspace(){
int ch=peekchar();
while((0<ch)&(ch<=32)){
advance();
ch=peekchar();
}
return 0;
}

int firstchar(int ch){
int ok=0;
if((65<=ch)&(ch<=90)){
ok=1;
}
if((97<=ch)&(ch<=122)){
ok=1;
}
if(ch==95){
ok=1;
}
return ok;
}

int restchar(int ch){
int ok=firstchar(ch);
if((48<=ch)&(ch<=57)){
ok=1;
}
return ok;
}

int keyword(int start,int len){
int h=0;
int pos=0;
int tok=3;
while(pos<len){
h=(h<<5)|(readbyte(start+pos)-96);
pos=pos+1;
}
if((len==3)&(h==9684)){
tok=1;
}
if((len==6)&(h==(22094|(18612<<15)))){
tok=2;
}
if((len==6)&(h==(21620|(20114<<15)))){
tok=15;
}
if((len==7)&(h==(4262|(26117<<15)|(20<<30)))){
tok=16;
}
if((len==4)&(h==(15021|(5<<15)))){
tok=17;
}
if((len==4)&(h==(15652|(22<<15)))){
tok=18;
}
if((len==4)&(h==(8242|(3<<15)))){
tok=19;
}
if((len==6)&(h==(5606|(19770<<15)))){
tok=23;
}
return tok;
}

int scanident(){
int start=*49152;
int len=0;
int ch=peekchar();
while(restchar(ch)==1){
len=len+1;
if(63<len){
seterror(2);
return 0;
}
advance();
ch=peekchar();
}
*49200=start;
*49208=len;
*49184=keyword(start,len);
return 0;
}

int hexvalue(int ch){
int value=0-1;
if((48<=ch)&(ch<=57)){
value=ch-48;
}
if((65<=ch)&(ch<=70)){
value=ch-55;
}
if((97<=ch)&(ch<=102)){
value=ch-87;
}
return value;
}

int decimalfits(int start){
int part=0;
while(part<4){
int value=0;
int pos=0;
while(pos<5){
value=value*10+(readbyte(start+part*5+pos)-48);
pos=pos+1;
}

int limit=0;
if(part==0){
limit=18446;
}
if(part==1){
limit=74407;
}
if(part==2){
limit=37095;
}
if(part==3){
limit=51615;
}
if(value<limit){
return 1;
}
if(limit<value){
return 0;
}
part=part+1;
}
return 1;
}

int scandecimal(){
int value=0;
int significant=0;
int sigstart=0;
int seen=0;
int ch=peekchar();
int digit=0;
while((48<=ch)&(ch<=57)){
digit=ch-48;
if(seen==0){
if(digit!=0){
seen=1;
sigstart=*49152;
significant=1;
}
}
else{
significant=significant+1;
}
value=value*10+digit;
advance();
ch=peekchar();
}
if(20<significant){
seterror(3);
return 0;
}
if(significant==20){
if(decimalfits(sigstart)==0){
seterror(3);
return 0;
}
}
*49192=value;
*49184=4;
return 0;
}

int scanhex(){
int value=0;
int significant=0;
int seen=0;
int any=0;
int digit=0;
int ch=0;
advance();
advance();
ch=peekchar();
digit=hexvalue(ch);
while(0<=digit){
any=1;
if(seen==0){
if(digit!=0){
seen=1;
significant=1;
}
}
else{
significant=significant+1;
}
value=(value<<4)|digit;
advance();
ch=peekchar();
digit=hexvalue(ch);
}
if(any==0){
seterror(3);
return 0;
}
if(16<significant){
seterror(3);
return 0;
}
*49192=value;
*49184=4;
return 0;
}

int scannumber(){
int pos=*49152;
if(readbyte(pos)==48){
if(pos+1<*49160){
int ch=readbyte(pos+1);
if((ch==120)|(ch==88)){
return scanhex();
}
}
}
return scandecimal();
}

int nexttoken(){
skipspace();
if(*49176!=0){
*49184=0;
return 0;
}
if(*49160<=*49152){
*49184=0;
return 0;
}

int ch=peekchar();
if(firstchar(ch)==1){
return scanident();
}
if((48<=ch)&(ch<=57)){
return scannumber();
}

int tok=0;
if(ch==40){
tok=5;
}
if(ch==41){
tok=6;
}
if(ch==123){
tok=7;
}
if(ch==125){
tok=8;
}
if(ch==59){
tok=9;
}
if(ch==44){
tok=10;
}
if(ch==42){
tok=11;
}
if(ch==38){
tok=12;
}
if(ch==91){
tok=13;
}
if(ch==93){
tok=14;
}
if(ch==61){
tok=20;
}
if(ch==43){
tok=21;
}
if(ch==45){
tok=22;
}
if(tok!=0){
*49184=tok;
advance();
return 0;
}
seterror(1);
*49184=0;
return 0;
}

int nameequal(int first,int flen,int second,int slen){
if(flen!=slen){
return 0;
}

int pos=0;
while(pos<flen){
if(readbyte(first+pos)!=readbyte(second+pos)){
return 0;
}
pos=pos+1;
}
return 1;
}

int alignup(int value,int align){
return(value+align-1)&(0-align);
}

int ptrtype(int type){
return 1000+type;
}

int isptr(int type){
if(1000<=type){
return 1;
}
return 0;
}

int ptrbase(int type){
return type-1000;
}

int findalias(int start,int len){
int count=*49264;
int pos=0;
int base=0;
while(pos<count){
base=54632+pos*24;
if(nameequal(start,len,*base,*(base+8))==1){
return*(base+16);
}
pos=pos+1;
}
return 0;
}

int addalias(int start,int len,int type){
if(findalias(start,len)!=0){
seterror(10);
return 0;
}

int count=*49264;
if(32<=count){
seterror(8);
return 0;
}

int base=54632+count*24;
*base=start;
*(base+8)=len;
*(base+16)=type;
*49264=count+1;
return 0;
}

int findstr(int start,int len){
int count=*49272;
int pos=0;
int base=0;
while(pos<count){
base=55400+pos*48;
if(nameequal(start,len,*base,*(base+8))==1){
return pos;
}
pos=pos+1;
}
return 0-1;
}

int addstr(int start,int len){
int old=findstr(start,len);
if(0<=old){
return old;
}

int count=*49272;
if(16<=count){
seterror(8);
return 0-1;
}

int base=55400+count*48;
*base=start;
*(base+8)=len;
*(base+16)=*49280;
*(base+24)=0;
*(base+32)=0;
*(base+40)=1;
*49272=count+1;
return count;
}

int typesize(int type){
int size=0;
if(type==1){
size=8;
}
if(type==2){
size=1;
}
if(1000<=type){
size=8;
}
if((100<=type)&(type<116)){
int base=55400+(type-100)*48;
size=*(base+32);
}
return size;
}

int typealign(int type){
int align=1;
if(type==1){
align=8;
}
if(1000<=type){
align=8;
}
if((100<=type)&(type<116)){
int base=55400+(type-100)*48;
align=*(base+40);
}
return align;
}

int parsetyp(){
int type=0;
int tok=*49184;
if(tok==1){
type=1;
nexttoken();
}
if(tok==19){
type=2;
nexttoken();
}
if(tok==18){
type=3;
nexttoken();
}
if(tok==15){
nexttoken();
if(*49184!=3){
seterror(10);
return 0;
}

int si=findstr(*49200,*49208);
if(si<0){
seterror(10);
return 0;
}
type=100+si;
nexttoken();
}
if(tok==17){
nexttoken();
if(*49184!=3){
seterror(10);
return 0;
}

int et=findalias(*49200,*49208);
if(et!=(0-1)){
seterror(10);
return 0;
}
type=1;
nexttoken();
}
if((tok==3)&(type==0)){
type=findalias(*49200,*49208);
if(type<=0){
seterror(10);
return 0;
}
nexttoken();
}
if(type==0){
seterror(10);
return 0;
}
while(*49184==11){
type=ptrtype(type);
nexttoken();
}
return type;
}

int addfield(int start,int len,int type,int count){
int si=*49360;
int sb=55400+si*48;
int fc=*(sb+24);
int first=*(sb+16);
int pos=0;
int base=0;
while(pos<fc){
base=56168+(first+pos)*40;
if(nameequal(start,len,*base,*(base+8))==1){
seterror(10);
return 0;
}
pos=pos+1;
}

int total=*49280;
if(64<=total){
seterror(8);
return 0;
}

int al=typealign(type);
int sz=typesize(type);
if((sz==0)|(count<=0)|(1024<count)){
seterror(13);
return 0;
}

int off=alignup(*(sb+32),al);
if(8192<off+sz*count){
seterror(13);
return 0;
}
base=56168+total*40;
*base=start;
*(base+8)=len;
*(base+16)=type;
*(base+24)=off;
*(base+32)=count;
*49280=total+1;
*(sb+24)=fc+1;
*(sb+32)=off+sz*count;
if(*(sb+40)<al){
*(sb+40)=al;
}
return 0;
}

int structdf(int start,int len){
int si=addstr(start,len);
*49360=si;
if(si<0){
return 0;
}

int sb=55400+si*48;
if(0<*(sb+24)){
seterror(10);
return 0;
}
if(*49184!=7){
seterror(10);
return 0;
}
nexttoken();
while((*49184!=8)&(*49176==0)){
int type=parsetyp();
if(*49184!=3){
seterror(10);
return 0;
}

int ns=*49200;
int nl=*49208;
nexttoken();
int count=1;
if(*49184==13){
nexttoken();
if(*49184!=4){
seterror(10);
return 0;
}
count=*49192;
nexttoken();
if(*49184!=14){
seterror(10);
return 0;
}
nexttoken();
}
if(*49184!=9){
seterror(10);
return 0;
}
nexttoken();
addfield(ns,nl,type,count);
}
if(*49184!=8){
seterror(10);
return 0;
}
nexttoken();
if(*49184!=9){
seterror(10);
return 0;
}
nexttoken();
*(sb+32)=alignup(*(sb+32),*(sb+40));
return 0;
}

int addconst(int start,int len,int value){
int count=*49312;
int pos=0;
int base=0;
while(pos<count){
base=58984+pos*24;
if(nameequal(start,len,*base,*(base+8))==1){
seterror(10);
return 0;
}
pos=pos+1;
}
if(64<=count){
seterror(8);
return 0;
}
base=58984+count*24;
*base=start;
*(base+8)=len;
*(base+16)=value;
*49312=count+1;
return 0;
}

int findcon(int start,int len){
int count=*49312;
int pos=0;
int base=0;
while(pos<count){
base=58984+pos*24;
if(nameequal(start,len,*base,*(base+8))==1){
return*(base+16);
}
pos=pos+1;
}
return 0-1;
}

int enumdef(int start,int len){
addalias(start,len,0-1);
if(*49184!=7){
seterror(10);
return 0;
}
nexttoken();
int value=0;
while((*49184!=8)&(*49176==0)){
if(*49184!=3){
seterror(10);
return 0;
}

int ns=*49200;
int nl=*49208;
nexttoken();
if(*49184==20){
nexttoken();
if(*49184!=4){
seterror(10);
return 0;
}
value=*49192;
nexttoken();
}
addconst(ns,nl,value);
value=value+1;
if(*49184==10){
nexttoken();
}
}
if(*49184!=8){
seterror(10);
return 0;
}
nexttoken();
if(*49184!=9){
seterror(10);
return 0;
}
nexttoken();
return 0;
}

int enci(int op,int dest,int source,int imm){
return(op<<26)|(dest<<22)|(source<<18)|((imm<<46)>>46);
}

int encr(int op,int dest,int left,int right){
return(op<<26)|(dest<<22)|(left<<18)|(right<<14);
}

int encs(int op){
return op<<26;
}

int emit(int word){
int pos=*49224;
if(81920<pos+8){
seterror(8);
return 0;
}

int padded=word|((63<<26)<<32);
*(73728+pos)=padded;
*49224=pos+8;
return 0;
}

int patchcall(int pos,int address){
int disp=(address>>2)-(pos>>2);
int word=(50<<26)|((disp<<42)>>42);
int padded=word|((63<<26)<<32);
*(73728+pos)=padded;
return 0;
}

int emitconst(int value){
int pos=0;
int shift=0;
int nibble=0;
emit(enci(22,4,0,0));
emit(enci(22,5,0,4));
while(pos<16){
emit(encr(6,4,4,5));
shift=(15-pos)*4;
nibble=(value>>shift)&15;
emit(enci(22,0,0,nibble));
emit(encr(4,4,4,0));
pos=pos+1;
}
return 0;
}

int findfunc(int start,int len){
int count=*49240;
int pos=0;
int base=0;
while(pos<count){
base=50024+pos*80;
if(nameequal(start,len,*base,*(base+8))==1){
return pos;
}
pos=pos+1;
}
return 0-1;
}

int sigsame(int base,int rett,int argc){
if(*(base+32)!=rett){
return 0;
}
if(*(base+40)!=argc){
return 0;
}

int pos=0;
while(pos<argc){
if(*(base+48+pos*8)!=*(61800+pos*8)){
return 0;
}
pos=pos+1;
}
return 1;
}

int addfunc(int start,int len,int defined,int address){
int rett=*49344;
int argc=*49352;
int fi=findfunc(start,len);
int base=0;
if(0<=fi){
base=50024+fi*80;
if(sigsame(base,rett,argc)==0){
seterror(11);
return fi;
}
if(defined==1){
if(*(base+24)==1){
seterror(5);
return fi;
}
*(base+24)=1;
*(base+16)=address;
}
return fi;
}

int count=*49240;
if(32<=count){
seterror(8);
return 0;
}
base=50024+count*80;
*base=start;
*(base+8)=len;
*(base+16)=address;
*(base+24)=defined;
*(base+32)=rett;
*(base+40)=argc;
int pos=0;
while(pos<4){
*(base+48+pos*8)=*(61800+pos*8);
pos=pos+1;
}
*49240=count+1;
return count;
}

int addfix(int pos,int fi){
int count=*49248;
if(128<=count){
seterror(8);
return 0;
}

int base=52584+count*16;
*base=pos;
*(base+8)=fi;
*49248=count+1;
return 0;
}

int typeok(int want,int got){
if(want==got){
return 1;
}
if((want==1)&(got==2)){
return 1;
}
if((want==2)&(got==1)){
return 1;
}
return 0;
}

int addvar(int start,int len,int type,int count){
int vc=*49288;
int pos=0;
int base=0;
while(pos<vc){
base=60520+pos*40;
if(nameequal(start,len,*base,*(base+8))==1){
seterror(10);
return 0;
}
pos=pos+1;
}
if(32<=vc){
seterror(8);
return 0;
}
if((type==3)|(count<=0)){
seterror(9);
return 0;
}
if(1024<count){
seterror(13);
return 0;
}

int sz=typesize(type)*count;
int al=typealign(type);
int used=alignup(*49296,al);
int slot=sz;
if(slot<8){
slot=8;
}
used=used+slot;
if(8192<used){
seterror(13);
return 0;
}
*49296=used;
base=60520+vc*40;
*base=start;
*(base+8)=len;
*(base+16)=type;
*(base+24)=0-used;
*(base+32)=count;
*49288=vc+1;
return 0-used;
}

int findvar(int start,int len){
int vc=*49288;
int pos=0;
int base=0;
while(pos<vc){
base=60520+pos*40;
if(nameequal(start,len,*base,*(base+8))==1){
return pos;
}
pos=pos+1;
}
return 0-1;
}

int loadvar(int vi){
int base=60520+vi*40;
int type=*(base+16);
int count=*(base+32);
int off=*(base+24);
if(1<count){
emit(enci(16,4,13,off));
*49320=ptrtype(type);
return 0;
}
if((typesize(type)!=8)&(type!=2)){
seterror(9);
return 0;
}
emit(enci(32,4,13,off));
if(type==2){
emit(enci(22,5,0,255));
emit(encr(3,4,4,5));
}
*49320=type;
return 0;
}

int saveval(int off,int type){
if(type==2){
emit(enci(22,5,0,255));
emit(encr(3,4,4,5));
}
emit(enci(33,4,13,off));
return 0;
}

int parsecall(int fi){
int fb=50024+fi*80;
int argc=*(fb+40);
int pos=0;
nexttoken();
while(pos<argc){
int type=parseexpr();
if(typeok(*(fb+48+pos*8),type)==0){
seterror(9);
return 0;
}
emit(enci(17,15,15,8));
emit(enci(33,4,15,0));
pos=pos+1;
if(pos<argc){
if(*49184!=10){
seterror(12);
return 0;
}
nexttoken();
}
}
if(*49184!=6){
seterror(12);
return 0;
}
nexttoken();
pos=0;
while(pos<argc){
emit(enci(32,pos,15,(argc-1-pos)*8));
pos=pos+1;
}
if(0<argc){
emit(enci(16,15,15,argc*8));
}

int cp=*49224;
emit(50<<26);
if(*(fb+24)==1){
patchcall(cp,*(fb+16));
}
else{
addfix(cp,fi);
}
emit(encr(10,4,0,0));
*49320=*(fb+32);
return*49320;
}

int primary(){
if(*49184==4){
int value=*49192;
nexttoken();
emitconst(value);
*49320=1;
return 1;
}
if(*49184==23){
nexttoken();
if(*49184!=5){
seterror(4);
return 0;
}
nexttoken();
int stype=parsetyp();
int count=1;
if(*49184==13){
nexttoken();
if(*49184!=4){
seterror(4);
return 0;
}
count=*49192;
nexttoken();
if(*49184!=14){
seterror(4);
return 0;
}
nexttoken();
}
if(*49184!=6){
seterror(4);
return 0;
}
nexttoken();
int sz=typesize(stype);
if((sz==0)|(count<=0)|(1024<count)){
seterror(9);
return 0;
}
emitconst(sz*count);
*49320=1;
return 1;
}
if(*49184==3){
int ns=*49200;
int nl=*49208;
nexttoken();
if(*49184==5){
int fi=findfunc(ns,nl);
if(fi<0){
seterror(7);
return 0;
}
return parsecall(fi);
}

int vi=findvar(ns,nl);
if(0<=vi){
loadvar(vi);
return*49320;
}

int cv=findcon(ns,nl);
if(0<=cv){
emitconst(cv);
*49320=1;
return 1;
}
seterror(9);
return 0;
}
if(*49184==5){
nexttoken();
int etype=parseexpr();
if(*49184!=6){
seterror(4);
return 0;
}
nexttoken();
return etype;
}
seterror(4);
return 0;
}

int unary(){
if(*49184==12){
nexttoken();
if(*49184!=3){
seterror(4);
return 0;
}

int vi=findvar(*49200,*49208);
if(vi<0){
seterror(9);
return 0;
}

int vbase=60520+vi*40;
int vtype=*(vbase+16);
int off=*(vbase+24);
nexttoken();
emit(enci(16,4,13,off));
*49320=ptrtype(vtype);
return*49320;
}
if(*49184==11){
nexttoken();
int ptype=unary();
if(isptr(ptype)==0){
seterror(9);
return 0;
}

int dtype=ptrbase(ptype);
if(typesize(dtype)!=8){
seterror(9);
return 0;
}
emit(enci(32,4,4,0));
*49320=dtype;
return dtype;
}
return primary();
}

int parseexpr(){
int left=unary();
int op=0;
while((*49184==21)|(*49184==22)){
op=*49184;
emit(enci(17,15,15,8));
emit(enci(33,4,15,0));
nexttoken();
int right=unary();
emit(enci(32,5,15,0));
emit(enci(16,15,15,8));
if(((left!=1)&(left!=2))|((right!=1)&(right!=2))){
seterror(9);
return 0;
}
if(op==21){
emit(encr(1,4,5,4));
}
else{
emit(encr(2,4,5,4));
}
left=1;
}
*49320=left;
return left;
}

int params(){
int argc=0;
if(*49184==6){
return 0;
}
if(*49184==18){
nexttoken();
if(*49184==6){
return 0;
}
seterror(12);
return 0;
}
while((*49184!=6)&(*49176==0)){
if(4<=argc){
seterror(12);
return argc;
}

int type=parsetyp();
if((type==3)|((100<=type)&(type<116))){
seterror(12);
return argc;
}

int ns=0;
int nl=0;
if(*49184==3){
ns=*49200;
nl=*49208;
nexttoken();
}
if(*49184==13){
nexttoken();
if(*49184!=14){
seterror(12);
return argc;
}
nexttoken();
type=ptrtype(type);
}
*(61800+argc*8)=type;
*(61832+argc*8)=ns;
*(61864+argc*8)=nl;
argc=argc+1;
if(*49184==10){
nexttoken();
}
else{
if(*49184!=6){
seterror(12);
return argc;
}
}
}
return argc;
}

int localdec(){
int type=parsetyp();
if(*49184!=3){
seterror(10);
return 0;
}

int ns=*49200;
int nl=*49208;
nexttoken();
int count=1;
if(*49184==13){
nexttoken();
if(*49184!=4){
seterror(10);
return 0;
}
count=*49192;
nexttoken();
if(*49184!=14){
seterror(10);
return 0;
}
nexttoken();
}

int off=addvar(ns,nl,type,count);
if(*49184==20){
if(1<count){
seterror(9);
return 0;
}
nexttoken();
int got=parseexpr();
if(typeok(type,got)==0){
seterror(9);
return 0;
}
saveval(off,type);
}
if(*49184!=9){
seterror(10);
return 0;
}
nexttoken();
return 0;
}

int patchpro(int pp,int frame){
int fs=alignup(frame+16,16);
int npad=(63<<26)<<32;
int base=73728+pp;
*base=enci(17,15,15,fs)|npad;
*(base+8)=enci(33,14,15,fs-8)|npad;
*(base+16)=enci(33,13,15,fs-16)|npad;
*(base+24)=enci(16,13,15,fs-16)|npad;
return fs;
}

int epilogue(int fs){
emit(enci(32,14,15,fs-8));
emit(enci(32,13,15,fs-16));
emit(enci(16,15,15,fs));
emit(encs(56));
return 0;
}

int funcbody(int fi,int argc){
int fb=50024+fi*80;
*49288=0;
*49296=0;
int pos=0;
while(pos<argc){
int ns=*(61832+pos*8);
int nl=*(61864+pos*8);
int type=*(61800+pos*8);
int off=addvar(ns,nl,type,1);
*(61900+pos*8)=off;
pos=pos+1;
}

int pp=*49224;
emit(encs(63));
emit(encs(63));
emit(encs(63));
emit(encs(63));
pos=0;
while(pos<argc){
emit(enci(33,pos,13,*(61900+pos*8)));
pos=pos+1;
}
while((*49184!=2)&(*49184!=8)&(*49176==0)){
localdec();
}

int fs=alignup(*49296+16,16);
patchpro(pp,*49296);
if(*49184!=2){
seterror(4);
return 0;
}
nexttoken();
if(*(fb+32)==3){
if(*49184!=9){
seterror(9);
return 0;
}
nexttoken();
emit(enci(22,0,0,0));
}
else{
int got=parseexpr();
if(typeok(*(fb+32),got)==0){
seterror(9);
return 0;
}
if(*49184!=9){
seterror(4);
return 0;
}
nexttoken();
emit(encr(10,0,4,0));
}
epilogue(fs);
if(*49184!=8){
seterror(4);
return 0;
}
nexttoken();
return 0;
}

int topfunc(int rett,int ns,int nl){
*49344=rett;
if(((100<=rett)&(rett<116))==1){
seterror(12);
return 0;
}
if(*49184!=5){
seterror(10);
return 0;
}
nexttoken();
int argc=params();
*49352=argc;
if(*49184!=6){
seterror(12);
return 0;
}
nexttoken();
if(*49184==9){
addfunc(ns,nl,0,0);
nexttoken();
return 0;
}
if(*49184!=7){
seterror(10);
return 0;
}

int pos=0;
while(pos<argc){
if(*(61832+pos*8)==0){
seterror(12);
return 0;
}
pos=pos+1;
}

int fi=addfunc(ns,nl,1,*49224);
nexttoken();
funcbody(fi,argc);
return 0;
}

int topitem(){
if(*49184==16){
nexttoken();
int type=parsetyp();
if(*49184!=3){
seterror(10);
return 0;
}

int tns=*49200;
int tnl=*49208;
nexttoken();
if(*49184!=9){
seterror(10);
return 0;
}
nexttoken();
addalias(tns,tnl,type);
return 0;
}
if(*49184==15){
nexttoken();
if(*49184!=3){
seterror(10);
return 0;
}

int sns=*49200;
int snl=*49208;
nexttoken();
if(*49184!=7){
seterror(10);
return 0;
}
return structdf(sns,snl);
}
if(*49184==17){
nexttoken();
if(*49184!=3){
seterror(10);
return 0;
}

int ens=*49200;
int enl=*49208;
nexttoken();
if(*49184!=7){
seterror(10);
return 0;
}
return enumdef(ens,enl);
}

int rett=parsetyp();
if(*49184!=3){
seterror(10);
return 0;
}

int fns=*49200;
int fnl=*49208;
nexttoken();
if(*49184!=5){
seterror(14);
return 0;
}
return topfunc(rett,fns,fnl);
}

int resolve(){
int count=*49248;
int pos=0;
int base=0;
int fb=0;
while(pos<count){
base=52584+pos*16;
fb=50024+*(base+8)*80;
if(*(fb+24)!=1){
seterror(7);
return 0;
}
patchcall(*base,*(fb+16));
pos=pos+1;
}
return 0;
}

int findmain(){
int count=*49240;
int pos=0;
int fb=0;
while(pos<count){
fb=50024+pos*80;
if(*(fb+8)==4){
int ms=*fb;
if(readbyte(ms)==109){
if(readbyte(ms+1)==97){
if(readbyte(ms+2)==105){
if(readbyte(ms+3)==110){
if((*(fb+24)!=1)|(*(fb+32)!=1)|(*(fb+40)!=0)){
seterror(11);
return 0;
}
return*(fb+16);
}
}
}
}
}
pos=pos+1;
}
seterror(6);
return 0;
}

int main(){
int mode=*68464;
int source=28672;
int length=*source;
if(20472<length){
return 0-1;
}
*49152=0;
*49160=length;
*49168=source+8;
*49176=0;
*49184=0;
*49192=0;
*49200=0;
*49208=0;
*49224=0;
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
*68456=81920;
int entry=*49224;
emit(50<<26);
emit(encs(62));
nexttoken();
while((*49184!=0)&(*49176==0)){
topitem();
}
if(*49176==0){
resolve();
}

int address=0;
if(*49176==0){
address=findmain();
}
if(*49176==0){
patchcall(entry,address);
}
if(*49176!=0){
return 0-1;
}

int seal=syscall(5,73728,0,0);
if(mode==1){
return 0;
}
return syscall(6,73728,*49224,0);
}

