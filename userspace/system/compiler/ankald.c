int rb(int addr){
int a=addr&(0-8);
int w=*a;
int s=(addr&7)*8;
return(w>>s)&255;
}

int wb(int addr,int byte){
int a=addr&(0-8);
int s=(addr&7)*8;
int w=*a;
int mask=255<<s;
w=(w&((0-1)-mask))|((byte&255)<<s);
*a=w;
return 0;
}

int pow2(int a){
if(a<=0){return 0;}
if((a&(a-1))!=0){return 0;}
return 1;
}

int alignup(int value,int a){
if(pow2(a)==0){return 0-1;}
int x=value+a-1;
if(x<value){return 0-1;}
return x&((0-1)-(a-1));
}

int pubtype(int t){
if(t<0){return 0;}
int scale=1000;
while(scale<=(t>>1)){scale=scale<<1;}
while(1000<=scale){if(scale<=t){t=t-scale;}scale=scale>>1;}
if(t==1){return 1;}
if(t==2){return 1;}
if(t==3){return 1;}
return 0;
}

int firstc(int ch){
if((65<=ch)&(ch<=90)){return 1;}
if((97<=ch)&(ch<=122)){return 1;}
if(ch==95){return 1;}
return 0;
}

int restc(int ch){
if(firstc(ch)==1){return 1;}
if((48<=ch)&(ch<=57)){return 1;}
return 0;
}

int nameeq(int a,int alen,int b,int blen){
if(alen!=blen){return 0;}
int i=0;
while(i<alen){
if(rb(a+i)!=rb(b+i)){return 0;}
i=i+1;
}
return 1;
}

int tbase(int b){return b+*(b+96)+*(b+104)*48;}
int teq(int a,int b,int n){int i=0;while(i<n){if(rb(a+i)!=rb(b+i)){return 0;}i=i+1;}return 1;}
int tname(int a){if(firstc(rb(a))==0){return 0;}int i=1;while((i<64)&(rb(a+i)!=0)){if(restc(rb(a+i))==0){return 0;}i=i+1;}if(i==64){return 0;}while(i<64){if(rb(a+i)!=0){return 0;}i=i+1;}return 1;}
int tfind(int b,int tag){int h=tbase(b);int d=h+40;int i=0;while(i<*(h+24)){if(teq(d,tag,64)==1){return d;}d=d+112+*(d+88)*160;i=i+1;}return 0;}
int tfuns(int b){int h=tbase(b);int d=h+40;int i=0;while(i<*(h+24)){d=d+112+*(d+88)*160;i=i+1;}return d;}
int trefok(int b,int r){int kind=*r;int depth=*(r+8);if((kind<1)|(4<kind)|(depth<0)|(63<depth)){return 0;}if(kind==4){if(tname(r+16)==0){return 0;}if(tfind(b,r+16)==0){return 0;}}else{int i=0;while(i<64){if(rb(r+16+i)!=0){return 0;}i=i+1;}}return 1;}
int tproduct(int a,int b,int limit){if((a<0)|(b<0)|(limit<0)){return 0-1;}int total=0;while(b!=0){if((b&1)!=0){if(limit-total<a){return 0-1;}total=total+a;}b=b>>1;if(b!=0){if(limit-a<a){return 0-1;}a=a+a;}}return total;}
int tvalid(int b,int n){
int h=0;
int end=0;
int dc=0;
int fc=0;
int d=0;
int i=0;
int total=0;
int fields=0;
int complete=0;
int old=0;
int j=0;
int used=0;
int alignment=0;
int rank=0;
int f=0;
int k=0;
int size=0;
int al=0;
int child=0;
int c=0;
int off=0;
int bytes=0;
int sym=0;
int count=0;
int lane=0;
int r=0;
int wire=0;
int want=0;
if(*(b+8)==1){return 1;}
h=tbase(b);end=b+n;
if(end-h<40){return 0;}
if(*h!=(20033|(16715<<16)|(22868<<32)|(49<<48))){return 0;}
if((*(h+8)!=1)|(*(h+16)!=end-h)){return 0;}
dc=*(h+24);fc=*(h+32);
if((dc<=0)|(4096<dc)|(fc<0)|(4096<fc)|(fc!=*(b+88))){return 0;}
d=h+40;i=0;total=0;
while(i<dc){
if(end-d<112){return 0;}fields=*(d+88);
if((fields<0)|(4096-total<fields)){return 0;}total=total+fields;
if(end-d-112<fields*160){return 0;}
if((tname(d)==0)|(*(d+104)!=0)){return 0;}
complete=*(d+64);
if(complete==0){if((*(d+72)!=0)|(*(d+80)!=0)|(fields!=0)|(*(d+96)!=0)){return 0;}}
else{if((complete!=1)|(*(d+72)<=0)|(fields==0)|(*(d+96)<=0)|(dc<*(d+96))|(16<*(d+80))|(pow2(*(d+80))==0)){return 0;}}
old=h+40;j=0;while(j<i){if(teq(d,old,64)==1){return 0;}old=old+112+*(old+88)*160;j=j+1;}
d=d+112+fields*160;i=i+1;}
if(end-d!=fc*480){return 0;}
d=h+40;i=0;
while(i<dc){used=0;alignment=1;rank=1;j=0;
while(j<*(d+88)){
f=d+112+j*160;
if((tname(f)==0)|(trefok(b,f+64)==0)){return 0;}
k=0;while(k<j){if(teq(f,d+112+k*160,64)==1){return 0;}k=k+1;}
size=0;al=1;child=0;
if(*(f+72)!=0){size=16;al=16;}
else{if(*(f+64)==1){size=8;al=8;}if(*(f+64)==2){size=1;}
if(*(f+64)==4){c=tfind(b,f+80);if(*(c+64)!=1){return 0;}size=*(c+72);al=*(c+80);child=*(c+96);}}
if((size<=0)|(*(d+96)<=child)|(*(f+152)<=0)){return 0;}
if(rank<child+1){rank=child+1;}
off=alignup(used,al);if((off<0)|(off!=*(f+144))){return 0;}
bytes=tproduct(size,*(f+152),((32767<<48)|(65535<<32)|(65535<<16)|65535)-off);if(bytes<0){return 0;}used=off+bytes;
if(alignment<al){alignment=al;}j=j+1;}
if(*(d+64)==1){if((alignup(used,alignment)!=*(d+72))|(alignment!=*(d+80))|(rank!=*(d+96))){return 0;}}
d=d+112+*(d+88)*160;i=i+1;}
i=0;while(i<fc){f=d+i*480;sym=b+*(b+80)+i*160;
if((teq(f,sym+8,64)==0)|(*(f+64)!=*(sym+72))|(*(f+72)!=*(sym+120))){return 0;}
count=*(f+72);if((count<0)|(4<count)){return 0;}
j=0;lane=0;
while(j<5){r=f+80+j*80;
if(count<j){k=0;while(k<80){if(rb(r+k)!=0){return 0;}k=k+1;}}
else{if(trefok(b,r)==0){return 0;}
if((*(r+8)==0)&((*r==4)|((0<j)&(*r==3)))){return 0;}
wire=*(r+8)*1000+*r;want=*(sym+112);if(j!=0){want=*(sym+120+j*8);}
if(wire!=want){return 0;}
if(j!=0){if(*(r+8)!=0){lane=alignup(lane,2)+2;}else{lane=lane+1;}if(4<lane){return 0;}}}
j=j+1;}i=i+1;}
return 1;}

int modbase(int i){
int d=*(131000+80);
return *(d+i*16);
}

int symbase(int m,int s){
int b=modbase(m);
return b+*(b+80)+s*160;
}

int vhead(int b,int n){
if(n<112){return 0;}
if(rb(b)!=65){return 0;}
if(rb(b+1)!=78){return 0;}
if(rb(b+2)!=75){return 0;}
if(rb(b+3)!=65){return 0;}
if(rb(b+4)!=79){return 0;}
if(rb(b+5)!=77){return 0;}
if(rb(b+6)!=49){return 0;}
if(rb(b+7)!=0){return 0;}
if((*(b+8)!=1)&(*(b+8)!=2)){return 0;}
if(*(b+16)!=112){return 0;}
if(*(b+24)!=n){return 0;}
int co=*(b+32);
int cs=*(b+40);
int ca=*(b+48);
int ro=*(b+56);
int rs=*(b+64);
int ra=*(b+72);
int so=*(b+80);
int sc=*(b+88);
int xo=*(b+96);
int xc=*(b+104);
if((co<0)|(ro<0)|(rs<0)|(so<0)|(xo<0)|(sc<0)|(xc<0)|(n<so)|(n<xo)){return 0;}
if(co!=112){return 0;}
if(cs<=0){return 0;}
if((cs&7)!=0){return 0;}
if((ca<8)|(pow2(ca)==0)){return 0;}
if((co&(ca-1))!=0){return 0;}
if((ra<8)|(pow2(ra)==0)){return 0;}
if((ro&(ra-1))!=0){return 0;}
if(((so&7)!=0)|((xo&7)!=0)){return 0;}
int ce=co+cs;
if(ce<co){return 0;}
int re=ro+rs;
if(re<ro){return 0;}
if(ro<ce){return 0;}
if(so<re){return 0;}
if(((n-so)>>3)<sc){return 0;}
int sx=so+sc*160;
if(sx<so){return 0;}
if(xo!=sx){return 0;}
if(((n-xo)>>3)<xc){return 0;}
int xe=xo+xc*48;
if(xe<xo){return 0;}
if((n<xe)|(xe<0)){return 0;}
if((*(b+8)==1)&(xe!=n)){return 0;}
if((*(b+8)==2)&(n-xe<40)){return 0;}
return 1;
}

int vsyms(int b,int n){
int cs=*(b+40);
int so=*(b+80);
int sc=*(b+88);
int s=0;
while(s<sc){
int q=b+so+s*160;
int nl=*q;
if((nl<=0)|(63<nl)){return 0;}
if(firstc(rb(q+8))==0){return 0;}
int p=1;
while(p<nl){if(restc(rb(q+8+p))==0){return 0;}p=p+1;}
while(p<64){if(rb(q+8+p)!=0){return 0;}p=p+1;}
int bind=*(q+72);
int kind=*(q+80);
int sec=*(q+88);
int val=*(q+96);
int size=*(q+104);
int rt=*(q+112);
int ac=*(q+120);
if(kind!=1){return 0;}
if(4<ac){return 0;}
if((pubtype(rt)==0)&(*(b+8)!=2)){return 0;}
if(bind==1){
if(sec!=1){return 0;}
if((val<0)|(cs<=val)|((val&7)!=0)){return 0;}
}else{
if(bind!=2){return 0;}
if((sec!=0)|(val!=0)|(size!=0)){return 0;}
}
p=0;
while(p<ac){int pt=*(q+128+p*8);if((pt==3)|((pubtype(pt)==0)&(*(b+8)!=2))){return 0;}p=p+1;}
while(p<4){if(*(q+128+p*8)!=0){return 0;}p=p+1;}
int t=s+1;
while(t<sc){
int z=b+so+t*160;
if(nameeq(q+8,nl,z+8,*z)==1){return 0;}
t=t+1;
}
s=s+1;
}
return 1;
}

int vreloc(int b,int n){
int cs=*(b+40);
int so=*(b+80);
int sc=*(b+88);
int xo=*(b+96);
int xc=*(b+104);
int r=0;
while(r<xc){
int q=b+xo+r*48;
int sec=*q;
int off=*(q+8);
int width=*(q+16);
int kind=*(q+24);
int si=*(q+32);
if((sec!=1)|(width!=8)|(kind!=1)){return 0;}
if((off&7)!=0){return 0;}
if((cs<off)|(cs-off<8)){return 0;}
if(sc<=si){return 0;}
if(*(b+so+si*160+72)!=2){return 0;}
r=r+1;
}
return 1;
}

int validmod(int m){
int d=*(131000+80);
int b=*(d+m*16);
int n=*(d+m*16+8);
if(vhead(b,n)==0){return 0;}
if(vsyms(b,n)==0){return 0;}
if(tvalid(b,n)==0){return 0;}
if(vreloc(b,n)==0){return 0;}
return 1;
}

int tsymbol(int sym){int m=0;while(m<*(131000+72)){int b=modbase(m);int i=0;while(i<*(b+88)){if(symbase(m,i)==sym){if(*(b+8)==1){return 0;}return tfuns(b)+i*480;}i=i+1;}m=m+1;}return 0;}
int tpairs(){int m=0;while(m<*(131000+72)){int b=modbase(m);if(*(b+8)==2){int d=tbase(b)+40;int i=0;while(i<*(tbase(b)+24)){int n=0;while(n<m){int peer=modbase(n);if(*(peer+8)==2){int other=tfind(peer,d);if(other!=0){if((*(d+64)==1)&(*(other+64)==1)){if(*(d+88)!=*(other+88)){return 0;}if(teq(d,other,112+*(d+88)*160)==0){return 0;}}}}n=n+1;}d=d+112+*(d+88)*160;i=i+1;}}m=m+1;}return 1;}
int sigsame(int a,int b){
int ta=tsymbol(a);int tb=tsymbol(b);if((ta!=0)&(tb!=0)){if(teq(ta+72,tb+72,408)==0){return 0;}}
if(*(a+80)!=*(b+80)){return 0;}
if(*(a+112)!=*(b+112)){return 0;}
int ac=*(a+120);
if(ac!=*(b+120)){return 0;}
int p=0;
while(p<ac){if(*(a+128+p*8)!=*(b+128+p*8)){return 0;}p=p+1;}
return 1;
}


int findexp(int imp,int want){
int mc=*(131000+72);
int count=0;
int fm=0-1;
int fs=0-1;
int il=*imp;
int m=0;
while(m<mc){
int b=modbase(m);
int sc=*(b+88);
int s=0;
while(s<sc){
int q=symbase(m,s);
if(*(q+72)==1){
if(nameeq(imp+8,il,q+8,*q)==1){count=count+1;fm=m;fs=s;}
}
s=s+1;
}
m=m+1;
}
if(want==0){return count;}
if(want==1){return fm;}
return fs;
}

int alldefs(){
int mc=*(131000+72);
int m=0;
while(m<mc){
int b=modbase(m);
int sc=*(b+88);
int s=0;
while(s<sc){
int q=symbase(m,s);
if(*(q+72)==1){if(findexp(q,0)!=1){return 0;}}
s=s+1;
}
m=m+1;
}
return 1;
}

int importsok(){
int mc=*(131000+72);
int m=0;
while(m<mc){
int b=modbase(m);
int sc=*(b+88);
int s=0;
while(s<sc){
int q=symbase(m,s);
if(*(q+72)==2){
int count=findexp(q,0);
if(count==0){return 4;}
if(count!=1){return 3;}
int em=findexp(q,1);
int es=findexp(q,2);
if(sigsame(q,symbase(em,es))==0){return 5;}
}
s=s+1;
}
m=m+1;
}
return 0;
}

int pmode(int m){
int b=modbase(m);
return ((*(b+112)<<32)>>58)==44;
}

int pmeta(int m){int b=modbase(m);return b+*(b+56);}

int pframe(int m,int index){
int q=pmeta(m)+32;
int i=0;
while(i<index){q=q+32+*(q+24)*32;i=i+1;}
return q;
}

int preloc(int m,int off){
int b=modbase(m);
int r=0;
int found=0;
while(r<*(b+104)){
int q=b+*(b+96)+r*48;
if(*(q+8)==off){if(found!=0){return 0-1;}found=q;}
r=r+1;
}
return found;
}

int pvalid(int m){
int b=modbase(m);
int cs=*(b+40);
int rs=*(b+64);
int limit=1<<18;
if(*(131000+160)==2){limit=1<<20;}
if(*(131000+160)==3){limit=1<<21;}
if((limit<*(b+24))|(rs<64)){return 0;}
if(*(b+56)!=112+cs){return 0;}
if(*(b+80)!=*(b+56)+rs){return 0;}
int h=pmeta(m);
if((*h!=(12343|(20529<<16)))|(*(h+8)!=2)|(*(h+16)!=cs)){return 0;}
int count=*(h+24);
if((count<=0)|(4096<count)){return 0;}
int end=h+rs;
int q=h+32;
int i=0;
int covered=0;
while(i<count){
if(end-q<32){return 0;}
int start=*q;
int stop=*(q+8);
int n=*(q+24);
if((n<0)|(4096<n)){return 0;}
if(((end-q-32)>>5)<n){return 0;}
if((start<0)|(stop<=start)|(cs<stop)|((start&7)!=0)|((stop&7)!=0)){return 0;}
if(*(b+112+start)!=((44<<26)|i|((63<<26)<<32))){return 0;}
int j=0;
while(j<i){
int other=pframe(m,j);
if((start<*(other+8))&(*other<stop)){return 0;}
j=j+1;
}
covered=covered+stop-start;
if(cs<covered){return 0;}
q=q+32+n*32;
i=i+1;
}
if((q!=end)|(covered!=cs)){return 0;}
int s=0;
int f=0;
while(s<*(b+88)){
int sym=symbase(m,s);
int lane=0;
int p=0;
while(p<*(sym+120)){
if(1000<=*(sym+128+p*8)){lane=alignup(lane,2)+2;}else{lane=lane+1;}
p=p+1;
}
if(4<lane){return 0;}
if(*(sym+72)==1){
if(count<=f){return 0;}
if(*(sym+96)!=*pframe(m,f)){return 0;}
f=f+1;
}
s=s+1;
}
if(f!=count){return 0;}
int r=0;
while(r<*(b+104)){
int rel=b+*(b+96)+r*48;
int off=*(rel+8);
if((*(rel+40)!=0)|(preloc(m,off)!=rel)){return 0;}
if(*(b+112+off)!=((50<<26)|((63<<26)<<32))){return 0;}
r=r+1;
}
int pc=0;
while(pc<cs){
int slot=*(b+112+pc);
if((slot>>32)!=(63<<26)){return 0;}
int word=(slot<<32)>>32;
int op=word>>26;
if(op==44){
int index=word&((1<<26)-1);
if(count<=index){return 0;}
if(*pframe(m,index)!=pc){return 0;}
}
if(op==50){
if((word>>22)!=(50<<4)){return 0;}
if(preloc(m,pc)==0){
int disp=word&((1<<22)-1);
if((1<<21)<=disp){disp=disp-(1<<22);}
int target=pc+disp*4;
int matches=0;
i=0;
while(i<count){if(*pframe(m,i)==target){matches=matches+1;}i=i+1;}
if(matches!=1){return 0;}
}
}
pc=pc+8;
}
return 1;
}

int pprofile(){
int limit=1<<20;
if(*(131000+160)==3){limit=1<<21;}
int mode=pmode(0);
int mc=*(131000+72);
int m=0;
int code=0;
int metadata=32;
int frames=0;
while(m<mc){
if(pmode(m)!=mode){return 0-1;}
if(mode==1){
if(pvalid(m)==0){return 0-1;}
int b=modbase(m);
int cs=*(b+40);
int rs=*(b+64)-32;
int fc=*(pmeta(m)+24);
if((code&(*(b+48)-1))!=0){return 0-1;}
if(((limit-code)<cs)|((limit-metadata)<rs)|((4096-frames)<fc)){return 0-1;}
code=code+cs;metadata=metadata+rs;frames=frames+fc;
}
m=m+1;
}
if(limit-code<metadata){return 0-1;}
return frames;
}

int codebase(int index){
int cur=0;
int m=0;
while(m<=index){
int b=modbase(m);
cur=alignup(cur,*(b+48));
if(cur<0){return 0-1;}
if(m==index){return cur;}
int next=cur+*(b+40);
if(next<cur){return 0-1;}
cur=next;
m=m+1;
}
return 0-1;
}

int codesize(){
int mc=*(131000+72);
int cur=0;
int m=0;
while(m<mc){
int b=modbase(m);
cur=alignup(cur,*(b+48));
if(cur<0){return 0-1;}
int next=cur+*(b+40);
if(next<cur){return 0-1;}
cur=next;
m=m+1;
}
return cur;
}

int robase(int index){
int cur=codesize();
if(cur<0){return 0-1;}
int m=0;
while(m<=index){
int b=modbase(m);
int rs=*(b+64);
if(0<rs){
cur=alignup(cur,*(b+72));
if(cur<0){return 0-1;}
if(m==index){return cur;}
int next=cur+rs;
if(next<cur){return 0-1;}
cur=next;
}else{
if(m==index){return 0;}
}
m=m+1;
}
return 0;
}

int imagegeom(int want){
int mc=*(131000+72);
int cur=codesize();
if(cur<0){return 0-1;}
if(pmode(0)==1){
if(want==0){return cur;}
cur=cur+32;
int index=0;
while(index<mc){int b0=modbase(index);cur=cur+*(b0+64)-32;index=index+1;}
return cur;
}
int lit=0;
int m=0;
while(m<mc){
int b=modbase(m);
int rs=*(b+64);
if(0<rs){
cur=alignup(cur,*(b+72));
if(cur<0){return 0-1;}
if(lit==0){lit=cur;}
int next=cur+rs;
if(next<cur){return 0-1;}
cur=next;
}
m=m+1;
}
if(want==0){return lit;}
return cur;
}


int findentry(int want){
int ep=*(131000+104);
int el=*(131000+112);
int mc=*(131000+72);
int count=0;
int fm=0-1;
int fs=0-1;
int m=0;
while(m<mc){
int b=modbase(m);
int sc=*(b+88);
int s=0;
while(s<sc){
int q=symbase(m,s);
if(*(q+72)==1){
if(nameeq(ep,el,q+8,*q)==1){count=count+1;fm=m;fs=s;}
}
s=s+1;
}
m=m+1;
}
if(want==0){return count;}
if(want==1){return fm;}
return fs;
}

int relocsok(){
int mc=*(131000+72);
int m=0;
while(m<mc){
int b=modbase(m);
int xo=*(b+96);
int xc=*(b+104);
int r=0;
while(r<xc){
int q=b+xo+r*48;
if(*(q+40)!=0){return 6;}
int si=*(q+32);
int imp=symbase(m,si);
if(findexp(imp,0)!=1){return 6;}
int em=findexp(imp,1);
int es=findexp(imp,2);
int exp=symbase(em,es);
if(sigsame(imp,exp)==0){return 6;}
int patch=codebase(m)+*(q+8);
int target=codebase(em)+*(exp+96);
if((patch<0)|(target<0)){return 6;}
if((patch&3)!=0){return 6;}
if((target&3)!=0){return 6;}
if(patch<=target){
if(((1<<23)-4)<target-patch){return 6;}
}else{
if((1<<23)<patch-target){return 6;}
}
r=r+1;
}
m=m+1;
}
return 0;
}

int zeroout(int size){
int out=*(131000+88);
int p=0;
while(p<size){
wb(out+p,0);
p=p+1;
}
return 0;
}

int copysecs(){
int out=*(131000+88);
int mc=*(131000+72);
int m=0;
while(m<mc){
int b=modbase(m);
int cb=codebase(m);
int cs=*(b+40);
int co=*(b+32);
int p=0;
while(p<cs){*(out+cb+p)=*(b+co+p);p=p+8;}
int rs=*(b+64);
if((0<rs)&(pmode(0)==0)){
int rb0=robase(m);
int ro=*(b+56);
p=0;
while(p<rs){wb(out+rb0+p,rb(b+ro+p));p=p+1;}
}
m=m+1;
}
return 0;
}

int pmerge(int frames){
int out=*(131000+88);
int cs=codesize();
int dest=out+cs;
*dest=12343|(20529<<16);*(dest+8)=2;*(dest+16)=cs;*(dest+24)=frames;
dest=dest+32;
int prefix=0;
int m=0;
while(m<*(131000+72)){
int base=codebase(m);
int count=*(pmeta(m)+24);
int i=0;
while(i<count){
int src=pframe(m,i);
int size=32+*(src+24)*32;
*dest=*src+base;*(dest+8)=*(src+8)+base;
int p=16;
while(p<size){*(dest+p)=*(src+p);p=p+8;}
*(out+base+*src)=(44<<26)|(prefix+i)|((63<<26)<<32);
dest=dest+size;
i=i+1;
}
prefix=prefix+count;
m=m+1;
}
return 0;
}

int patchall(){
int out=*(131000+88);
int mc=*(131000+72);
int m=0;
while(m<mc){
int b=modbase(m);
int xo=*(b+96);
int xc=*(b+104);
int r=0;
while(r<xc){
int q=b+xo+r*48;
int imp=symbase(m,*(q+32));
int em=findexp(imp,1);
int es=findexp(imp,2);
int exp=symbase(em,es);
int patch=codebase(m)+*(q+8);
int target=codebase(em)+*(exp+96);
int disp=(target>>2)-(patch>>2);
int word=(50<<26)|((disp<<42)>>42);
int padded=word|((63<<26)<<32);
*(out+patch)=padded;
r=r+1;
}
m=m+1;
}
return 0;
}

int fail(int code){
*(131000+120)=code;
return code;
}

int main(){
int mc=*(131000+72);
if(mc<=0){return fail(1);}
int profile=*(131000+160);
if((profile!=0)&(profile!=2)&(profile!=3)){return fail(9);}
int d=*(131000+80);
int out=*(131000+88);
int cap=*(131000+96);
int ep=*(131000+104);
int el=*(131000+112);
if((d<=0)|(out<=0)|(cap<=0)|(ep<=0)){return fail(1);}
if((el<=0)|(63<el)){return fail(8);}
if(firstc(rb(ep))==0){return fail(8);}
int p=1;
while(p<el){if(restc(rb(ep+p))==0){return fail(8);}p=p+1;}
int m=0;
while(m<mc){if(validmod(m)==0){return fail(2);}m=m+1;}
if(profile==2){if((mc!=1)|(pmode(0)!=1)){return fail(9);}}
if(profile==3){if(pmode(0)!=1){return fail(9);}}
int pf=pprofile();
if(pf<0){return fail(9);}
if(tpairs()==0){return fail(9);}
if(alldefs()==0){return fail(3);}
int ir=importsok();
if(ir!=0){return fail(ir);}
int cs=codesize();
int lit=imagegeom(0);
int ims=imagegeom(1);
if((cs<=0)|(ims<cs)|(ims<0)){return fail(7);}
if(cap<ims){return fail(7);}
if(findentry(0)!=1){return fail(8);}
int em=findentry(1);
int es=findentry(2);
int ent=codebase(em)+*(symbase(em,es)+96);
if((ent<0)|(cs<=ent)|((ent&7)!=0)){return fail(8);}
if(0<pf){
if((ent!=0)|(el!=4)){return fail(8);}
if((rb(ep)!=109)|(rb(ep+1)!=97)|(rb(ep+2)!=105)|(rb(ep+3)!=110)){return fail(8);}
int entrysym=symbase(em,es);
if(*(entrysym+112)!=1){return fail(8);}
if(profile==2){
if((*(entrysym+120)!=2)|(*(entrysym+128)!=2001)|(*(entrysym+136)!=1001)){return fail(8);}
}else{
if(*(entrysym+120)!=0){return fail(8);}
}
}
int rr=relocsok();
if(rr!=0){return fail(rr);}
zeroout(ims);
copysecs();
if(0<pf){pmerge(pf);}
patchall();
*(131000+128)=cs;
*(131000+136)=lit;
*(131000+144)=ent;
*(131000+152)=ims;
*(131000+120)=0;
return 0;
}
