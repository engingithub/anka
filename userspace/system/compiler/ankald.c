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
while(1000<=t){t=t-1000;}
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
if(*(b+8)!=1){return 0;}
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
if(xe!=n){return 0;}
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
if(pubtype(rt)==0){return 0;}
if(bind==1){
if(sec!=1){return 0;}
if((val<0)|(cs<=val)|((val&7)!=0)){return 0;}
}else{
if(bind!=2){return 0;}
if((sec!=0)|(val!=0)|(size!=0)){return 0;}
}
p=0;
while(p<ac){int pt=*(q+128+p*8);if((pt==3)|(pubtype(pt)==0)){return 0;}p=p+1;}
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
if(vreloc(b,n)==0){return 0;}
return 1;
}

int sigsame(int a,int b){
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
if(0<rs){
int rb0=robase(m);
int ro=*(b+56);
p=0;
while(p<rs){wb(out+rb0+p,rb(b+ro+p));p=p+1;}
}
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
int rr=relocsok();
if(rr!=0){return fail(rr);}
zeroout(ims);
copysecs();
patchall();
*(131000+128)=cs;
*(131000+136)=lit;
*(131000+144)=ent;
*(131000+152)=ims;
*(131000+120)=0;
return 0;
}
