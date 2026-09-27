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

int cb(){return 131000+72;}
int mc(){return *cb();}
int dp(){return *(cb()+8);}
int rootp(){return *(cb()+16);}
int rootn(){return *(cb()+24);}
int outp(){return *(cb()+32);}
int outcap(){return *(cb()+40);}
int wsp(){return *(cb()+48);}
int wscap(){return *(cb()+56);}
int resp(){return *(cb()+64);}

int srcp(int i){return *(dp()+i*32);}
int srcn(int i){return *(dp()+i*32+8);}
int namep(int i){return *(dp()+i*32+16);}
int namen(int i){return *(dp()+i*32+24);}

int nameeq(int a,int an,int b,int bn){
if(an!=bn){return 0;}
int i=0;
while(i<an){if(rb(a+i)!=rb(b+i)){return 0;}i=i+1;}
return 1;
}

int findname(int p,int n,int want){
int count=0;
int index=0-1;
int i=0;
while(i<mc()){
if(nameeq(p,n,namep(i),namen(i))==1){count=count+1;index=i;}
i=i+1;
}
if(want==0){return count;}
return index;
}

int manifestok(){
int count=mc();
if(count<=0){return 0;}
if((dp()<=0)|(rootp()<=0)|(rootn()<=0)|(127<rootn())){return 0;}
if((outp()<=0)|(outcap()<=0)|(wsp()<=0)|(wscap()<264)|(resp()<=0)){return 0;}
int i=0;
while(i<count){
if(srcp(i)<=0){return 0;}
if(srcn(i)<0){return 0;}
if((namep(i)<=0)|(namen(i)<=0)|(127<namen(i))){return 0;}
int j=i+1;
while(j<count){
if(nameeq(namep(i),namen(i),namep(j),namen(j))==1){return 0;}
j=j+1;
}
i=i+1;
}
if(findname(rootp(),rootn(),0)!=1){return 0;}
return 1;
}

int fail(int code){
int r=resp();
*r=code;
return code;
}

int depth(){return *wsp();}
int active(int idx){
int d=depth();
int i=0;
while(i<d){if(*(wsp()+8+i*8)==idx){return 1;}i=i+1;}
return 0;
}

int push(int idx){
int d=depth();
if(32<=d){return 0;}
*(wsp()+8+d*8)=idx;
*wsp()=d+1;
return 1;
}

int pop(){
int d=depth();
if(d<=0){return 0;}
*wsp()=d-1;
return 1;
}

int emit(int ch){
int r=resp();
int p=*(r+8);
if(outcap()<=p){return 0;}
wb(outp()+p,ch);
*(r+8)=p+1;
return 1;
}

int ws(int ch){if((ch==32)|(ch==9)){return 1;}return 0;}

int kwinclude(int s,int p,int n){
if(n-p<7){return 0;}
if(rb(s+p)!=105){return 0;}
if(rb(s+p+1)!=110){return 0;}
if(rb(s+p+2)!=99){return 0;}
if(rb(s+p+3)!=108){return 0;}
if(rb(s+p+4)!=117){return 0;}
if(rb(s+p+5)!=100){return 0;}
if(rb(s+p+6)!=101){return 0;}
return 1;
}

int skipws(int s,int q,int n){
while(q<n){if(ws(rb(s+q))==0){return q;}q=q+1;}
return q;
}

int dirparse(int s,int p,int n,int want){
int q=skipws(s,p,n);
if(n<=q){if(want==0){return 0;}return 0-1;}
if(rb(s+q)!=35){if(want==0){return 0;}return 0-1;}
q=skipws(s,q+1,n);
if(kwinclude(s,q,n)==0){if(want==0){return 2;}return 0-1;}
q=skipws(s,q+7,n);
if(n<=q){if(want==0){return 3;}return 0-1;}
if(rb(s+q)!=34){if(want==0){return 3;}return 0-1;}
q=q+1;
int np=q;
int done=0;
while((q<n)&(done==0)){
int ch=rb(s+q);
if((ch==34)|(ch==10)|(ch==13)){done=1;}else{q=q+1;}
}
int nl=q-np;
if((nl<=0)|(127<nl)|(n<=q)){if(want==0){return 3;}return 0-1;}
if(rb(s+q)!=34){if(want==0){return 3;}return 0-1;}
q=skipws(s,q+1,n);
if(q<n){
if(rb(s+q)==13){q=q+1;}
}
if(q<n){
if(rb(s+q)!=10){if(want==0){return 3;}return 0-1;}
q=q+1;
}
if(want==0){return 1;}
if(want==1){return np;}
if(want==2){return nl;}
return q;
}

int copyline(int s,int p,int n){
int q=p;
while(q<n){
int ch=rb(s+q);
if(emit(ch)==0){return 0-1;}
q=q+1;
if(ch==10){return q;}
}
return q;
}

int expand(int idx){
int s=srcp(idx);
int n=srcn(idx);
int p=0;
while(p<n){
int t=dirparse(s,p,n,0);
if(t==0){
int q=copyline(s,p,n);
if(q<0){return 7;}
p=q;
}else{
if(t==2){return 6;}
if(t==3){return 8;}
int np=dirparse(s,p,n,1);
int nl=dirparse(s,p,n,2);
int next=dirparse(s,p,n,3);
int count=findname(s+np,nl,0);
if(count==0){return 2;}
if(count!=1){return 3;}
int target=findname(s+np,nl,1);
if(active(target)==1){return 4;}
if(32<=depth()){return 5;}
if(push(target)==0){return 5;}
int e=expand(target);
pop();
if(e!=0){return e;}
if(emit(10)==0){return 7;}
p=next;
}
}
return 0;
}

int main(){
if(manifestok()==0){return fail(1);}
*resp()=0-1;
*(resp()+8)=0;
*wsp()=0;
int root=findname(rootp(),rootn(),1);
if(root<0){return fail(1);}
if(push(root)==0){return fail(5);}
int e=expand(root);
pop();
if(e!=0){return fail(e);}
*resp()=0;
return 0;
}
