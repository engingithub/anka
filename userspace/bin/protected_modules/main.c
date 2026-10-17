#include "/probe/api.h"
int main(){
char b[4];
*b=64;
*(b+1)=0;
*(b+2)=255;
*(b+3)=66;
int result=touch(b,4);
if(result!=4){return syscall(0,1,0,0);}
if(*b!=65){return syscall(0,2,0,0);}
if(write_bytes(b,4)!=4){return syscall(0,3,0,0);}
if(write_bytes(b+4,0)!=0){return syscall(0,4,0,0);}
if(write_bytes(b+3,2)!=(0-1)){return syscall(0,5,0,0);}
return syscall(0,0,0,0);
}
int tail(int x){return x;}
