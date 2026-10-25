#include "/include/stdlib.h"
char *identity(char *p);
char *empty();
int main(){
char *p=malloc(4);
int *word=malloc(8);
char **cell=malloc(16);
char *q=0;
void *nil=malloc(0);
int i=0;
int status=0;
if((p==0)|(word==0)|(cell==0)){return syscall(0,1,0,0);}
if(nil!=0){return syscall(0,2,0,0);}
if((identity(0)!=0)|(empty()!=0)){return syscall(0,9,0,0);}
if(malloc(0)!=0){return syscall(0,10,0,0);}
if((*p!=0)|(*word!=0)){return syscall(0,3,0,0);}
*cell=identity(p);
q=*cell;
*p=65;*(p+1)=0;*(p+2)=255;*(p+3)=66;
*word=42;
if((*q!=65)|(*word!=42)){return syscall(0,4,0,0);}
status=write_bytes(q,4);
if(status!=4){return syscall(0,5,0,0);}
free(cell);free(word);free(p);free(nil);free(0);
while(i<4){
q=malloc(16);
if(q==0){return syscall(0,6,0,0);}
if(*q!=0){return syscall(0,7,0,0);}
*q=99;free(q);i=i+1;
}
q=malloc(16);
if(q==0){return syscall(0,8,0,0);}
*q=77;
return syscall(0,0,0,0);
}
char *identity(char *p){return p;}
char *empty(){return 0;}
