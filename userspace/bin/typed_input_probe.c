char *identity(char *p);
int main(){
char buffer[4];
char *p=identity(buffer);
*p=17;*(p+1)=17;*(p+2)=17;*(p+3)=17;
int status=0;
int bad=read_bytes(p+3,2);
if(bad!=(0-1)){status=1;}
int empty=read_bytes(p+4,0);
if(empty!=0){status=2;}
int count=read_bytes(p,3);
if(count!=3){status=3;}
if(*p!=65){status=4;}
if(*(p+1)!=0){status=5;}
if(*(p+2)!=255){status=6;}
if(*(p+3)!=17){status=7;}
int emitted=write_bytes(p,count);
if(emitted!=3){status=8;}
int tail=read_bytes(p,4);
if(tail!=2){status=9;}
if(*p!=66){status=10;}
if(*(p+1)!=67){status=11;}
if(*(p+2)!=255){status=12;}
if(*(p+3)!=17){status=13;}
emitted=write_bytes(p,tail);
if(emitted!=2){status=14;}
int eof=read_bytes(p,4);
if(eof!=0){status=15;}
return syscall(0,status,0,0);
}
char *identity(char *p){return p;}
