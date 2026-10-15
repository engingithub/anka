char *identity(char *p);
int main(){
char buffer[4];
char *p=identity(buffer);
*p=65;
*(p+1)=0;
*(p+2)=255;
*(p+3)=66;
int count=write_bytes(p,4);
int empty=write_bytes(p+4,0);
int bad=write_bytes(p+3,2);
int status=0;
if(count!=4){status=1;}
if(empty!=0){status=2;}
if(bad!=(0-1)){status=3;}
if(*p!=65){status=4;}
return syscall(0,status,0,0);
}
char *identity(char *p){return p;}
