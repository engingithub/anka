char *identity(char *p);
int main(){
char buffer[4];
char *p=identity(buffer);
int i=0;
int sum=0;
while(i<4){
*(p+i)=i+1;
sum=sum+*(p+i);
i=i+1;
}
int status=syscall(0,sum,0,0);
return 0;
}
char *identity(char *p){return p;}
