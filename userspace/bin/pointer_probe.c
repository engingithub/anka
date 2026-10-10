int main(){
int x=40;
int *p=&x;
*p=*p+2;
int status=syscall(0,x,0,0);
return 0;
}
