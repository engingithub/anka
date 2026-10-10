int main(){
char left=17;
char x=255;
char right=51;
char *p=&x;
*p=511;
int observed=*p;
char copied=*p;
copied=298;
int status=syscall(0,observed+left+right+copied,0,0);
return 0;
}
