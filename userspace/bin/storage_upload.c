void *malloc(int bytes);
void free(void *pointer);
int main() {
    char header[8];
    char *request=malloc(4264);
    char *reply=malloc(4336);
    int used=0;
    int length=0;
    int amount=0;
    int n=0;
    int i=0;
    if(request==0){return 10;}
    if(reply==0){return 10;}
    while(used<8){
        n=read_bytes(header+used,8-used);
        if(n<=0){return 11;}
        used=used+n;
    }
    i=2;
    while(i<8){if(*(header+i)!=0){return 12;}i=i+1;}
    length=(*header&255)+256*((*(header+1))&255);
    if(length<168){return 12;}
    if(4264<length){return 12;}
    used=0;
    while(used<length){
        amount=length-used;
        if(1024<amount){amount=1024;}
        n=read_bytes(request+used,amount);
        if(n<=0){return 13;}
        used=used+n;
    }
    n=read_bytes(header,1);
    if(n!=0){return 14;}
    used=0;
    while(used<length){
        amount=length-used;
        if(1024<amount){amount=1024;}
        n=ssend(request+used,amount);
        if(n!=(0-2)){if(n<=0){return 15;}used=used+n;}
    }
    n=sshut();
    if(n!=0){return 16;}
    used=0;
    while(used<length+72){
        amount=length+72-used;
        if(1024<amount){amount=1024;}
        n=srecv(reply+used,amount);
        if(n!=(0-2)){if(n<=0){return 17;}used=used+n;}
    }
    n=srecv(header,1);
    if(n!=0){return 18;}
    i=0;
    while(i<length){
        if(*(reply+72+i)!=*(request+i)){return 19;}
        i=i+1;
    }
    free(reply);
    free(request);
    return 0;
}
