void *malloc(int bytes);
void free(void *pointer);
int main() {
    char header[8];
    char *request=malloc(168);
    char *reply=malloc(4296);
    int used=0;
    int count=0;
    int total=0;
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
    if((*header&255)!=168){return 12;}
    i=1;
    while(i<8){if(*(header+i)!=0){return 12;}i=i+1;}
    used=0;
    while(used<168){
        n=read_bytes(request+used,168-used);
        if(n<=0){return 13;}
        used=used+n;
    }
    n=read_bytes(header,1);
    if(n!=0){return 14;}
    count=(*(request+48)&255)+256*((*(request+49))&255);
    i=50;
    while(i<56){if(*(request+i)!=0){return 15;}i=i+1;}
    if(count<1){return 15;}
    if(4096<count){return 15;}
    total=200+count;
    used=0;
    while(used<168){
        n=ssend(request+used,168-used);
        if(n!=(0-2)){if(n<=0){return 16;}used=used+n;}
    }
    n=sshut();
    if(n!=0){return 17;}
    used=0;
    while(used<total){
        amount=total-used;
        if(1024<amount){amount=1024;}
        n=srecv(reply+used,amount);
        if(n!=(0-2)){if(n<=0){return 18;}used=used+n;}
    }
    n=0-2;
    while(n==(0-2)){n=srecv(header,1);}
    if(n!=0){return 19;}
    i=0;
    while(i<168){
        if(*(reply+32+i)!=*(request+i)){return 20;}
        i=i+1;
    }
    used=0;
    while(used<count){
        amount=count-used;
        if(1024<amount){amount=1024;}
        n=write_bytes(reply+200+used,amount);
        if(n<=0){return 21;}
        used=used+n;
    }
    free(reply);
    free(request);
    return 0;
}
