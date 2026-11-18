int main() {
    char request[112];
    char reply[144];
    int i=0;
    int used=0;
    int n=0;
    while(i<112){*(request+i)=0;i=i+1;}
    *(request+0)=65;*(request+1)=78;*(request+2)=75;*(request+3)=65;
    *(request+4)=80;*(request+5)=81;*(request+6)=49;
    *(request+8)=1;*(request+24)=42;
    *(request+32)=10;*(request+40)=20;*(request+48)=3;*(request+56)=30;
    *(request+64)=4;*(request+72)=1;*(request+80)=7;*(request+88)=1;*(request+96)=99;
    while(used<112){
        n=ssend(request+used,112-used);
        if(n!=(0-2)){if(n<=0){return 11;}used=used+n;}
    }
    n=sshut();
    if(n!=0){return 12;}
    used=0;
    while(used<144){
        n=srecv(reply+used,144-used);
        if(n!=(0-2)){if(n<=0){return 13;}used=used+n;}
    }
    n=srecv(request,1);
    if(n!=0){return 14;}

    i=0;
    while(i<112){
        if(i!=5){if(*(reply+i)!=*(request+i)){return 15;}}
        i=i+1;
    }
    if(*(reply+5)!=82){return 16;}
    i=112;
    while(i<144){
        n=0;
        if(i==120){n=8;}
        if(i==128){n=99;}
        if(i==136){n=8;}
        if(*(reply+i)!=n){return 17;}
        i=i+1;
    }
    return 0;
}
