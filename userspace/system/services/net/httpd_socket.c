#include "stdlib.h"
int getbyte(char *addr);
int putbyte(char *addr, int value);
int reqok(char *addr, int len);
int put200(char *addr);
int put404(char *addr);

int main() {
    char buffer[1024];
    int used=0;
    int scanned=0;
    int end=0;
    int n=0;
    int out=0;
    int sent=0;
    char *reply;
    while (end==0) {
        if (used==1024) { return 14; }
        n=srecv(buffer+used,1024-used);
        if (n!=(0-2)) {
            if (n==0) { return 11; }
            if ((n<0) | (1024-used<n)) { return 10; }
            used=used+n;
            while ((scanned<used) & (end==0)) {
                scanned=scanned+1;
                if (3<scanned) {
                    if (getbyte(buffer+(scanned-1))==10) {
                        if ((getbyte(buffer+(scanned-4))==13) & (getbyte(buffer+(scanned-3))==10) &
                            (getbyte(buffer+(scanned-2))==13)) { end=scanned; }
                    }
                }
            }
        }
    }
    reply=malloc(74);
    if (reply==0) { return 16; }
    if (reqok(buffer,end)!=0) { out=put200(reply); } else { out=put404(reply); }
    while (sent<out) {
        n=ssend(reply+sent,out-sent);
        if (n!=(0-2)) {
            if ((n<=0) | (out-sent<n)) { free(reply); return 15; }
            sent=sent+n;
        }
    }
    free(reply);
    return 0;
}
#include "http_reply.h"
