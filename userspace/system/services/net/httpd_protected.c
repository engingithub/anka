int getbyte(char *addr);
int putbyte(char *addr, int value);
int reqok(char *addr, int len);
int put200(char *addr);
int put404(char *addr);

int main() {
    char buffer[1024];
    char extra[1];
    int used=0;
    int count=0;
    int done=0;
    int out=0;
    while ((used<1024) & (done==0)) {
        count=read_bytes(buffer+used,1024-used);
        if (count==(0-1)) { return 10; }
        if (count==0) { done=1; } else { used=used+count; }
    }
    if (used==1024) {
        count=read_bytes(extra,1);
        if (count!=0) { return 14; }
    }
    if (used==0) { return 11; }
    if (reqok(buffer,used)!=0) { out=put200(buffer); } else { out=put404(buffer); }
    if (write_bytes(buffer,out)!=out) { return 15; }
    return 0;
}

#include "http_reply.h"
