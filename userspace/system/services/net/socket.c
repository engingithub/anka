int getbyte(int addr) {
    int base = addr & (0 - 8);
    int word = *base;
    int shift = (addr & 7) * 8;
    return (word >> shift) & 255;
}

int putbyte(int addr, int value) {
    int base = addr & (0 - 8);
    int shift = (addr & 7) * 8;
    int word = *base;
    int mask = (0 - 1) - (255 << shift);
    word = (word & mask) | ((value & 255) << shift);
    *base = word;
    return 0;
}

int pair(int addr) {
    return (getbyte(addr) << 8) | getbyte(addr + 1);
}

int putpair(int addr, int value) {
    putbyte(addr, (value >> 8) & 255);
    putbyte(addr + 1, value & 255);
    return 0;
}

int quad(int addr) {
    return (pair(addr) << 16) | pair(addr + 2);
}

int putquad(int addr, int value) {
    putpair(addr, (value >> 16) & 65535);
    putpair(addr + 2, value & 65535);
    return 0;
}

int add32(int value, int delta) {
    int low = (value & 65535) + (delta & 65535);
    int high = ((value >> 16) & 65535) + ((delta >> 16) & 65535) + (low >> 16);
    return ((high & 65535) << 16) | (low & 65535);
}

int issval() {
    return (16718 << 16) | 19265;
}

int addsum(int sum, int word) {
    sum = sum + word;
    sum = (sum & 65535) + (sum >> 16);
    return sum;
}

int cksum(int addr, int len) {
    int sum = 0;
    int pos = 0;

    while (pos + 1 < len) {
        sum = addsum(sum, pair(addr + pos));
        pos = pos + 2;
    }
    if (pos < len) {
        sum = addsum(sum, getbyte(addr + pos) << 8);
    }
    while (65535 < sum) {
        sum = (sum & 65535) + (sum >> 16);
    }
    return 65535 - sum;
}

int tcpcsum(int addr, int tlen) {
    int sum = 0;
    int pos = 0;

    sum = addsum(sum, pair(addr + 26));
    sum = addsum(sum, pair(addr + 28));
    sum = addsum(sum, pair(addr + 30));
    sum = addsum(sum, pair(addr + 32));
    sum = addsum(sum, 6);
    sum = addsum(sum, tlen);

    while (pos + 1 < tlen) {
        sum = addsum(sum, pair(addr + 34 + pos));
        pos = pos + 2;
    }
    if (pos < tlen) {
        sum = addsum(sum, getbyte(addr + 34 + pos) << 8);
    }
    while (65535 < sum) {
        sum = (sum & 65535) + (sum >> 16);
    }
    return 65535 - sum;
}

int ipok(int addr, int len) {
    int total = 0;
    int frag = 0;

    if (len < 54) {
        return 0;
    }
    if (1514 < len) {
        return 0;
    }
    if (pair(addr + 12) != 2048) {
        return 0;
    }
    if (getbyte(addr + 14) != 69) {
        return 0;
    }

    total = pair(addr + 16);
    if (total < 40) {
        return 0;
    }
    if (len - 14 < total) {
        return 0;
    }
    if (cksum(addr + 14, 20) != 0) {
        return 0;
    }

    frag = pair(addr + 20);
    if ((frag & 16383) != 0) {
        return 0;
    }
    return 1;
}

int islocal(int addr) {
    if (getbyte(addr + 30) != 10) {
        return 0;
    }
    if (getbyte(addr + 31) != 0) {
        return 0;
    }
    if (getbyte(addr + 32) != 0) {
        return 0;
    }
    if (getbyte(addr + 33) != 2) {
        return 0;
    }
    return 1;
}

int tupleok(int addr, int peerip, int peerpt) {
    if (quad(addr + 26) != peerip) {
        return 0;
    }
    if (pair(addr + 34) != peerpt) {
        return 0;
    }
    return 1;
}

int zeropad(int addr, int start, int end) {
    int pos = start;
    while (pos < end) {
        putbyte(addr + pos, 0);
        pos = pos + 1;
    }
    return 0;
}

int replyctl(int addr, int flags, int seq, int ack) {
    int m0 = getbyte(addr + 6);
    int m1 = getbyte(addr + 7);
    int m2 = getbyte(addr + 8);
    int m3 = getbyte(addr + 9);
    int m4 = getbyte(addr + 10);
    int m5 = getbyte(addr + 11);
    int i0 = getbyte(addr + 26);
    int i1 = getbyte(addr + 27);
    int i2 = getbyte(addr + 28);
    int i3 = getbyte(addr + 29);
    int pport = pair(addr + 34);
    int sum = 0;

    putbyte(addr + 0, m0);
    putbyte(addr + 1, m1);
    putbyte(addr + 2, m2);
    putbyte(addr + 3, m3);
    putbyte(addr + 4, m4);
    putbyte(addr + 5, m5);

    putbyte(addr + 6, 2);
    putbyte(addr + 7, 0);
    putbyte(addr + 8, 0);
    putbyte(addr + 9, 0);
    putbyte(addr + 10, 0);
    putbyte(addr + 11, 2);
    putpair(addr + 12, 2048);

    putbyte(addr + 14, 69);
    putbyte(addr + 15, 0);
    putpair(addr + 16, 40);
    putpair(addr + 18, 0);
    putpair(addr + 20, 16384);
    putbyte(addr + 22, 64);
    putbyte(addr + 23, 6);
    putpair(addr + 24, 0);

    putbyte(addr + 26, 10);
    putbyte(addr + 27, 0);
    putbyte(addr + 28, 0);
    putbyte(addr + 29, 2);
    putbyte(addr + 30, i0);
    putbyte(addr + 31, i1);
    putbyte(addr + 32, i2);
    putbyte(addr + 33, i3);

    putpair(addr + 34, 49153);
    putpair(addr + 36, pport);
    putquad(addr + 38, seq);
    putquad(addr + 42, ack);
    putbyte(addr + 46, 80);
    putbyte(addr + 47, flags);
    putpair(addr + 48, 4096);
    putpair(addr + 50, 0);
    putpair(addr + 52, 0);

    sum = tcpcsum(addr, 20);
    putpair(addr + 50, sum);
    sum = cksum(addr + 14, 20);
    putpair(addr + 24, sum);
    zeropad(addr, 54, 60);

    return syscall(19, 0, 0, 1, 0, 60);
}

int copyapp(int src, int len) {
    int pos = 0;
    while (pos < len) {
        putbyte(114688 + pos, getbyte(src + pos));
        pos = pos + 1;
    }
    return 0;
}

int senddata(int addr, int len, int seq, int ack) {
    int pos = 0;
    int tlen = 20 + len;
    int total = 20 + tlen;
    int flen = 14 + total;
    int sum = 0;

    putpair(addr + 16, total);
    putpair(addr + 18, 0);
    putpair(addr + 20, 16384);
    putbyte(addr + 22, 64);
    putbyte(addr + 23, 6);
    putpair(addr + 24, 0);

    putquad(addr + 38, seq);
    putquad(addr + 42, ack);
    putbyte(addr + 46, 80);
    putbyte(addr + 47, 24);
    putpair(addr + 48, 4096);
    putpair(addr + 50, 0);
    putpair(addr + 52, 0);

    while (pos < len) {
        putbyte(addr + 54 + pos, getbyte(114688 + pos));
        pos = pos + 1;
    }

    sum = tcpcsum(addr, tlen);
    putpair(addr + 50, sum);
    sum = cksum(addr + 14, 20);
    putpair(addr + 24, sum);

    if (flen < 60) {
        zeropad(addr, flen, 60);
        flen = 60;
    }
    return syscall(19, 0, 0, 1, 0, flen);
}
int tellcli(int value) {
    return syscall(12, 1, 0, value);
}

int main() {
    int state = 0;
    int peerip = 0;
    int peerpt = 0;
    int rcvnxt = 0;
    int sndnxt = 0;
    int status = 0;
    int len = 0;
    int total = 0;
    int tlen = 0;
    int plen = 0;
    int sport = 0;
    int flags = 0;
    int seq = 0;
    int ack = 0;
    int epoch = 0;
    int msg = 0;
    int tag = 0;
    int slen = 0;

    while (1) {
        status = syscall(18, 0, 0, 1, 0);
        len = sysret(1);

        if (status == 9) {
            status = syscall(17, 0, 0, epoch);
            epoch = sysret(1);
            if (status != 0) {
                return 110 + status;
            }
        } else {
            if (status != 0) {
                return 100 + status;
            }

            if (ipok(98304, len) != 0) {
            if (islocal(98304) != 0) {
                if (getbyte(98304 + 23) == 6) {
                    total = pair(98304 + 16);
                    tlen = total - 20;
                    if (20 <= tlen) {
                        if (getbyte(98304 + 46) == 80) {
                            if (tcpcsum(98304, tlen) == 0) {
                                if (pair(98304 + 36) == 49153) {
                                    sport = pair(98304 + 34);
                                    flags = getbyte(98304 + 47);
                                    seq = quad(98304 + 38);
                                    ack = quad(98304 + 42);
                                    plen = tlen - 20;

                                    if (state == 0) {
                                        if (flags == 2) {
                                            if (plen == 0) {
                                                peerip = quad(98304 + 26);
                                                peerpt = sport;
                                                rcvnxt = add32(seq, 1);
                                                sndnxt = add32(issval(), 1);
                                                status = replyctl(98304, 18, issval(), rcvnxt);
                                                if (status != 0) {
                                                    return 120 + status;
                                                }
                                                state = 1;
                                            }
                                        }
                                    } else {
                                        if (tupleok(98304, peerip, peerpt) != 0) {
                                            if (state == 1) {
                                                if (flags == 16) {
                                                    if (plen == 0) {
                                                        if (seq == rcvnxt) {
                                                            if (ack == sndnxt) {
                                                                state = 2;
                                                                status = tellcli(1);
                                                                if (status != 0) {
                                                                    return 130 + status;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            } else {
                                                if (state == 2) {
                                                    if (flags == 17) {
                                                        if (plen == 0) {
                                                            if (seq == rcvnxt) {
                                                                if (ack == sndnxt) {
                                                                    rcvnxt = add32(rcvnxt, 1);
                                                                    status = replyctl(98304, 16, sndnxt, rcvnxt);
                                                                    if (status != 0) {
                                                                        return 120 + status;
                                                                    }
                                                                    status = tellcli(2);
                                                                    if (status != 0) {
                                                                        return 130 + status;
                                                                    }
                                                                    return 1;
                                                                }
                                                            }
                                                        }
                                                    } else {
                                                        if ((flags == 16) | (flags == 24)) {
                                                            if (0 < plen) {
                                                                if (plen <= 1024) {
                                                                    if (seq == rcvnxt) {
                                                                        if (ack == sndnxt) {
                                                                            copyapp(98304 + 54, plen);
                                                                            rcvnxt = add32(rcvnxt, plen);
                                                                            status = replyctl(98304, 16, sndnxt, rcvnxt);
                                                                            if (status != 0) {
                                                                                return 120 + status;
                                                                            }
                                                                            status = tellcli(4096 + plen);
                                                                            if (status != 0) {
                                                                                return 130 + status;
                                                                            }
                                                                            msg = syscall(14, 1, 0, 0);
                                                                            tag = sysret(1);
                                                                            if (tag == 1) {
                                                                                if (8192 < msg) {
                                                                                    slen = msg - 8192;
                                                                                    if (0 < slen) {
                                                                                        if (slen <= 1024) {
                                                                                            status = senddata(98304, slen, sndnxt, rcvnxt);
                                                                                            if (status != 0) {
                                                                                                return 120 + status;
                                                                                            }
                                                                                            sndnxt = add32(sndnxt, slen);
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        }
    }
}
