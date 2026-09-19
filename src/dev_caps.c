/* dev_caps: capability map for o1s shell (uid 2000, enforcing).
 * Tries each primitive, prints errno. No side effects. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/keyctl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#ifndef SYS_add_key
#define SYS_add_key 248
#endif
#ifndef SYS_memfd_create
#define SYS_memfd_create 279
#endif
#ifndef KEYCTL_JOIN_SESSION_KEYRING
#define KEYCTL_JOIN_SESSION_KEYRING 1
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(30);
    printf("dev_caps: o1s capability map\n");
    {
        errno = 0;
        int fd = socket(38, SOCK_SEQPACKET, 0);
        printf("AF_ALG socket: fd=%d errno=%d\n", fd, errno);
        if (fd >= 0)
            close(fd);
    }
    {
        errno = 0;
        long r = syscall(SYS_add_key, "user", "t", "x", 1, -2);
        printf("add_key: ret=%ld errno=%d\n", r, errno);
    }
    {
        errno = 0;
        long r = syscall(SYS_keyctl, KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0,
                         0);
        printf("keyctl_join: ret=%ld errno=%d\n", r, errno);
    }
    {
        errno = 0;
        int r = unshare(CLONE_NEWUSER);
        printf("unshare(USERNS): ret=%d errno=%d\n", r, errno);
    }
    {
        errno = 0;
        int fd = syscall(SYS_memfd_create, "t", 0);
        printf("memfd_create: fd=%d errno=%d\n", fd, errno);
        if (fd >= 0)
            close(fd);
    }
    {
        errno = 0;
        char b[8];
        struct iovec li = {b, 8}, ri = {(void *)0x1000, 8};
        long r = syscall(SYS_process_vm_readv, syscall(SYS_getpid), &li,
                         1, &ri, 1, 0);
        printf("process_vm_readv: ret=%ld errno=%d\n", r, errno);
    }
    {
        errno = 0;
        unsigned sz = 0;
        long r = syscall(SYS_prctl, 35, 15, &sz, 0, 0);
        printf("prctl_MM_MAP_SIZE: ret=%ld errno=%d\n", r, errno);
    }
    printf("dev_caps: done\n");
    return 0;
}
