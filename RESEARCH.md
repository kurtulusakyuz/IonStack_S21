# IonStack_S21 RESEARCH — o1s/G991B (5.4.242) research notes

Condensed from the full campaign (`Root-My-Galaxy-Payloads/docs/
SM-G991B-G991BXXSJHZC2.md`). vmlinux: `firmware/G991BXXSJHZC2/vmlinux.elf`.

## Mechanism (verified)

Waiter `LOCK_PI(chain)` → `WAIT_REQUEUE_PI(f_wait→target, 8s)` → main
`CMP_REQUEUE_PI` → planter (same thread, post-wake) + consumer
`sched_setattr(waiter)` → `rt_mutex_adjust_pi` → `adjust_prio_chain` reads
`task->pi_blocked_on` → `waiter->lock` → `trylock` → walk → `rb_erase`
write. Fake waiter/lock/task live on a reclaimed order-3 heap page
(skb/sendmsg reclaim).

## Slot geometry (disasm-proven, all depths from thread stack top `TOP-C`)

- Waiter slot = `futex_wait_requeue_pi` entry `sp - 0x108`
  (`rt_mutex_init_waiter(sp+0x98)`, frame `0x1A0`); absolute depth
  `[0x148, 0x198)`, `lock` at depth `0x160` (`waiter+0x38`).
- `task->pi_blocked_on` dangles at the stale slot post-timeout
  (`remove_waiter` NULLs it only on some paths; the observed stable panic —
  `trylock+0x1c` on VA 0 — proves a dangling zeroed waiter is walked).

## Planter depth map (measured per syscall; NFDS=640 unless noted)

| Planter copy | Depth range | vs waiter `[0x148,0x198)` | Verdict |
|---|---|---|---|
| pselect input (core `sp+0x50`, 64B) | `[0x1D0,0x210)` | 0x38 too deep | only `tree_parent_color` reachable |
| select input | `[0x1B0,0x1F0)` | 0x18 too deep | miss |
| MCAST stamp (`do_ipv6 sp+0x30`, 264B) | `[0x248,0x350)` | 0xB0 too shallow | miss |
| recvmsg msghdr (`__sys sp+0x70`, 56B) | `[0xD8,0x110)` | 0x50 too shallow | miss |
| poll ufds (stack fantail) | covers slot | `revents` clobbers every 8B | kernel addrs impossible |
| signal frame | delivery-dependent | unreliable | skip |
| resbit result bitmaps | exact overlap possible | nonzero+stable mutually exclusive | futile |

The 8-byte `lock` field sits in a copy-gap: every reachable copy is too
shallow, too deep, sparse, clobbered, or non-blocking. Six stamp variants
(in/ex/out words, cyclic/RED parents, `0xdeadbeef` marker-oracle,
byte-plotter) all fault at VA 0 — decisive miss signal.

## Other fronts (all quiet/closed)

- Pipe-reclaim gate systematically `0/0` (slab/page-type + drain
  calibration; fresh reboots included).
- io_uring ~8k iters (1 wedge/3000), uhid destroy-path clean, perf 2.3k
  quiet, mali ~22k ops quiet, ION logic 4.5k quiet (CMA/secure heaps stall
  in EL3-SMC = DoS only), binder NDK+RAW fuzzing quiet.
- One reportable finding: mediaserver CFI-DoS (wrong-interface binder
  object → `BnMediaPlayerService::onTransact+0x764` → `__cfi_check_fail`,
  SIGILL, clean restart; DoS-only).
- AF_ALG/eBPF/kallsyms/V4L2: EACCES or group-gated for shell. Shizuku =
  shell uid 2000 (no advantage over adb).

## Reopen triggers

- A blocking syscall with a copy covering depth `0x160` (8B-contiguous,
  attacker-controlled, stable window).
- A kernel infoleak locating the actually-walked object.
- Post-SPL CVE with public PoC affecting 5.4 + unpriv reachability.
