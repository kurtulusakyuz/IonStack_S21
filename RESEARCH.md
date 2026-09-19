# IonStack_S21 RESEARCH — SM-G991B / G991BXXSJHZC2 (o1s)

Galaxy S21 (European, `o1s`), firmware `G991BXXSJHZC2`
(`AP3A.240905.015.A2`), kernel `5.4.242-30958140`, Android SPL `2026-01-01`,
Exynos 2100 / Mali-G78 (Valhall JM, `r38p0`). Shell entry is `uid=2000`
(`adb shell`), no `CAP_*`.

Status: **GhostLock write program CLOSED with evidence (deterministic
DoS-only; write via this path proven impossible).** Standing fronts: Mali
r38 recon, oempocalypse-P2 watch, report write-up. Campaign window:
September 2026. Post-write artifacts (KernelSU `.ko` + `ksud` built for
this exact firmware) are staged separately — the missing
piece was purely the initial kernel write.

## 0. Target hardening (why this device is hard)

- `CFI_CLANG=y` + PAC + PAN/UAO, `CONFIG_KDP_CRED=y`,
  `CONFIG_PANIC_ON_OOPS=y` (every oops reboots — panics are observable
  but always fatal), `CONFIG_KDP_NS` frame present on-device.
- SELinux enforcing, shell `uid=2000` without `CAP_*`.
- `CONFIG_USERFAULTFD` absent, no SUID binaries, `CONFIG_CHECKPOINT_RESTORE`
  unset, `CONFIG_USER_NS` unset, `CONFIG_RDS` unset,
  `CONFIG_CRYPTO_USER_API_AEAD` unset, `CONFIG_MFC_USE_DMABUF_CONTAINER`
  unset (all verified against the firmware config).
- Consequence: cred patching is dead (KDP guards cred); only a data-only
  write (`selinux_state.enforcing=0` + UMH/`core_pattern` → root daemon —
  exactly the S22U b0q precedent) or an insmod path can lead to root.
  CFI/PAC do not constrain data writes.

## 1. GhostLock (CVE-2026-43499, futex PI) — CLOSED, DoS-only

Root cause (public since 2026-05, verified present in this tree):
`remove_waiter()` clears `current->pi_blocked_on` instead of
`waiter->task->pi_blocked_on`. In the `FUTEX_CMP_REQUEUE_PI` proxy-lock
rollback (`rt_mutex_start_proxy_lock` fails EDEADLK on the
owner→chain→waiter→target deadlock cycle, `current` = requeuer), the
waiter's `pi_blocked_on` is never cleared — dangling pointer to the
stack `rt_waiter`. The waiter returns ETIMEDOUT via the early path (no
cleanup), the slot is reused, and a later `sched_setattr` walks garbage.
Upstream fix `3bfdc63` is absent from 5.4.242 (5.4 EOL). Tree sites:
`remove_waiter` uses `current`, rollback caller at `rtmutex.c:1807`,
requeue caller at `futex.c:2259`.

Crash signature (guest and device identical): `sched_setattr` →
`rt_mutex_adjust_pi` → `rt_mutex_adjust_prio_chain+0x108` →
`_raw_spin_trylock+0x1c`, fault VA 0 (`x0=0`, or the `0xffffffc01180db28`
`idle_sched_class` variant when ticks tear parked content).

Guest reproduction (KDP-less QEMU, dance `dance8d`): 3-thread cycle
(owner holds TARGET, proxy-blocks on CHAIN; waiter holds CHAIN,
plain-queues; main CMP → `ret=-1 errno=35` EDEADLK) + consumer
`sched_setattr` → device-identical Oops; the guest reboots on it, like
the phone. A TRIG hbreak at the `bl rt_mutex_adjust_pi`
(`core.c:5148`) shows the dangling `pi` live (pid/comm-attributed via
debuginfo offsets `pid@0x588, comm@0x750, stack@0x30, pi@0x838`); slot
content varies per run (NULL-lock → Oops, heap-garbage-lock → clean
`ret=0`).

Slot lifecycle, fully mapped: `pi` = stack-top `E-0x328`, stable across
runs (n=3/4, pid-attributed via the `trig2` variant). Asleep =
pristine-stale; post-return = stack-ptr/zero residue; deterministic VA=0
via the all-zero post-reblock slot (`dance8j` reproducer).

Spray closure (guest, gdb stack-map protocol): 9 syscall families
depth-mapped (poll/select/sendmsg/setsockopt/adjtimex/affinity/
mempolicy/perf/move_pages) — every copy is too shallow, heap-side, or
ENOSYS against `E-0x2F0`; plus compat, exception-disasm, and sendmmsg
(`E-sp` 0x400/0x1a0, victim in the dead band) variants. Slab-reclaim of
the `pi_state` is blocked by an owner-liveness Catch-22 (the owner dies
only via chain-release, which destroys the stale pointer). Independent
confirm from the ASUS i005 port (link §5): their waiter sits at −0x1b0,
40+ spray syscalls exhausted, none reaches `+0x38`; the chain reads
`lock` FIRST (early-bail without it); `rb_erase` never fires (the waiter
is dequeued by the bug itself).

On-device verification (2026-09-17, HZC2, shell/2000, enforcing): the
trigger works on the KDP kernel (gate ok + CMP EDEADLK every run,
no-fire safe). Capability caps: AF_ALG/add_key EACCES, userns EINVAL,
memfd/process_vm OK, PR_SET_MM EPERM. A 9-lane spray sweep (pattern
`0x5X`): most lanes clean `ret=0`; the ppoll-32 + process_vm lanes hit
the NATURAL-NULL flip → device-identical Oops (`trylock+0x1c <-
chain+0x108`, VA=0, lastkmsg `118`/`119`, 2 reboots). Zero pattern
landings on real hardware either — the wall stands with identical
geometry and behavior.

Walk-outcome taxonomy (device-proven): NULL-lock → Oops + reboot;
mapped-nonzero-lock → spin (alarm-killable); legit/early-bail → clean
`ret=0`.

**Verdict FINAL: GhostLock on o1s is a deterministic DoS primitive
(reboot). No write path exists through it.**

## 2. SIGRETURN / AQUOS stamp port — CLOSED (chaotic, no control)

Why it was tried: of all surveyed planters, only an `rt_sigreturn`
FPSIMD copy is geometrically wide enough (512B) to cover the waiter
slot. A signal handler edits the FPSIMD context inside the user
sigframe; on handler return the kernel's `restore_fpsimd_context` runs
`memset(sp,0,0x210)` then `copy_from_user(sp, ctx->vregs, 0x200)` onto
the waiter thread's own kernel stack; the fake waiter is placed at
`SIGRETURN_FPSIMD_WAITER_OFF` inside that copy. Stamp = the
`rt_sigreturn` syscall (waiter self-sends SIGUSR2); consumer = a thread
calling `sched_setattr(waiter_tid)`. In-tree source: `src/slide_app.c`
(`slide_sigreturn_*`), runtime offset override `SLIDE_SIG_OFF` (hex).

Confirmed geometry (disasm + live crash agree; all depths from the
`pt_regs` base `T` = kernel stack top − `S_FRAME_SIZE`):
`S_FRAME_SIZE = 0x140` (entry `sub sp,sp,#0x140`; the `add sp,sp,x0` /
`tbnz` is the VMAP_STACK overflow probe — net-zero, SP deterministic),
`THREAD_SIZE = 0x4000`, `THREAD_ALIGN = 2*THREAD_SIZE = 0x8000`.
Syscall wrapper entry = `T − H`, `H = el0_svc_handler (0x10) +
el0_svc_common (0x40) = 0x50`. Futex chain: `__arm64_sys_futex` (0x70)
→ `do_futex` (0x20) → `futex_wait_requeue_pi` (0x1A0,
`rt_mutex_init_waiter(sp+0x98)`) → **waiter slot = T − 0x1E8**,
`waiter->lock` (waiter+0x38) = **T − 0x1B0** (crash `x25` matches
exactly). Sigreturn chain: `__arm64_sys_rt_sigreturn` (0x30) →
`restore_sigframe` (0x60) → `restore_fpsimd_context` (0x30 + 0x220) →
**fpsimd local = T − 0x330**. Theoretical stamp offset =
`(T−0x1E8) − (T−0x330) = 0x148` (= build default
`SIGRETURN_FPSIMD_WAITER_OFF`). The restore buffer sits at E-0x440 ..
E-0x230 (`E-sp` = 0x220 measured), so the victim (E-0x328) overlaps at
buffer+0x118 (vregs+0x108). FP-gate discovered: threads without FP dirt
skip the restore entirely (breakpoint never fires without FP use).

Exhaustive offset sweep (marker `0x4242…` at `off+0x38`, one run each
unless noted): `0xf8` (twice), `0xe0 0xe8 0xf0 0x100`,
`0x108` (twice) `0x118 0x128 0x138 0x140 0x148 0x150 0x158`,
`0x168 0x178 0x188 0x1a8 0x1b8 0x1c8` — **every valid offset → fault
VA = 0.** (`0x110` never ran — sweep interrupted.) Gradient payload +
`SLIDE_CLEAN=1` (`-DSLIDE_NO_DIAG -DSLIDE_NO_SCRUB`, zero post-stamp
syscalls between the `rt_sigreturn` copy and the walk): still VA=0.
This is not an offset problem.

The paradox that closed it: the FPU oracle (`q0..q31` reloaded from the
fpsimd local, mirroring stamped bytes at 16B granularity) shows a
gradient landing (`fpu24 = 0x4242000000000180`, offset 0x180) — the 512B
copy DOES land — yet the walked slot always reads `lock = 0`. HW
watchpoint forensics caught the tear agent: the waiter's OWN
post-restore syscalls (audit frames: `audit_syscall_exit <-
audit_filter_inodes <- el0_svc_common`) rewrite the slot. Strict-park
builds avoid that; the remaining variance is fully explained by the
grand model: delivery needs FP-dirt, which needs CFS (FIFO/pin goes
cold: records omitted, restore skips, stale residue flips
NULL/coherent/mapped); CFS delivers pattern but ticks/migration tear it
to NULL before fire. A 15-variant closure lab confirmed chaos, not
control: pattern LANDS post-copy (repeatable, burst-attributed) but
fire-time content is nondeterministic (NULL/coherent/mapped-garbage)
across identical binaries — per-restore copy-skip flip-flop (FP-state
dependent) + tear races + a 2000-fire overlapping lottery, ALL clean.

DECISIVE (full-victim fire-time dump, `trig2` variant): the copy
delivers ONLY at victim+0x40 (`prio` = pattern); +0x00..0x38 keep
return-path live locals (heap/stack/text/ints, run-varying). The walked
gate field `lock` (+0x38) is NEVER user-controlled at fire (15/15
dumps) — structurally outside every delivered window. **Write via this
path is impossible: geometry, not probability.**

## 3. ASUS i005 transfer attempts (all tested on o1s)

- perf SP-leak (`PERF_SAMPLE_REGS_INTR`): open+mmap OK on o1s, but
  **0 kernel samples** (2 builds, 400/800ms storms). Dead here.
- M-walk variant (walk enters via a fresh LOCK_PI, not `sched_setattr`):
  the MCAST lane spins till alarm(15) (trylock-retry on a mapped lock =
  deeper walk than consumer-fire, still no control); other lanes
  early-bail + D-state sleep. No win.
- EXIT=142 lesson adopted: oracles are Oops-VA / ret / dumps only, never
  exit codes.
- Reference: <https://github.com/huaguiqi/asus-i005-cve-2026-43499>
  (5.4.210-qgki arm64, shell; same 3-thread trigger shape; hit the wall
  independently).

## 4. OEM / chipset fronts

- **CVE-2026-23789** (MFC encoder dma_buf double-free, Exynos 2100
  affected, published 2026-09-14, NO public exploit): direct V4L2
  (`/dev/video*`) is EACCES for shell, but the HW encoder works from
  shell via the MediaCodec Binder path (create/configure/start/dequeue
  OK). Error fuzz (60 rounds) + pressure fuzz (8 encoders × 200 rounds +
  2–3GB hog) came back quiet. ROOT-CAUSED CLOSED: the double-put lives
  inside the bufcon path, but HZC2 has
  `CONFIG_MFC_USE_DMABUF_CONTAINER=n` → the count stub returns −1, the
  get_daddr stub returns 0 → the error path is UNREACHABLE on o1s.
- `/dev/dsp` (`vendor_dsp_device`): DAC `cameraserver:system`, shell
  blocked — stage-1 shape only (needs an escape into cameraserver
  first).
- Mali-G78 (Valhall JM), driver **r38p0**: `/dev/mali0` (`gpu_device`)
  **openable from shell** (open OK, read EPERM). In CVE-2026-0860 range
  (r29–r49.5, infoleak, no PoC); CVE-2023-6241 range but its PoC is gone
  and it is likely CSF-specific (G78 is JM); the Sept-2026 bulletin rest
  needs r41+/r44+. → **STANDING FRONT (r38 recon).**
- A write primitive WOULD root this device (missing piece, not a dead
  end): KDP guards cred, but data-only targets work
  (`selinux_state.enforcing=0` + UMH/`core_pattern` → root daemon).

## 5. External review outcomes (all host-verified, no transfer)

- prctl(`PR_SET_MM_MAP`) 352B spray: DEAD on o1s —
  `CONFIG_CHECKPOINT_RESTORE` is not set (guest + firmware config;
  lane-8 EINVAL explained as the validator, not geometry; symbol absent
  from vmlinux). Holds for Pixel/GKI kernels, not Samsung 5.4 here.
- ZFOLD4 `fusiondrive` port (5.10 Samsung): same family, stuck at the
  same gate (insert never lands); MCAST/SO_1000 leftover numbers are
  5.10-geometry (no transfer); SOL_SOCKET-1000 goes heap on 5.4
  (skipped). Leftover method = standing practice here.
- Exception-path axis (proposed): DEAD by geometry (disasm-proven, no
  guest run needed) — `do_page_fault` frame 0x70 sits at ~E-0x200 max
  from userspace (victim E-0x328 unreachable); deep-fault overlap misses
  `lock` by 0x38+; FAR is register-passed, not spilled.
- FUSE-park of the sigreturn copy: INAPPLICABLE — the source is the user
  STACK sigframe (always present post-setup, never faults);
  `CONFIG_FUSE_FS=y` on both sides but nothing to park on. The altstack
  variant self-defeats (setup would park on a torn frame).
- magic/size header theory: REJECTED — the handler emits a valid header
  (`done=1`) and parsing passes (`memset` runs); the skip is downstream.
- Related ports reviewed (design confirms, no forks):
  <https://github.com/p2p3p/GhostLock-for-OnePlus> (6.12/6.6,
  two-stage write: W1 `selinux_enforcing`, W2 cred→`init_cred`;
  newer kernels only),
  <https://github.com/XiaoBaiLovesStirring/ghostlock-k419-adapter>
  (stack-layout feasibility table; its "not feasible" verdicts assume
  NFDS=320 — o1s needs NFDS≥736 for lock coverage, derived and tested,
  still NULL),
  <https://github.com/Wtrwx/smt878u-ionstack-poc> (chain-walk probe —
  supports the stale-object reading),
  <https://github.com/sarabpal-dev/qemu> (branch `samsung`: DEFEX
  dpolicy flow, kallsyms→ELF, run/debug scripts, buildroot rootfs —
  QEMU recipe baseline).

## 6. Other surfaces (all quiet / closed / inaccessible)

- io_uring — QUIET (~8000 iters, single-threaded bulk + rare
  LINK/DRAIN): pending unlinked polls do NOT wedge close (control-proven);
  op-11 TIMEOUT rejects all timespecs; op-12 is ACCEPT; LINK+DRAIN
  chains lose follower CQEs; 9/10 teardown wedges were the
  register-racer; SQPOLL EPERM. Final: 1 wedge / 3000 iters, zero
  crashes.
- uhid — CLEAN: write-after-destroy, double-destroy, no-create writes
  all fail clean (EINVAL); 300-iter destroy-vs-blocked-reader race: zero
  stuck readers, zero crashes; the historic `report_wait` crash not
  reproduced; early input-close UAF theory disproven.
- binder — quiet fuzzing (1500 iters libbinder transport + 1100 raw
  transport with racer; an 8-byte transport header is load-bearing,
  bytes past it freely mutable) + ONE reportable finding: mediaserver
  CFI-DoS — wrong-interface binder objects make
  `BnMediaPlayerService::onTransact+0x764` trip `__cfi_check_fail`
  (SIGILL, tombstoned, repeatable, service restarts cleanly). DoS-only;
  CFI working as intended.
- ION — QUIET (4500+ iters, alloc/free/share/mmap/dup/close races,
  system heap; correct UAPI recovered from the tree after a hand-rolled
  struct with a bogus field invalidated the first probe). CMA/secure
  heaps stall inside EL3-SMC under pressure and trip the watchdog
  (DoS, documented, not a memory bug).
- perf + misc/vendor — QUIET or INACCESSIBLE: perf fully open
  (`paranoid -1`), 2300 iters, zero wedges/crashes; `batt_misc`
  white-box clean; `ccic_misc` UVDM gated on PD hardware; V4L2/MFC,
  camera, dsp, ION-misc, `vertex10` group/SELinux-gated for shell.
- AF_ALG EACCES (kills Copy-Fail on-device), eBPF EACCES,
  kallsyms/kptr/dmesg denied, `/proc/buddyinfo` + `/proc/slabinfo`
  unreadable from shell.
- Position disclosure: device KASLR slide = 0 (4× perf CALLCHAIN
  min-IP). `perf_find_task` (REGS mode-vote, no function filter) PORTED
  and WORKING (best `0xffffff8064df0f00`, 56/256 votes — task/cred
  anchor candidate without slide knowledge). KernelSnitch verified
  COMPATIBLE (jhash/mask/order: `mm_struct` 896B order-0, hashsize 2048)
  — STAGED via `src/kernelsnitch/`, not built (no consumer yet).
  boot_id pointer-leak DEAD (random UUID, tested).

## 7. 2026 page-cache LPE family + CVE sweep (SPL 2026-01-01)

Architecturally dead on o1s by firmware config: CopyFail needs
`CRYPTO_USER_API_AEAD` (n), PinTheft needs `RDS` (n),
Fragnesia/skb_shift/vsockdrop-usns need `USER_NS` (n).

CVE triage round (2026-09-18, all host-verified): CVE-2026-43074 NOT on
5.4 (introduced in 6.4); CVE-2026-52910 pattern present but not viable
(needs verified-eBPF execution, no shell vmalloc spray); 43503 needs
userns (absent), 46242 pre-introduction, 52912 needs bridge/NFQUEUE
(unreachable). Three parallel sweeps (Android bulletins + KEV + Project
Zero + Mali/vendor + io_uring/binder/futex families): **nothing else
qualifies.** GhostLock is the sole fully-qualifying CVE (5.4-present,
post-SPL fix, unpriv, write, public); Copy-Fail dies on AF_ALG;
Mali CVE-2025-0427 likely backported with no PoC; MFC CVE-2026-23789
has no exploit; everything else is pre-SPL patched, wrong-version (6.x
io_uring/nft/overlayfs), priv-gated, or read-only/DoS.

## 8. QEMU lab record (KDP-less guest; lab tree kept separately)

Bring-up (o1s/5.4 on the `samsung` branch baseline): source build boots
the device kernel to userspace `/init`. Fixes, all local: old-RKP
`GET_RO_BUFFER (0x15)` handler (this 5.4 speaks the old RKP API —
without it paging dies); old-KDP setters (`SET_NS_ROOT_SB`,
`SET_NS_FLAGS`, `SET_NS_DATA`, `SET_NS_SB_VFSMOUNT` with guest-learned
offsets; `SET_FREEPTR` replicates the hardened obfuscation;
`PREPARE_RO_CRED` fills new_ro + cred body + `tsec->bp_cred`;
`CRED_INIT` anchors bp_pgd; `SET_CRED_PGD` refreshes it); KDP integrity
(`security_integrity_current`) neutered via guest-text patch; empty
`/ems` + `/ems/ontime` DT nodes (NULL `dom_list` tick panic); DTB banks
= real RAM layout (2 GiB single bank — the 39-bit linear mapping can't
cover the high bank). gdb-multiarch drives the stub
(hbreak/trap/single-step/python-memory, all verified live). Build env:
meson+ninja+pixman/fdt, static link, slirp dropped (9p share instead).

KDP-less kernel rebuild: stock config minus `RKP`, `KDP*`,
`SECURITY_DEFEX`, `SECURITY_SELINUX` (+`VIRTIO_PCI`/`9P_FS` for the 9p
share). Samsung-tree gaps fixed: `EXYNOS_FMP_FIPS` off (broken
host-python codegen), `SAMSUNG_TUI` off (missing generated
`band_info.h`), `VIDEO_EXYNOS_PABLO_ISP` off (missing generated
`linux/debug-snapshot.h`); 1-line redundant-label fix in
`drivers/soc/samsung/debug/cache.S`. Result: `Image` + vmlinux with
symbols and file/line live in gdb; guest boots to Buildroot login with
a 9p CMD loop (`BOOT-DONE`/`CMD-DONE` markers).

Dance log (PI mechanics, all evidence for §1–§2): dance1 (PI
lock+CMP+walk) clean; TRIG hbreak dumps live `task->pi_blocked_on`;
dance4 (poke waiter post-requeue, then walk): `pi_blocked_on == NULL` at
fire — the poke's SA_RESTART re-issues a *plain* wait, so no walk
happens at all (wchan `futex_wait_queue_me` cannot tell PI from plain;
`pi_blocked_on` is the only discriminator); dance5
(plant-before-requeue: poke while plain-blocked, CMP, walk undisturbed):
`pi_blocked_on` SET, walked waiter pristine (`waiter+0x38` = real
rt_mutex, `ret=0`) — the sigreturn handler writes the *userspace*
ucontext fpsimd area only, no kernel-side stamp ever reaches the walk
slot; dance7 (hygienic CMP→FIRE hammer, wchan gate, orphan-cancel):
50/50 `ret=0`, zero Oops. Code proof closes it: `waiter->lock` is
assigned once (`task_blocks_on_rt_mutex`) and never cleared, `fork`
clears `pi_blocked_on`, and every chain deref before the `trylock` is
re-checked under `pi_lock` — a settled PI walk always reads a coherent
waiter. The device VA=0 needs `pi` → zeroed memory, unreachable
in-tree; the SIGRETURN kernel-stamp route is structurally dead (plant is
userspace-only), not merely mis-aimed. Open lab item:
`selinux_cred_prepare` fault on a stale new cred during bring-up.

## 9. Reproducibility pitfalls (earned the hard way)

- Never pipe compiler output to `head` (SIGPIPE kills the link → stale
  binaries pushed). Redirect to a file, check the build return code,
  and always `md5sum` host vs device after push.
- `pkill -f <pattern>` matches the invoking shell itself; use `-x`.
- The device `timeout` never returns on D-state children;
  forked-close guards belong in the test binaries, not shell wrappers.
- `/data/local/tmp` is wiped on reboot — repush binaries after every
  boot.
- NDK headers clash with kernel uapi (`sigaction`, `ioctl` overloads)
  and omit facts (verify every dlsym'd signature against headers;
  cross-check ioctl struct sizes against the tree, not memory).
- `/proc/buddyinfo`, `/proc/slabinfo`, dmesg, kallsyms are unreadable
  from shell; tombstones come from
  `/data/log/dumpstate_lastkmsg_*.log.gz` (they are ZIPs containing
  `dumpstate_lastkmsg.lst`, not gzip streams).
- `errno=35` is EDEADLK, not EAGAIN: `CMP_REQUEUE_PI` succeeds on
  poll 1; o1s never overrode the 50 ms waiter-timeout default (other
  targets use 2 s), so stamp+fire historically ran post-wake on a
  dequeued waiter — the source of every early NULL. Fire inside the
  block window: 28+ clean `sched_setattr ret=0` walks on live waiters,
  zero reboots.
- Pipe-scan is circular pre-write: reading pipe pages needs hijacked
  fops first, so the in-tree stack scan cannot serve as a
  plant-residency oracle. FPU readback shows userspace regs only.
- Child-consumer interference: forked children inherit a stale waiter
  tid and walk it first (panic + reboot before the parent finishes) —
  hence the fire-time `/proc/self/task` gate (`O1S_NO_CHILD_CONSUME`).
- An mm spray of 32× fork-exhaustion-rebooted the phone twice (not via
  exploit); 4× is the reboot-safe level (`src/util.c`).

## 10. In-repo experiment record (this tree only)

- `src/slide_app.c`: slide waiter (writer+consumer moved before
  `UNLOCK_PI`); slide pselect (generalized byte-plotter over
  `slide_route_nfds`, NFDS sweep 320→1024 — full lock coverage needs
  nfds in [736,1024], derived and tested, still NULL); slide SIGRETURN
  (`SIGRETURN_FPSIMD_WAITER_OFF` default `0x148`, `SLIDE_SIG_OFF`
  runtime override, `SLIDE_CLEAN` / `NO_DIAG` / `NO_SCRUB` / `NO_POKE`
  builds).
- `src/fops.c` `prepare_pselect_fdsets`: pi-mapped in-words for the
  pselect stamp route.
- `src/util.c`: mm spray levels (see §9).
- `src/targets/o1s-G991BXXSJHZC2/target.h`: o1s tunables
  (`APP_PHYS_P0_ORACLE=0`, `SLIDE_PSELECT_WORD_SHIFT=0`,
  `O1S_PI_STAMP_FIX`, `O1S_NO_CHILD_CONSUME`, `O1S_PROBE_MARKER`,
  `O1S_MEASURE`); `p0_fingerprint.h` + `tools/generate_p0_fingerprint.pl`
  for the P0 oracle.
- `src/kernelsnitch/` (`futex_hash.h`, `kernelsnitch.h`, `timeutils.h`,
  `utils.h`): staged, unbuilt — see §6.
- Six stamp variants (in/ex/out words, cyclic parent,
  RED-terminating parent, `0xdeadbeef` marker-oracle, byte-plotter) all
  faulted at VA 0 — decisive miss signal, superseded by §2.

## 11. Reopen triggers + standing fronts

Standing: Mali r38 recon; oempocalypse-P2 watch.

What would reopen a write path: a post-SPL CVE with a public PoC
affecting 5.4 + unpriv reachability; a Mali GPU-side (shader compiler)
project allocation (days, untouched); a kernel infoleak primitive
(would re-open heap-indexing); a covering spray primitive for the
E-0x2F0 slot; a different device/revision.
