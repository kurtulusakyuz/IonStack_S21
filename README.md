# IonStack_S21 — CVE-2026-43499 research for Galaxy S21 (SM-G991B)

Device-specific IonStack payload for the Samsung Galaxy S21 (o1s) on
firmware `G991BXXSJHZC2`. **Status: research CLOSED — deterministic
DoS-only; the kernel write path is proven impossible on this build.
Full evidence in RESEARCH.md.**

| Field | Value |
|---|---|
| Model | SM-G991B |
| Device | o1s |
| Firmware | G991BXXSJHZC2 |
| Android | 15 / API 35 (`AP3A.240905.015.A2`, fingerprint `samsung/o1sxeea/o1s`) |
| Page size | 4096 |
| Kernel | 5.4.242-30958140-abG991BXXSJHZC2 |
| SoC | Exynos 2100 |
| Mitigations | CFI+PAC+PAN/UAO, KDP_CRED, SELinux enforcing, no userfaultfd |

Based on the IonStack CVE-2026-43499 implementation published in
NebuSec/CyberMeowfia (upstream `b850d3bddc74c3328d5fbcc0568d21962b55d949`)
and BuSung-dev/CVE-2026-43499-S25U, with thanks to F-19-F/IonStackQuest3.
Upstream Apache License 2.0 retained in LICENSE (see NOTICE).

## Final state (read this first)

The GhostLock write program for this device is **finished and closed**,
not paused. What was proven, in order:

1. **The bug is real and present.** `remove_waiter()` clears
   `current->pi_blocked_on` instead of `waiter->task->pi_blocked_on`,
   so a `FUTEX_CMP_REQUEUE_PI` rollback leaves a dangling pointer to a
   stack `rt_waiter`. Upstream fix `3bfdc63` is absent from 5.4.242.
2. **The trigger is 100% reliable.** The 3-thread cycle (owner →
   chain → waiter → target deadlock, main CMP fails EDEADLK) plus a
   consumer `sched_setattr` reproduces a device-identical Oops
   (`rt_mutex_adjust_prio_chain+0x108` → `_raw_spin_trylock+0x1c`,
   fault VA 0) both in a KDP-less QEMU guest and on the phone itself
   (lastkmsg `118`/`119`). The dangling slot is fully mapped
   (stack-top `E-0x328`, lifecycle characterized via QEMU+GDB).
3. **The write is structurally impossible here.** Nine syscall-spray
   families were depth-mapped — none reaches the slot; slab-reclaim is
   blocked by an owner-liveness Catch-22; and the decisive fire-time
   dump shows the sigreturn copy delivers ONLY at victim+0x40 while the
   walked gate field `lock` (+0x38) is NEVER attacker-controlled
   (15/15 dumps).Independent ports (ASUS i005, AQUOS sigreturn route)
   hit the same wall. Geometry, not probability.
4. **What survives is a deterministic reboot primitive.** NULL-lock
   walks panic the kernel and reboot the phone — a reliable DoS, not a
   privilege escalation.

Related 2026 kernel LPE avenues were also closed on this build by
firmware config (`USER_NS`, `RDS`, `CRYPTO_USER_API_AEAD` all unset;
MFC double-free unreachable with `MFC_USE_DMABUF_CONTAINER=n`;
AF_ALG/eBPF gated for shell). The remaining open fronts live outside
this repo's scope: Mali-G78 r38 recon (`/dev/mali0` is shell-openable),
oempocalypse-P2 watch, and the final report. Post-write artifacts
(KernelSU `.ko` + `ksud` built for this exact firmware) are staged
separately by the owner; the `src/kernelsnitch/` headers in this tree
remain staged but unbuilt (no consumer exists without a write).

This repo is kept as the complete, self-contained record of the o1s
GhostLock campaign: source, target profile, geometry notes, and
verdicts. Binaries built from it are reproducers and oracles
(Oops-VA / return-code / dump based), not root exploits.

## Layout

```
Makefile                  build (NDK r27+, ANDROID_NDK_HOME)
src/                      exploit source (o1s profile only)
src/targets/o1s-G991BXXSJHZC2/  target.h + p0_fingerprint.h
src/kernelsnitch/         mm_struct leak (futex hash collision, staged)
tools/                    p0 fingerprint helper
RESEARCH.md               research notes (geometry, verdicts)
```

## Build

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk
make clean all
# SLIDE_WRITER_SEL=1|2|3 selects mcast/sigreturn(default)/xattr writers.
# Unset selects the experimental pselect writer (see RESEARCH.md).
```

Outputs (`build/o1s-G991BXXSJHZC2/`):
`cve-2026-43499` (LD_PRELOAD payload), `cve-2026-43499-app.so` (app payload),
`cve-2026-43499-root` (root helper).

## Deploy & run

```sh
adb push build/o1s-G991BXXSJHZC2/cve-2026-43499 /data/local/tmp/cve-2026-43499
adb push build/o1s-G991BXXSJHZC2/cve-2026-43499-root /data/local/tmp/cve-2026-43499-root
adb shell chmod 755 /data/local/tmp/cve-2026-43499 /data/local/tmp/cve-2026-43499-root
adb shell "LD_PRELOAD=/data/local/tmp/cve-2026-43499 sh"
# on success:
adb shell "/data/local/tmp/cve-2026-43499-root -c 'id; getenforce'"
```

Expectation management: on this build "success" means the trigger walk
and its oracle output — a NULL-lock walk reboots the device instead of
yielding root (see "Final state" above). Root, if ever achieved via a
future write primitive, lives only until reboot; nothing is flashed.

## Status / warnings

- **DoS-only, write path closed with evidence** — see RESEARCH.md for
  the full account (slot geometry, spray closure, SIGRETURN grand
  model, decisive fire-time dump, on-device confirmation).
- Timing-sensitive; expect kernel panics. Reboot for clean slabs, keep the
  device idle while running. `/data/local/tmp` is wiped on reboot — repush
  binaries after every boot.
- Never pipe compiler output to `head` (use a file + return code), and
  always `md5sum` host vs device after push — see RESEARCH.md §9.
- Use only on devices you own or are explicitly authorized to test.
