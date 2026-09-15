# IonStack_S21 — CVE-2026-43499 exploit port for Galaxy S21 (SM-G991B)

Device-specific IonStack payload for the Samsung Galaxy S21 (o1s) on
firmware `G991BXXSJHZC2`. Gives volatile root via LD_PRELOAD exploit +
`call_usermodehelper` root-helper daemon (same shape as IonStack-S22U /
IONSTACK-S22). **Status: research — blocked, see RESEARCH.md.**

| Field | Value |
|---|---|
| Model | SM-G991B |
| Device | o1s |
| Firmware | G991BXXSJHZC2 |
| Android | 12 / API 31 (`AP3A.240905.015.A2`, fingerprint `samsung/o1sxeea/o1s`) |
| Page size | 4096 |
| Kernel | 5.4.242-30958140-abG991BXXSJHZC2 |
| SoC | Exynos 2100 |
| Mitigations | CFI+PAC+PAN/UAO, KDP_CRED, SELinux enforcing, no userfaultfd |

Based on the IonStack CVE-2026-43499 implementation published in
NebuSec/CyberMeowfia (upstream `b850d3bddc74c3328d5fbcc0568d21962b55d949`)
and BuSung-dev/CVE-2026-43499-S25U, with thanks to F-19-F/IonStackQuest3.
Upstream Apache License 2.0 retained in LICENSE (see NOTICE).

## Layout

```
Makefile                  build (NDK r27+, ANDROID_NDK_HOME)
src/                      exploit source (o1s profile only)
src/targets/o1s-G991BXXSJHZC2/  target.h + p0_fingerprint.h
src/kernelsnitch/         mm_struct leak (futex hash collision)
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
/adb shell "/data/local/tmp/cve-2026-43499-root -c 'id; getenforce'"
```

Root (if achieved) lives only until reboot; nothing is flashed.

## Status / warnings

- **Blocked, parked with proofs** — see RESEARCH.md for the full account.
  The race stage panics the kernel (`sched_setattr →
  rt_mutex_adjust_prio_chain → _raw_spin_trylock` NULL fault) without ever
  landing the stamp: the 8-byte `lock` field sits in a copy-gap no surveyed
  blocking syscall covers (disasm-verified per-syscall depth map in
  RESEARCH.md). Pipe-reclaim gate systematically misses (`0/0`).
- Timing-sensitive; expect kernel panics. Reboot for clean slabs, keep the
  device idle while running. `/data/local/tmp` is wiped on reboot — repush
  binaries after every boot.
- Use only on devices you own or are explicitly authorized to test.
