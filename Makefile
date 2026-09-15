# IonStack_S21 o1s-G991BXXSJHZC2 build
API ?= 35
OUTDIR ?= build/o1s-G991BXXSJHZC2
TARGET_HEADER := src/targets/o1s-G991BXXSJHZC2/target.h
TARGET_INCLUDE := targets/o1s-G991BXXSJHZC2/target.h

# Stack-writer select: 1=mcast, 2=sigreturn (default), 3=xattr.
# Unset/empty SLIDE_WRITER_SEL leaves SLIDE_STACK_WRITER undefined and
# selects the pselect stack writer (experimental, see MEMORY.md).
APP_TARGET_CFLAGS :=
ifdef SLIDE_WRITER_SEL
APP_TARGET_CFLAGS := -DSLIDE_STACK_WRITER=$(SLIDE_WRITER_SEL)
else
APP_TARGET_CFLAGS := -DSLIDE_STACK_WRITER=2
endif

PRELOAD_SRCS := \
  src/main.c \
  src/util.c \
  src/slide.c \
  src/fops.c \
  src/exp_stamp.c \
  src/resbit_route.c \
  src/pipe.c \
  src/root.c \
  src/preload.c

APP_PRELOAD_SRCS := \
  src/main.c \
  src/util.c \
  src/slide_app.c \
  src/fops.c \
  src/exp_stamp.c \
  src/resbit_route.c \
  src/pipe.c \
  src/root.c \
  src/preload.c

PRELOAD := $(OUTDIR)/cve-2026-43499
APP_PRELOAD := $(OUTDIR)/cve-2026-43499-app.so
ROOT_HELPER := $(OUTDIR)/cve-2026-43499-root

COMMON_CFLAGS := \
  -O2 -g0 -Wall -Wextra \
  -Wno-unused-parameter -Wno-sign-compare \
  -Isrc -DTARGET_HEADER='"$(TARGET_INCLUDE)"'

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
TARGET_CC := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android$(API)-clang
else
TARGET_CC := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$(API)-clang
endif

ifeq ($(wildcard $(TARGET_CC)),)
$(error set ANDROID_NDK_HOME to an Android NDK containing $(TARGET_CC))
endif

.DEFAULT_GOAL := all
.PHONY: all clean

all: $(PRELOAD) $(APP_PRELOAD) $(ROOT_HELPER)

$(OUTDIR):
	mkdir -p $@

$(PRELOAD): $(PRELOAD_SRCS) $(TARGET_HEADER) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) -fPIC $(COMMON_CFLAGS) $(PRELOAD_SRCS) \
	  -shared -pthread -o $@

$(ROOT_HELPER): src/su_daemon.c | $(OUTDIR)
	$(TARGET_CC) -fPIE -pie -O2 -g0 -Wall -Wextra $< -ldl -o $@

$(APP_PRELOAD): $(APP_PRELOAD_SRCS) $(TARGET_HEADER) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 $(APP_TARGET_CFLAGS) -fPIC $(COMMON_CFLAGS) $(APP_PRELOAD_SRCS) \
	  -shared -pthread -o $@

clean:
	rm -rf $(OUTDIR)
