# Build the single-file `mcp` binary.
#
# No Python interpreter is involved: container parsing, MCS decryption and pyc
# writing are C, and decompilation is a bundled pycdc (Rust) embedded as a
# zlib image. The result is one static executable.
#
#   make NDK=/workspace/ndk/android-ndk-r29     Android/Termux build (ships)
#   make                                        glibc build, for local tests
#   make check                                  ABI + smoke test
#   make clean

# Single source of truth for the version: passed to the compiler and used for
# the release tag.
VERSION ?= 1.0.0

.DEFAULT_GOAL := all

CC      ?= cc
STRIP   ?= strip

# ---------------------------------------------------------------- toolchain
ifneq ($(NDK),)
  # Android/bionic. A glibc static binary builds and runs on a desktop and then
  # dies with SIGSYS on Termux, because Android's seccomp filter rejects the
  # syscalls glibc's startup path issues.
  API      ?= 24
  TC        = $(NDK)/toolchains/llvm/prebuilt/linux-arm64
  CC        = $(TC)/bin/aarch64-linux-android$(API)-clang
  STRIP     = $(TC)/bin/llvm-strip
  SYSROOT   = --sysroot=$(TC)/sysroot
else
  SYSROOT   =
endif

# ------------------------------------------------------------------- layout
# Per-toolchain build tree: objects built against glibc cannot be relinked
# into a bionic binary, and make only compares timestamps.
BUILD    := .build/$(if $(NDK),ndk-$(notdir $(NDK)),native)
BIN      := mcp
PYCDC    := vendor/pycdc
PYCDC_C  := $(BUILD)/pycdc_res.c
PYCDC_O  := $(BUILD)/pycdc_res.o

CSRC := csrc/main.c csrc/util.c csrc/nls.c csrc/crypto.c csrc/rc4.c \
        csrc/mcs_parse.c csrc/mcs_emit.c csrc/opcode_tbl.c \
        csrc/mcpk_hash.c csrc/mcpk.c csrc/unescape.c csrc/decoy.c
OBJS := $(patsubst csrc/%.c,$(BUILD)/%.o,$(CSRC)) $(PYCDC_O)

# ------------------------------------------------------------------- flags
CFLAGS  ?= -O2
CFLAGS  += -Wall -Wextra -std=c11 -D_GNU_SOURCE
CPPFLAGS += -Icsrc -DMCP_VERSION=\"$(VERSION)\"
LDFLAGS += -static
LDLIBS  += -lz -lm

# The same output name hides which libc it holds, and make only compares
# timestamps. TAG is rewritten (only) when the toolchain identity changes.
TAG      := .build/.toolchain
TAG_ID   := $(if $(NDK),ndk-$(API),native)
$(TAG): FORCE
	@mkdir -p .build
	@printf '%s' '$(TAG_ID)' | cmp -s - $@ || printf '%s' '$(TAG_ID)' > $@

# ------------------------------------------------------------------ targets
.PHONY: all clean check FORCE
all: $(BIN)

$(BIN): $(OBJS) $(TAG) | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SYSROOT) -o $@.tmp $(OBJS) $(LDLIBS)
	$(STRIP) $@.tmp
	mv $@.tmp $@
	@echo "[+] built $@ ($$(stat -c %s $@) bytes)"

$(BUILD)/%.o: csrc/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

# The embedded decompiler; rebuilt only when vendor/pycdc changes.
$(PYCDC_C): $(PYCDC) mkres.py | $(BUILD)
	python3 mkres.py $(PYCDC) $@ mcp_pycdc

$(PYCDC_O): $(PYCDC_C) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $(PYCDC_C)

$(BUILD):
	@mkdir -p $@

# The ABI check matters more than it looks: a glibc-linked binary builds and
# runs fine on a desktop, then dies with SIGSYS on Termux.
check: $(BIN)
	@if strings -a $(BIN) | grep -q "__libc_early_init"; then \
	    echo "[!] $(BIN) is linked against glibc -- it will die with SIGSYS on Android"; \
	    echo "    rebuild with: make NDK=/path/to/android-ndk-r29"; exit 1; \
	fi
	@strings -a $(BIN) | grep -q "bionic" \
	    && echo "[+] bionic (Android) ABI" \
	    || echo "[!] no bionic marker found -- check the toolchain"
	@./$(BIN) --help >/dev/null 2>&1 && echo "[+] --help ok"
	@./$(BIN) pack a b >/dev/null 2>&1 && { echo "[!] pack still present"; exit 1; } || echo "[+] pack removed"

clean:
	rm -rf .build
