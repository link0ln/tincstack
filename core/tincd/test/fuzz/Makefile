# Makefile -- links the libFuzzer harnesses against the ASan/UBSan core built
# by run.sh (meson, -fsanitize=fuzzer-no-link). Invoked inside the toolbox
# container only: `make SRC=/src BUILD=/out/build OUT=/out/bin [props]`.
#
# (Reconstructed by stream L: the original was never committed because
# core/tincd/.gitignore ignores every `Makefile`; it is force-added now so
# `run.sh build` works from a clean checkout.)

SRC   ?= /src
BUILD ?= /out/build
OUT   ?= /out/bin
CC    ?= clang

SAN     = -fsanitize=address,undefined -fno-omit-frame-pointer
INC     = -iquote $(SRC)/src -iquote $(BUILD)/src/include -iquote $(BUILD)/src
CFLAGS  = -g -O1 -std=gnu11 -Wall $(SAN) $(INC)
FUZZ    = -fsanitize=fuzzer

L       = $(BUILD)/src
LIBS_D  = -Wl,--start-group $(L)/libtincd.a $(L)/libcommon.a $(L)/ed25519/libed25519.a \
          $(L)/chacha-poly1305/libchacha_poly.a $(L)/libtinc_crypto.a -lm -lz -llzo2 -llz4 \
          -lssl -lcrypto -Wl,--end-group
LIBS_T  = -Wl,--start-group $(L)/libtinc.a $(L)/libcommon.a $(L)/ed25519/libed25519.a \
          $(L)/chacha-poly1305/libchacha_poly.a $(L)/libtinc_crypto.a -lncursesw -ltinfo \
          -lreadline -lssl -lcrypto -lz -llzo2 -llz4 -lm -Wl,--end-group

HARNESSES = fuzz_yamlconf fuzz_classify fuzz_invitation fuzz_pool fuzz_sf
SF_WRAPS  = -Wl,--wrap=receive_meta_bytes,--wrap=terminate_connection,--wrap=sendto,--wrap=finish_connecting

all: $(addprefix $(OUT)/,$(HARNESSES)) $(OUT)/yamlconf_props

$(OUT):
	mkdir -p $(OUT)

# The parser/emitter alone: what the daemon and the CLI both link.
$(OUT)/fuzz_yamlconf: fuzz_yamlconf.c | $(OUT)
	$(CC) $(CFLAGS) $(FUZZ) -o $@ $< $(LIBS_T)

$(OUT)/yamlconf_props: yamlconf_props.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS_T)

# The front classifier (transport_table.c has no other daemon dependency).
$(OUT)/fuzz_classify: fuzz_classify.c | $(OUT)
	$(CC) $(CFLAGS) $(FUZZ) -o $@ $< $(LIBS_D)

# invitation.c lives in libtinc.a; variables[] lives in tincctl.c, so the CLI
# is linked in with its main() renamed.
$(OUT)/tincctl_nomain.o: $(SRC)/src/tincctl.c | $(OUT)
	$(CC) $(CFLAGS) -Dmain=tincctl_main -c -o $@ $<

$(OUT)/fuzz_invitation: fuzz_invitation.c $(OUT)/tincctl_nomain.o | $(OUT)
	$(CC) $(CFLAGS) $(FUZZ) -o $@ $< $(OUT)/tincctl_nomain.o $(LIBS_T)

$(OUT)/fuzz_pool: fuzz_pool.c $(OUT)/tincctl_nomain.o | $(OUT)
	$(CC) $(CFLAGS) $(FUZZ) -o $@ $< $(OUT)/tincctl_nomain.o $(LIBS_T)

# The single-flow receive path with its daemon edges wrapped (see fuzz_sf.c).
$(OUT)/fuzz_sf: fuzz_sf.c | $(OUT)
	$(CC) $(CFLAGS) $(FUZZ) -o $@ $< $(SF_WRAPS) $(LIBS_D)

# The yamlconf property tests: build and run (run.sh check). ASLR off for the
# process, as run.sh does for the harnesses (ASan vs vm.mmap_rnd_bits=32).
props: $(OUT)/yamlconf_props
	setarch $$(uname -m) -R $(OUT)/yamlconf_props

.PHONY: all props
