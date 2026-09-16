# Makefile -- link the libFuzzer harnesses in this directory against the
# ASan+UBSan core objects meson built in $(BUILD). Driven by run.sh inside a
# throwaway container; nothing here is installed on the host.
#
#   make SRC=/src BUILD=/out/build OUT=/out/bin          # build every harness
#   make SRC=/src BUILD=/out/build OUT=/out/bin props    # build + run yamlconf_props
#
# NOTE: core/tincd/.gitignore has a bare `Makefile` rule that matches at any
# depth, so this file must be force-added (git add -f) or kept un-ignored via
# the `!test/fuzz/Makefile` negation there. It was previously lost that way.

CC      ?= clang
SRC     ?= /src
BUILD   ?= /out/build
OUT     ?= /out/bin

FUZZDIR := $(dir $(lastword $(MAKEFILE_LIST)))
# -iquote (not -I) for the source tree, so quoted includes ("system.h", ...)
# resolve there while <dirent.h> and friends still pick the SYSTEM headers,
# not tincd's Windows shims -- this mirrors meson's inc_conf = include/ only.
INC     := -iquote $(SRC)/src -I$(SRC)/src/include -I$(BUILD)/src/include
SAN     := -fsanitize=address,undefined
BASEFLAGS := -g -O1 -fno-omit-frame-pointer $(INC)

LIBDIR  := $(BUILD)/src
# Daemon core: what transport/obfs/sf/classify harnesses need.
LIBS_D  := $(LIBDIR)/libtincd.a $(LIBDIR)/libcommon.a \
           $(LIBDIR)/libtinc_crypto.a \
           $(LIBDIR)/chacha-poly1305/libchacha_poly.a \
           $(LIBDIR)/ed25519/libed25519.a
# Client lib (invitation.c/pool.c/info.c); pulls symbols like recvline defined
# in tincctl.c, so only harnesses that also link tincctl_nomain.o use it.
LIBS_T  := $(LIBDIR)/libtinc.a $(LIBS_D)
SYSLIBS := -lssl -lcrypto -lz -llzo2 -llz4 -lncursesw -lreadline -lpthread -lm
GROUP_D := -Wl,--start-group $(LIBS_D) -Wl,--end-group $(SYSLIBS)
GROUP_T := -Wl,--start-group $(LIBS_T) -Wl,--end-group $(SYSLIBS)

# libFuzzer provides main() at link time; the core objects were built with
# -fsanitize=fuzzer-no-link so their coverage instrumentation matches.
LINK    := $(CC) $(BASEFLAGS) $(SAN),fuzzer

# Harnesses whose parser input reaches the socket before any authentication.
WRAP_SF   := -Wl,--wrap=receive_meta_bytes -Wl,--wrap=terminate_connection \
             -Wl,--wrap=sendto -Wl,--wrap=finish_connecting
WRAP_OBFS := -Wl,--wrap=sendto -Wl,--wrap=receive_meta_bytes \
             -Wl,--wrap=terminate_connection -Wl,--wrap=finish_connecting \
             -Wl,--wrap=handle_incoming_vpn_packet_decap

HARNESSES := fuzz_yamlconf fuzz_classify fuzz_invitation fuzz_pool fuzz_sf fuzz_obfs

.PHONY: all props clean
all: $(addprefix $(OUT)/,$(HARNESSES))

# tincctl.c carries variables[] (and cmd_config) that the invitation/pool/yaml
# harnesses reference; compile it once with main() renamed out of the way.
$(OUT)/tincctl_nomain.o: $(SRC)/src/tincctl.c
	@mkdir -p $(OUT)
	$(CC) $(BASEFLAGS) $(SAN) -fsanitize=fuzzer-no-link -Dmain=tincctl_main -c $< -o $@

$(OUT)/fuzz_classify: $(FUZZDIR)fuzz_classify.c
	@mkdir -p $(OUT)
	$(LINK) $< $(GROUP_D) -o $@

$(OUT)/fuzz_sf: $(FUZZDIR)fuzz_sf.c
	@mkdir -p $(OUT)
	$(LINK) $< $(WRAP_SF) $(GROUP_D) -o $@

$(OUT)/fuzz_obfs: $(FUZZDIR)fuzz_obfs.c
	@mkdir -p $(OUT)
	$(LINK) $< $(WRAP_OBFS) $(GROUP_D) -o $@

$(OUT)/fuzz_invitation: $(FUZZDIR)fuzz_invitation.c $(OUT)/tincctl_nomain.o
	@mkdir -p $(OUT)
	$(LINK) $< $(OUT)/tincctl_nomain.o $(GROUP_T) -o $@

$(OUT)/fuzz_pool: $(FUZZDIR)fuzz_pool.c $(OUT)/tincctl_nomain.o
	@mkdir -p $(OUT)
	$(LINK) $< $(OUT)/tincctl_nomain.o $(GROUP_T) -o $@

$(OUT)/fuzz_yamlconf: $(FUZZDIR)fuzz_yamlconf.c $(OUT)/tincctl_nomain.o
	@mkdir -p $(OUT)
	$(LINK) $< $(OUT)/tincctl_nomain.o $(GROUP_T) -o $@

# Property tests: their own main(), no fuzzer. Build and run.
props: $(FUZZDIR)yamlconf_props.c $(OUT)/tincctl_nomain.o
	@mkdir -p $(OUT)
	$(CC) $(BASEFLAGS) $(SAN) -fsanitize=fuzzer-no-link $< $(OUT)/tincctl_nomain.o $(GROUP_T) -o $(OUT)/yamlconf_props
	setarch $$(uname -m) -R $(OUT)/yamlconf_props

clean:
	rm -f $(addprefix $(OUT)/,$(HARNESSES)) $(OUT)/tincctl_nomain.o $(OUT)/yamlconf_props
