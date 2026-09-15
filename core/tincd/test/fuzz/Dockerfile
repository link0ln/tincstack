# Throwaway toolbox for the libFuzzer harnesses in this directory: clang with
# libFuzzer/ASan/UBSan plus everything the meson build of the core needs.
# Nothing here is installed on the host. See run.sh.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang lld llvm libclang-rt-14-dev meson ninja-build pkg-config make \
        libssl-dev zlib1g-dev liblzo2-dev liblz4-dev \
        libncurses-dev libreadline-dev python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV CC=clang
WORKDIR /work
