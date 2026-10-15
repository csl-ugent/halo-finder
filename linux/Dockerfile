FROM ubuntu:22.04
ENV DEBIAN_FRONTEND noninteractive
ENV LLVM_COMPILER clang
RUN apt-get update && apt-get install -y clang-14 python3 llvm-14 lld-14 make libelf-dev bc bison texinfo libssl-dev flex file wget dwarves python3-pip cpio binutils-aarch64-linux-gnu
RUN for f in /bin/llvm-*; do ln -s "$f" "$(echo $f | sed 's/-14$//')" ; done;
RUN ln -s /bin/clang-14 /bin/clang
RUN ln -s /bin/clang++-14 /bin/clang++
RUN ln -s /bin/ld.lld-14 /bin/ld.lld
RUN pip install wllvm
RUN apt update && apt install -y cmake zlib1g-dev libc++-dev vim
