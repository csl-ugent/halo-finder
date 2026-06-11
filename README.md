## Building a Linux kernel to bitcode

### Prepare Linux sources

1. Download & extract a recent kernel release from https://kernel.org

```sh
$ wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.14.1.tar.xz
$ tar xf linux-6.14.1.tar.xz
```

2. Copy the `.config` file (attached) to the root of the extracted directory

3. Modify.config: CONFIG_CC_HAS_ASM_GOTO, CONFIG_CC_HAS_ASM_GOTO_OUTPUT, and CONFIG_JUMP_LABEL to n (if listed), as the compilation process tends to reset this.

4. Patch kernel sources

Update `arch/x86/include/asm/cpufeature.h` to use the `static_cpu_has` variant inside `boot_cpu_has`.
Update `include/linux/compiler_types.h` to use the empty variant of the `__compiletime_assert` macro.
Update `include/linux/bitfield.h` to get rid of `__field_overflow` and `__bad_mask`.

5. Patch scripts/min-tool-version.sh to allow clang-12

### Prepare Build Environment

Use a docker image based on the following Dockerfile:
```
FROM ubuntu:rolling
ENV DEBIAN_FRONTEND noninteractive
ENV LLVM_COMPILER clang
RUN apt-get update && apt-get install -y clang-12 python3 llvm-12 lld-12 make libelf-dev bc bison texinfo libssl-dev flex file wget dwarves python3-pip cpio
RUN for f in /bin/llvm-*; do ln -s "$f" "$(echo $f | sed 's/-12$//')" ; done;
RUN ln -s /bin/clang-12 /bin/clang
RUN ln -s /bin/ld.lld-12 /bin/ld.lld
RUN pip install wllvm --break-system-packages
```

It's also necessary to build a custom clang build with the patch from the `disable-inline` directory applied.
This will then be mounted and used for the actual compilation.

### Build Linux sources

Actual build (inside root directory):
```sh
$ docker run --mount src=`pwd`,target=/linux,type=bind --mount src='/home/ndossche/thesis/crix/llvm/llvm-project/prefix-llvm-12',target=/llvm,type=bind -t -i --rm linux-kernel-llvm bash
$ cd linux
$ export LLVM_COMPILER_PATH=/llvm/bin
$ make LLVM=1 CC=wllvm -j$(nproc)
$ extract-bc vmlinux
```

## Building and Running HaLo

### Prerequisites

It requires a build of LLVM 14.0.6:

```sh
$ cd tool/llvm
$ ./fetch-llvm.sh
$ ./build-llvm.sh
```

### Building HaLo

```sh
$ cd tool/analyzer
$ make -j$(nproc)
```

### Running HaLo

```sh
$ cd tool
$ ./analyzer/build/lib/kanalyzer -t 0.1667 -c 1 -ignore-volatile path_to_vmlinux.bc &> output_filename
```

### Evaluation

The `dump_categories.py` script can be run to obtain the statistics of the results.
The categorisation is based on the output of the tool, and a mapping file that maps a field to a particular bug triage category.
The mapping is stored in the `tool/bug-studies/categorisatie` file and is a tab-separated file with the left side the field name and right side the category.

The following categories are possible (see paper also):

|Category name           |Description|
|------------------------|-----------|
|fp:init                 |False positive. Initialisation code.|
|fp:cleanup              |False positive. Cleanup code.|
|fp:safe                 |False positive. Benign race|
|fp:recheck              |False positive. The first access is a performance optimization and the second access actually does the work under a lock.|
|fp:cant-change          |False positive. This is a field that cannot change after initialisation.|
|fp:debug                |False positive. Kernel debugging related code.|
|fp:tool-limitation      |False positive. Limitation of precision due to tool implementation or design.|
|fp:incorrect-rule       |False positive. The rule is incorrect.|
|fp:error-reporting      |False positive. This is error-reporting code where developers don't care about data races (i.e. a special case of a benign race).|
|fp:comment              |False positive. There is a comment explaining why the race is safe.|
|fp:atomics              |False positive. Atomic-based synchronisation prevents the race.|
|unknown:lack-knowledge  |Unknown. Lack knowledge.|
|unknown:sudden-rc       |Unknown. The bug location suddenly uses an RCU instead of using the normally used lock.|
|unknown:other-protection|Unknown. Another type of unspecified protection could incidentally protect the access.|
|unknown:sysfs           |Unknown. The race happens in sysfs code, which is very inconsistent w.r.t. data race protection. Who knows whether this is a bug.|
|unknown:procfs          |Unknown. The race happens in procfs code, which is very inconsistent w.r.t. data race protection. Who knows whether this is a bug.|
|unknown:ioctl           |Unknown. The race happens in ioctl code, which is very inconsistent w.r.t. data race protection. Sometimes there can be true positives here but it's often hard to say.|
|tp                      |True positive.|
