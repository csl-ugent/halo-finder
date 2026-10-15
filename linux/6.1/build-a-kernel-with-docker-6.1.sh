#!/bin/bash

# For example, if 966f331403dc3ed04ff64eaf3930cf1267965e53 is a fix for CVE-2025-21999 on the Linux 6.1 branch, run
# ./build-a-kernel-with-docker-6.1.sh CVE-2025-21999 966f331403dc3ed04ff64eaf3930cf1267965e53
# 
# Once it starts the configuration of the new options since the baseline, just keep pressing enter continuously a while until the build system stops asking questions (this just gets the default options selected). If at some point the build would fail, try manually setting the CONFIG_FORTIFY_SOURCE=n in .config
#
# You will need to create a BASEDIR directory
#   * which contains as a subdirectory a checkout of the stable Linux kernel repository (ie, contains the backports), such as https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/
#   * this Linux repository should be named linux-${VERSION}-base, i.e., linux-6.1-base
#   * override the BASEDIR variable below
#   * the script will create a subdirectory 6.1 (ie, ${VERSION), in which this script will create a checkout and build per CVE you invoke this script with
# You will to override PATCHESDIR to point to the directory this build-a-kernel-with-docker-6.1.sh is in
# Set DOCKER to the docker image you built for the analyzer/clang 12
# Set LLVMPREFIX to the prefix of the install directory in which the patched llvm-12/clang-12 is built
# Set ANALYZERBASE to the directory in which the source of HaLo Finder tool is (i.e., it has an ${ANALYZERBASE}/analyzer/build/lib/kanalyzer file)

set -e

CVE=$1
FIXCOMMIT=$2

VERSION=6.1

BASEDIR=/home/bcoppens/nora/linux-cve-experiments/
PATCHESDIR=/home/bcoppens/nora/
BASEKERNEL=linux-${VERSION}-base
DOCKER=bcoppens:kernelcompile
LLVMPREFIX=/home/bcoppens/nora/thesis/crix/llvm/llvm-12/prefix/
ANALYZERBASE=/home/bcoppens/nora/thesis/crix/

mkdir -p $VERSION

OURDIR=./${VERSION}/${CVE}--${VERSION}--${FIXCOMMIT}

cd $BASEDIR
git clone ./$BASEKERNEL/ ./${OURDIR}

cd ${OURDIR}

git checkout "${FIXCOMMIT}^"

patch -p1 < ${PATCHESDIR}6.1-patch-baseline
(patch -p1 < ${PATCHESDIR}6.1-patch-compiler_types_option_a) || (patch -p1 < ${PATCHESDIR}6.1-patch-compiler_types_option_b)
(patch -p1 < ${PATCHESDIR}6.1-patch-nospec) || echo "This patch cannot be applied, that's ok I hope"
(patch -p1 < ${PATCHESDIR}6.1-patch-wwan) || echo "This patch cannot be applied, that's ok I hope"
(patch -p1 < ${PATCHESDIR}6.1-patch-swapops) || echo "This patch cannot be applied, that's ok I hope"
(patch -p1 < ${PATCHESDIR}6.1-patch-libmake) || echo "This patch cannot be applied, that's ok I hope"
(patch -p1 < ${PATCHESDIR}6.1-patch-static_cpu_has) || echo "This patch cannot be applied, that's ok I hope"

cp -a ${PATCHESDIR}6.1-config .config # TODO: no to FORTIFY!

echo '#!/bin/bash' > ./build.sh
#echo 'cd /linux ; export PATH="/llvm/bin:$PATH" ; make LLVM=1 CC=wllvm -j$(nproc)' >> ./build.sh
echo 'cd /linux ; export PATH="/llvm/bin:$PATH" ; time make LLVM=1 CC=wllvm -j10 ; time extract-bc vmlinux' >> ./build.sh
# echo 'make LLVM=1 CC=wllvm -j$(nproc) vmlinux.o; time extract-bc vmlinux.o' >> ./build.sh
# multiple runs, at least one should not crash
echo 'time /analyzer/analyzer/build/lib/kanalyzer -t 0.1667 --dump-locking-counts /linux/vmlinux.bc &> /linux/kanalyzer-run-1' >> ./build.sh
echo 'time /analyzer/analyzer/build/lib/kanalyzer -t 0.1667 --dump-locking-counts /linux/vmlinux.bc &> /linux/kanalyzer-run-2' >> ./build.sh
echo 'time /analyzer/analyzer/build/lib/kanalyzer -t 0.1667 --dump-locking-counts /linux/vmlinux.bc &> /linux/kanalyzer-run-3' >> ./build.sh

chmod a+x ./build.sh

docker run --mount src=`pwd`,target=/linux,type=bind --mount src=${LLVMPREFIX},target=/llvm,type=bind --mount src=${ANALYZERBASE},target=/analyzer,type=bind -t -i --rm ${DOCKER} '/linux/build.sh'

