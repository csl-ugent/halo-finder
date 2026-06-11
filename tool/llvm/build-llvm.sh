#!/bin/bash -e


# LLVM version: 14.0.6 (as of 30/08/2022)

ROOT=$(git rev-parse --show-toplevel)/tool
cd $ROOT/llvm/llvm-project

if [ ! -d "build" ]; then
  mkdir build
fi

cd build
cmake -DLLVM_TARGET_ARCH="X86" -DLLVM_ENABLE_DUMP=ON -DLLVM_TARGETS_TO_BUILD="X86" -DLLVM_INCLUDE_BENCHMARKS=OFF -DCMAKE_BUILD_TYPE=Release \
			-DLLVM_ENABLE_PROJECTS="clang" -G "Unix Makefiles" ../llvm
make -j8

if [ ! -d "$ROOT/llvm/llvm-project/prefix" ]; then
  mkdir $ROOT/llvm/llvm-project/prefix
fi

cmake -DCMAKE_INSTALL_PREFIX=$ROOT/llvm/llvm-project/prefix -P cmake_install.cmake
