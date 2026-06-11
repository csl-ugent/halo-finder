#!/bin/bash
cd llvm-project
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.6/clang-14.0.6.src.tar.xz
wget https://github.com/llvm/llvm-project/releases/download/llvmorg-14.0.6/llvm-14.0.6.src.tar.xz
echo "Extracting LLVM"
tar xf llvm-14.0.6.src.tar.xz
echo "Extracting Clang"
tar xf clang-14.0.6.src.tar.xz
mv clang-14.0.6.src clang
mv llvm-14.0.6.src llvm
