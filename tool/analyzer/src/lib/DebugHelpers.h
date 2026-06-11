#pragma once

#include <llvm/Pass.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/CFG.h>

using namespace llvm;

void dumpDebugValue(const Function* function);
StringRef getFieldNameFrom(const Module& M, const Function* function, Type* type, uint64_t offset);
std::string getBasicBlockName(const BasicBlock* BB);
