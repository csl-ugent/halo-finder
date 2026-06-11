#pragma once

#include "Analyzer.h"
#include "Common.h"

class TypeRemapperPass : public IterativeModulePass {
public:
    TypeRemapperPass(GlobalContext *Ctx_)
            : IterativeModulePass(Ctx_, "TypeRemapper") { }

    virtual bool doInitialization(llvm::Module *);
    virtual bool doFinalization(llvm::Module *);
    virtual bool doModulePass(llvm::Module *);
};
