#ifndef POINTER_ANALYSIS_H
#define POINTER_ANALYSIS_H

#include "Analyzer.h"

class PointerAnalysisPass : public IterativeModulePass {
private:
    void detectAliasPointersIndividual(Function*, AAResults*);

	void detectAliasPointers(Function *, AAResults &,
			PointerAnalysisMap &);

	Value *getSourcePointer(Value *);

    mutex storeMutex;

public:
	PointerAnalysisPass(GlobalContext *Ctx_)
		: IterativeModulePass(Ctx_, "PointerAnalysis") { }
	virtual bool doInitialization(llvm::Module *);
	virtual bool doFinalization(llvm::Module *);
	virtual bool doModulePass(llvm::Module *);
};

#endif
