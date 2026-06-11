#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Support/ThreadPool.h>
#include <stack>
#include "PointerAnalysis.h"
#include "ClOptForward.h"

/// Alias types used to do pointer analysis.
#define MUST_ALIAS

bool PointerAnalysisPass::doInitialization(Module *M) {
	return false;
}

bool PointerAnalysisPass::doFinalization(Module *M) {
	return false;
}

Value *PointerAnalysisPass::getSourcePointer(Value *P) {

	Value *SrcP = P;
	stack<Value *> EI;

	EI.emplace(SrcP);
	while (!EI.empty()) {
		Value *TI = EI.top();
		EI.pop();

		// Possible sources
		if (isa<Argument>(TI)
				|| isa<AllocaInst>(TI)
				|| isa<CallInst>(TI)
				|| isa<GlobalVariable>(TI)
		   )
			return SrcP;

		if (UnaryInstruction *UI = dyn_cast<UnaryInstruction>(TI)) {
			Value *UO = UI->getOperand(0);
			if (UO->getType()->isPointerTy() && isa<Instruction>(UO)) {
				SrcP = UO;
				EI.emplace(SrcP);
			}
		}
		else if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(TI)) {
			SrcP = GEP->getPointerOperand();
			EI.emplace(SrcP);
		}
	}

	return SrcP;
}

/// Detect aliased pointers in this function.
void PointerAnalysisPass::detectAliasPointers(Function *F,
		AAResults &AAR,
		PointerAnalysisMap &aliasPtrs) {

	std::set<Value *> addr1Set;

	// Collect interesting pointers
	for (inst_iterator i = inst_begin(F), ei = inst_end(F);
			i != ei; ++i) {

		Instruction *I = dyn_cast<Instruction>(&*i);

		if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
			addr1Set.insert(LI->getPointerOperand());
		}
		else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
			addr1Set.insert(SI->getPointerOperand());
		}
		else if ( CallInst *CI = dyn_cast<CallInst>(I)) {
			for (unsigned j = 0, ej = CI->arg_size();
					j < ej; ++j) {
				Value *Arg = CI->getArgOperand(j);

				if (!Arg->getType()->isPointerTy())
					continue;
				addr1Set.insert(Arg);
			}
		}
	}

	// FIXME: avoid being stuck
	if (addr1Set.size() > 1000) {
		return;
	}

	for (auto Addr1 : addr1Set) {

		for (auto Addr2 : addr1Set) {

			if (Addr1 == Addr2)
				continue;

            storeMutex.lock();
			AliasResult AResult = AAR.alias(Addr1, Addr2);
            storeMutex.unlock();

			bool notAlias = true;

			if (AResult == llvm::AliasResult::MustAlias || AResult == llvm::AliasResult::PartialAlias)
				notAlias = false;

			else if (AResult == llvm::AliasResult::MayAlias) {
#ifdef MUST_ALIAS
				if (getSourcePointer(Addr1) == getSourcePointer(Addr2))
					notAlias = false;
#else
				notAlias = false;
#endif
			}

			if (notAlias)
				continue;

			auto as = aliasPtrs.find(Addr1);
			if (as == aliasPtrs.end()) {
				SmallPtrSet<Value *, 16> sv;
				sv.insert(Addr2);
                storeMutex.lock();
				aliasPtrs[Addr1] = sv;
                storeMutex.unlock();
			} 
			else {
				as->second.insert(Addr2);
			}
		}
	}
}

void PointerAnalysisPass::detectAliasPointersIndividual(Function* F, AAResults* AAR) {
    PointerAnalysisMap aliasPtrs;
    detectAliasPointers(F, *AAR, aliasPtrs);

    // Save pointer analysis result.
    storeMutex.lock();
    Ctx->FuncPAResults[F] = aliasPtrs;
    //Ctx->FuncAAResults[F] = &AAR;
    storeMutex.unlock();
}

bool PointerAnalysisPass::doModulePass(Module *M) {

	// Save TargetLibraryInfo.
	Triple ModuleTriple(M->getTargetTriple());
	TargetLibraryInfoImpl TLII(ModuleTriple);

	// Run BasicAliasAnalysis pass on each function in this module.
	// XXX: more complicated alias analyses may be required.
	auto *FPasses = new legacy::FunctionPassManager(M);
	auto *AARPass = new AAResultsWrapperPass();

	FPasses->add(AARPass);

	FPasses->doInitialization();
	for (Function &F : *M) {
		if (F.isDeclaration())
			continue;
		FPasses->run(F);
	}
	FPasses->doFinalization();

	// Basic alias analysis result.
	AAResults &AAR = AARPass->getAAResults();

    ThreadPool threadPool(hardware_concurrency(ThreadCount));
	for (auto& f : *M) {
		if (!f.empty())
            threadPool.async(&PointerAnalysisPass::detectAliasPointersIndividual, this, &f, &AAR);
	}

    threadPool.wait();

	return false;
}
