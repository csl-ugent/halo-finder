//===-- DataFlowAnalysis.cc - Utils for data-flow analysis------===//
// 
// This file implements commonly used functions for data-flow
// analysis
//
//===-----------------------------------------------------------===//

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/AbstractCallSite.h>

#include "DataFlowAnalysis.h"
#include "Helpers.h"


/// Get aliased pointers for this pointer.
void DataFlowAnalysis::getAliasPointers(Value *Addr,
		std::set<Value *> &aliasAddr,
		const PointerAnalysisMap &aliasPtrs) const {
	aliasAddr.insert(Addr);

	auto it = aliasPtrs.find(Addr);
	if (it == aliasPtrs.end())
		return;

	for (auto itt : it->second)
		aliasAddr.insert(itt);
}

/// Track the source of the CriticalVariable. First, determine the
/// type of the LoadPointer, identify the alias if any. For each alias,
/// extract the store operand.
void DataFlowAnalysis::findSourceCV(Value *V,
		set<Value *> &CVSet, set<Value *> &TrackedSet, int interproceduralDepth) {
    if (isa<Constant>(V) && !isa<ConstantExpr>(V))
        return;

    if (!TrackedSet.insert(V).second)
		return;

#if 0
    if (auto I = dyn_cast<Instruction>(V)) {
        if (I->getFunction()->getName().equals("hci_conn_request_evt")) {
            static mutex debugMutex;
            OP << "I dump: ";
            I->dump();
        }
    }
#endif

	if (auto CE = dyn_cast<ConstantExpr>(V)) {
		findSourceCV(CE->getOperand(0), CVSet, TrackedSet, interproceduralDepth);
	} else if (auto A = dyn_cast<Argument>(V)) {
		CVSet.insert(V);
		if (!A->getParent()) {
			return;
		}

#if 1
        if (interproceduralDepth > 0) {
            bool debug = false; //A->getParent()->getName().equals("btrfs_check_zoned_mode");
            if (debug) A->dump();
            auto callersIt = Ctx->Callers.find(A->getParent());
            if (callersIt != Ctx->Callers.end()) {
                if (callersIt->second.size() < 100) { // Avoid explosion
                    for (CallInst *Caller: callersIt->second) {
                        if (A->getArgNo() >= Caller->arg_size())
                            continue;
                        Value *Arg = Caller->getArgOperand(A->getArgNo());
                        if (debug) Arg->dump();
                        findSourceCV(Arg, CVSet, TrackedSet, interproceduralDepth - 1);
                    }
                }
            }
        }
#endif
	} else if (auto CI = dyn_cast<CallInst>(V)) {
		CVSet.insert(V);
        // Track simple getters
        if (!CI->isIndirectCall() && CI->arg_size() == 1 && CI->getArgOperand(0)->getType()->isPointerTy()) {
            auto it = Ctx->Callees.find(CI);
            if (it != Ctx->Callees.end()) {
                for (const auto *function: it->second) {
                    if (function->size() == 1) {
                        CVSet.insert(CI->getArgOperand(0));
                        findSourceCV(CI->getArgOperand(0), CVSet, TrackedSet, interproceduralDepth);
                    }
                }
            }
        }
	} else if (auto SI = dyn_cast<SelectInst>(V)) {
		findSourceCV(SI->getTrueValue(), CVSet, TrackedSet, interproceduralDepth);
		findSourceCV(SI->getFalseValue(), CVSet, TrackedSet, interproceduralDepth);
	} else if (auto GEP = dyn_cast<GetElementPtrInst>(V)) {
		CVSet.insert(V);
		// TODO: consider aliases
		findSourceCV(GEP->getPointerOperand(), CVSet, TrackedSet, interproceduralDepth);
	} else if (auto PN = dyn_cast<PHINode>(V)) {
		for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; ++i) {
			Value *IV = PN->getIncomingValue(i);
			findSourceCV(IV, CVSet, TrackedSet, interproceduralDepth);
		}
	} else if (auto LI = dyn_cast<LoadInst>(V)) {
        auto pointerOperand = LI->getPointerOperand();
        if (isa<GetElementPtrInst>(pointerOperand) || isa<BitCastInst>(pointerOperand)) {
            findSourceCV(pointerOperand, CVSet, TrackedSet, interproceduralDepth);
        }

        // Get aliases
        Function *F = LI->getFunction();
        std::set<Value *> AliasSet;
        if (auto it = Ctx->FuncPAResults.find(F); it != Ctx->FuncPAResults.end()) {
            getAliasPointers(LI->getPointerOperand(), AliasSet, it->second);
            // To find all stores using the pointer, use alias analysis
            for (auto alias: AliasSet) {
                if (TrackedSet.insert(alias).second) {
                    for (auto U: alias->users()) {
                        auto SI = dyn_cast<StoreInst>(U);
                        if (SI && alias == SI->getPointerOperand()) {
                            findSourceCV(SI->getValueOperand(), CVSet, TrackedSet, interproceduralDepth);
                        }
                    }
                }
            }
        }
	}
	// Default policy for unary and binary
	else if (auto UI = dyn_cast<UnaryInstruction>(V)) {
		Value *UO = UI->getOperand(0);
		findSourceCV(UO, CVSet, TrackedSet, interproceduralDepth);
	} else if (auto BO = dyn_cast<BinaryOperator>(V)) {
		for (unsigned i = 0, e = BO->getNumOperands();
				i != e; ++i) {
			Value *Opd = BO->getOperand(i);
			findSourceCV(Opd, CVSet, TrackedSet, interproceduralDepth);
		}
	}
}

void DataFlowAnalysis::findObjectCriticalSourcesAndIndirections(Value *V, vector<ValueWithIndirections> &CVSet, set<Value *> &TrackedSet, int interproceduralDepth, float amountOfIndirections) {
    if (isa<Constant>(V))
        return;

    if (!TrackedSet.insert(V).second)
        return;

    if (auto A = dyn_cast<Argument>(V)) {
        if (!A->getParent()) {
            return;
        }



#if 1
        if (interproceduralDepth > 0) {
            auto callersIt = Ctx->Callers.find(A->getParent());
            CVSet.emplace_back(ValueWithIndirections{.type = ValueWithIndirections::ValueType::Value, .value = V, .indirections = amountOfIndirections / (callersIt != Ctx->Callers.end() ? callersIt->second.size() : 1)});
            if (callersIt != Ctx->Callers.end()) {
                if (callersIt->second.size() < 100) { // Avoid explosion
                    for (CallInst *Caller: callersIt->second) {
                        if (A->getArgNo() >= Caller->arg_size())
                            continue;

                        Value *Arg = Caller->getArgOperand(A->getArgNo());

                        if (Caller->isIndirectCall()) {
                            set<const Value*> trackedSet;
                            FieldSourceSet sourceSet;
                            findFields(*Caller->getModule(), Caller->getCalledOperand(), sourceSet, trackedSet, false);
                            for (auto& source : sourceSet) {
                                auto& field = source.fieldPtr()->last();
                                CVSet.emplace_back(ValueWithIndirections{.type = ValueWithIndirections::ValueType::Interface, .fieldContainingType = field.typePtr(), .fieldOffset = field.offset, .indirections = amountOfIndirections});
                            }
                        } else {
                            set<Value*> TrackedSetParent{TrackedSet};
                            //OP << A->getParent()->getName() << " -> " << Caller->getFunction()->getName() << " [label=\" " << amountOfIndirections << "\"];\n";
                            // Note! Passing an argument is not an indirection, because indirections count the operations on the values,
                            // and passing a value is not an operation. Furthermore, semantically it shouldn't matter whether
                            // a function is inlined or not; but counting it as an indirection would introduce a semantic difference.
                            findObjectCriticalSourcesAndIndirections(Arg, CVSet, TrackedSetParent,
                                                                     interproceduralDepth - 1, amountOfIndirections /*/ callersIt->second.size()*/);
//                            TrackedSet.insert(Arg);
                        }
                    }
                }
            }
        }
#endif
    } else if (auto CI = dyn_cast<CallInst>(V)) {
        CVSet.emplace_back(ValueWithIndirections{.value = V, .indirections = amountOfIndirections});
        // Track simple getters
        if (!CI->isIndirectCall() && CI->arg_size() == 1 && CI->getArgOperand(0)->getType()->isPointerTy()) {
            auto it = Ctx->Callees.find(CI);
            if (it != Ctx->Callees.end()) {
                for (const auto *function: it->second) {
                    if (function->size() == 1) {
                        findObjectCriticalSourcesAndIndirections(CI->getArgOperand(0), CVSet, TrackedSet,
                                                                 interproceduralDepth,
                                                                 amountOfIndirections + 1);
                    }
                }
            }
        } else {
            for (unsigned int i = 0, l = CI->arg_size(); i < l; ++i) {
                findObjectCriticalSourcesAndIndirections(CI->getArgOperand(i), CVSet, TrackedSet, interproceduralDepth,
                                                         amountOfIndirections + 1);
            }
        }
    } else if (auto SI = dyn_cast<SelectInst>(V)) {
        findObjectCriticalSourcesAndIndirections(SI->getTrueValue(), CVSet, TrackedSet, interproceduralDepth,
                                                 amountOfIndirections);
        findObjectCriticalSourcesAndIndirections(SI->getFalseValue(), CVSet, TrackedSet, interproceduralDepth,
                                                 amountOfIndirections);
    } else if (auto GEP = dyn_cast<GetElementPtrInst>(V)) {
        // TODO: consider aliases
        findObjectCriticalSourcesAndIndirections(GEP->getPointerOperand(), CVSet, TrackedSet, interproceduralDepth,
                                                 amountOfIndirections + GEP->getNumOperands() - 2);
    } else if (auto PN = dyn_cast<PHINode>(V)) {
        for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; ++i) {
            Value *IV = PN->getIncomingValue(i);
            findObjectCriticalSourcesAndIndirections(IV, CVSet, TrackedSet, interproceduralDepth, amountOfIndirections);
        }
    } else if (auto LI = dyn_cast<LoadInst>(V)) {
        auto pointerOperand = LI->getPointerOperand();
        if (isa<GetElementPtrInst>(pointerOperand) || isa<BitCastInst>(pointerOperand)) {
            findObjectCriticalSourcesAndIndirections(pointerOperand, CVSet, TrackedSet, interproceduralDepth,
                                                     amountOfIndirections + 1);
        }

        // Get aliases
        Function *F = LI->getFunction();
        std::set<Value *> AliasSet;
        if (auto it = Ctx->FuncPAResults.find(F); it != Ctx->FuncPAResults.end()) {
            getAliasPointers(LI->getPointerOperand(), AliasSet, it->second);

            // To find all stores using the pointer, use alias analysis
            for (auto alias: AliasSet) {
                if (TrackedSet.insert(alias).second) {
                    for (auto U: alias->users()) {
                        auto SI = dyn_cast<StoreInst>(U);
                        if (SI && alias == SI->getPointerOperand()) {
                            findObjectCriticalSourcesAndIndirections(SI->getValueOperand(), CVSet, TrackedSet,
                                                                     interproceduralDepth, amountOfIndirections + 1);
                        }
                    }
                }
            }
        }
    }
    // Default policy for unary and binary
    else if (auto UI = dyn_cast<UnaryInstruction>(V)) {
        Value *UO = UI->getOperand(0);
        findObjectCriticalSourcesAndIndirections(UO, CVSet, TrackedSet, interproceduralDepth, amountOfIndirections);
    }
}

/// Collect sources of a Target by backward Dataflow analysis
void DataFlowAnalysis::findSources(Value *V, set<Value *> &SrcSet, set<Value*>& visited) {
    if (!visited.insert(V).second)
        return;

#if 0
	// If the CV is modified by the return value of a function
	CallInst *CI = dyn_cast<CallInst>(V);
	if (CI) {
		Function *CF = CI->getCalledFunction();
		if (!CF) return;

		// Explicit handling of overflow operations, treat as binary operator
		if (CF->getName().contains("with.overflow")) {
			for (unsigned int i = 0; i < CI->getNumArgOperands(); ++i)
				findSources(CI->getArgOperand(i), SrcSet, visited);
			return;
		}
		return;
	}

	if (dyn_cast<GlobalVariable>(V)) {
		// FIXME: ???
		Constant *Ct = dyn_cast<Constant>(V);
		if (!Ct) return;

		SrcSet.insert(V);
		return;
	}

	if (dyn_cast<ConstantExpr>(V)) {
		ConstantExpr *CE = dyn_cast<ConstantExpr>(V);
		findSources(CE->getOperand(0), SrcSet, visited);
		return;
	}
#endif
	LoadInst *LI = dyn_cast<LoadInst>(V);
	if (LI) {
		// FIXME: this is wrong
        SrcSet.insert(LI);
		//findSources(LI->getPointerOperand(), SrcSet, visited);
		return;
	}

	SelectInst *SI = dyn_cast<SelectInst>(V);
	if (SI) {
		findSources(SI->getTrueValue(), SrcSet, visited);
		findSources(SI->getFalseValue(), SrcSet, visited);
		return;
	}

	if (isa<GetElementPtrInst>(V)) {
        SrcSet.insert(V);
        return;
    }

	PHINode *PN = dyn_cast<PHINode>(V);
	if (PN) {
		for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; ++i) {
			Value *IV = PN->getIncomingValue(i);
			findSources(IV, SrcSet, visited);
		}
		return;
	}

	ICmpInst *ICmp = dyn_cast<ICmpInst>(V);
	if (ICmp) {
		for (unsigned i = 0; i < ICmp->getNumOperands(); ++i) {
			Value *Opd = ICmp->getOperand(i);
			findSources(Opd, SrcSet, visited);
		}
		return;
	}

	BinaryOperator *BO = dyn_cast<BinaryOperator>(V);
	if (BO) {
		for (unsigned i = 0, e = BO->getNumOperands(); i != e; ++i) {
			Value *Opd = BO->getOperand(i);
			if (isa<Constant>(Opd))
				continue;
			findSources(Opd, SrcSet, visited);
		}
		return;
	}

	UnaryInstruction *UI = dyn_cast<UnaryInstruction>(V);
	if (UI) {
		findSources(UI->getOperand(0), SrcSet, visited);
		return;
	}

#if 0
	if (dyn_cast<Constant>(V)) {
		SrcSet.insert(V);
		return;
	}
#endif
}
