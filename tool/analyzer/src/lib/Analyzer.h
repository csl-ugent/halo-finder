#ifndef ANALYZER_GLOBAL_H
#define ANALYZER_GLOBAL_H

#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include "llvm/Support/CommandLine.h"
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include "Common.h"
#include "TypeRemapper.h"
#include "Field.h"


using CallInstSetEntry = llvm::CallInst*;

#if 0
struct CallInstSetEntryInfo {
    static inline CallInstSetEntry getEmptyKey() {
        return {.call = nullptr, .direct = false};
    }

    static inline CallInstSetEntry getTombstoneKey() {
        return {.call = nullptr, .direct = true};
    }

    static inline unsigned getHashValue(const CallInstSetEntry& entry) {
        hash<CallInst*> ch;
        hash<bool> bh;
        return ch(entry.call) * 31 * 31 + bh(entry.direct) * 31;
    }

    static inline bool isEqual(const CallInstSetEntry& LHS, const CallInstSetEntry& RHS) {
        return LHS.call == RHS.call && LHS.direct == RHS.direct;
    }
};
#endif

// 
// typedefs
//
typedef vector< pair<llvm::Module*, llvm::StringRef> > ModuleList;
// The set of all functions.
typedef llvm::SmallPtrSet<llvm::Function*, 8> FuncSet;
// Mapping from function name to function.
typedef unordered_map<string_view, llvm::Function*> NameFuncMap;
typedef llvm::SmallPtrSet<CallInstSetEntry, 4> CallInstSet;
typedef DenseMap<Function*, CallInstSet> CallerMap;
typedef DenseMap<CallInst *, FuncSet> CalleeMap;
// Pointer analysis types.
typedef DenseMap<Value *, SmallPtrSet<Value *, 16>> PointerAnalysisMap;
typedef unordered_map<Function *, PointerAnalysisMap> FuncPointerAnalysisMap;

struct GlobalContext {
    TypeRemapper typeRemapper;
    unordered_map<const Function*, shared_ptr<Field>> lockCheckFunctions;
    set<shared_ptr<Field>, FieldSharedPtrCompare> securityCriticalFields;

	// Map global function name to function.
	NameFuncMap GlobalFuncs;

	// Functions whose addresses are taken.
	FuncSet AddressTakenFuncs; // TODO: move this to MLTA pass to reduce memory usage?

	// Map a callsite to all potential callee functions.
	CalleeMap Callees;

	// Map a function to all potential caller instructions.
	CallerMap Callers;

	// Unified functions -- no redundant inline functions
	DenseMap<size_t, Function *>UnifiedFuncMap;
	set<Function *>UnifiedFuncSet;

	// Map function signature to functions
	DenseMap<size_t, FuncSet>sigFuncsMap;

	// Modules.
	ModuleList Modules;

	// Functions handling errors & copies
	set<string> ErrorHandleFuncs;
	map<string, tuple<int8_t, int8_t, int8_t>> CopyFuncs;

	// Pointer analysis results.
    FuncPointerAnalysisMap FuncPAResults;

	bool shouldSkipFunction(const Function* function) const {
		return function->empty() || UnifiedFuncSet.find(const_cast<Function*>(function)) == UnifiedFuncSet.end();
	}
};

class IterativeModulePass {
protected:
	GlobalContext *Ctx;
	const char * ID;
public:
	IterativeModulePass(GlobalContext *Ctx_, const char *ID_)
		: Ctx(Ctx_), ID(ID_) { }

	// Run on each module before iterative pass.
	virtual bool doInitialization(llvm::Module *M)
		{ return true; }

	// Run on each module after iterative pass.
	virtual bool doFinalization(llvm::Module *M)
		{ return true; }

	// Iterative pass.
	virtual bool doModulePass(llvm::Module *M)
		{ return false; }

	virtual void run(ModuleList &modules);
};

#endif
