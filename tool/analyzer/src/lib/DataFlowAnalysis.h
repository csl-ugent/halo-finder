#ifndef DATA_FLOW_ANALYSIS_H
#define DATA_FLOW_ANALYSIS_H

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/CFG.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Format.h>
#include <set>
#include <map>
#include <string>
#include "Analyzer.h"
#include "Common.h"

struct ValueWithIndirections {
    enum class ValueType {
        Value,
        Interface,
    };
    ValueType type;
    union {
        const Value *value;
        struct {
            // No implicit destructor workaround instead of embedding Field
            const Type* fieldContainingType;
            uint32_t fieldOffset;
        };
    };
    float indirections;
};

using namespace llvm;

class DataFlowAnalysis {

	public:
		explicit DataFlowAnalysis(GlobalContext *GCtx) : Ctx(GCtx) {}
		~DataFlowAnalysis() = default;

		void findSources(Value *V, set<Value *> &SrcSet, set<Value*>& visited);

		// Track the sources and same-origin critical variables of the
		// given critical variable.
		void findSourceCV(Value *V, set<Value *> &CVSet, set<Value *> &TrackedSet, int interproceduralDepth = 0);
        void findObjectCriticalSourcesAndIndirections(Value *V, vector<ValueWithIndirections> &CVSet, set<Value *> &TrackedSet, int interproceduralDepth, float amountOfIndirections = 0.0f);

		void getAliasPointers(Value *Addr,
				std::set<Value *> &aliasAddr,
				const PointerAnalysisMap &aliasPtrs) const;
	private:
		// Set of LoadPointers
		std::set<Value *> LPSet; 
		GlobalContext *Ctx;
};

#endif

