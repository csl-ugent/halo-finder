#pragma once

#include "DataFlowAnalysis.h"
#include "Common.h"
#include "Field.h"
#include "Helpers.h"
#include "LockStyles.h"
#include "WrapperFinder.h"
#include <stack>
#include <utility>
#include <llvm/Support/Regex.h>


struct FieldData {
	vector<CallInst*> sources;
};

struct StoreTaintData {
    vector<unsigned char> argumentsWithStores {};
    bool fresh : 1 {true};
    bool cyclic : 1 {false};
};

class LockCheckerPass : public IterativeModulePass {
	public:
		explicit LockCheckerPass(GlobalContext *Ctx_)
			: IterativeModulePass(Ctx_, "LockChecker"),
			  DFA(Ctx_) {
			}
        ~LockCheckerPass() {
        }
		bool doInitialization(llvm::Module *) override;
		bool doFinalization(llvm::Module *) override;
		bool doModulePass(llvm::Module *) override;

	private:
		DataFlowAnalysis DFA;

		set<const Function*> allocFunctions, freeFunctions, lockAssertFunctions;
        map<const Function*, set<const Type*>> initializations;

		unordered_map<const Function*, LockUnlockerData> lockers, unlockers;

		map<shared_ptr<Field>, FieldData, FieldSharedPtrCompare> LockFields, UnLockFields;
        unordered_set<const Type*> lockTypes;

		void findBasicBlockCoverage(Module* M, LockCoverageMap& lockCoverage);
		void findViolations(Module* M);
		void loadTransformers(const Module& M);
		void loadSimpleFunctionLists(const Module& M);
		void findWrappers();
		void findLockAndUnLockFields(Module* M);
		void handleFunctionForLockAndUnLockFields(Function& function);
		bool isFunctionALocker(const Function& function) const;
		bool isFunctionAnUnLocker(const Function& function) const;
        bool processLockUnlockFunctionCall(unordered_map<const Function*, LockUnlockerData>& map, const CallInst* caller, const Function* function);
        void findLockWrappers();
        void taintAnalyseAllocFunctions();
        void taintAnalyseFreeFunctions();
        void taintStore(const Function* function);

        map<const Function*, StoreTaintData> storeTaintData;

		friend struct LockCheckerPassData;
};

struct LockCheckerPassData {
	explicit LockCheckerPassData(const LockCheckerPass&);

	DataFlowAnalysis& DFA;
    const unordered_set<const Type*>& lockTypes;
    const set<const Function*>& lockAssertFunctions;
    const unordered_map<const Function*, LockUnlockerData>& lockers, &unlockers;
    const map<const Function*, StoreTaintData>& storeTaintData;
    const map<shared_ptr<Field>, FieldData, FieldSharedPtrCompare>& lockFields;
};
