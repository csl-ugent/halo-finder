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

class LockCheckerPass final {
	public:
		explicit LockCheckerPass(GlobalContext *Ctx_)
			: Ctx(Ctx_),
			  DFA(Ctx_) {
			}
        ~LockCheckerPass() {
        }
		void doInitialization(const vector<Function *> &functions);
		void run(const vector<Function *> &functions);

	private:
		GlobalContext *Ctx;
		DataFlowAnalysis DFA;

		set<const Function*> allocFunctions, freeFunctions, lockAssertFunctions;
        map<const Function*, set<const Type*>> initializations;

		unordered_map<const Function*, LockUnlockerData> lockers, unlockers;

		map<shared_ptr<Field>, FieldData, FieldSharedPtrCompare> LockFields, UnLockFields;
        unordered_set<const Type*> lockTypes;

		void findBasicBlockCoverage(const vector<Function *> &functions, LockCoverageMap& lockCoverage);
		void findViolations(const vector<Function *> &functions);
		void loadTransformers(const vector<Function *> &functions);
		void loadSimpleFunctionLists(const vector<Function *> &functions);
		void findWrappers();
		void findLockAndUnLockFields(const vector<Function *> &functions);
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
