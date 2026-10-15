#pragma once

#include "LockChecker.h"
#include "Config.h"


#define DEBUG_KEEP_HAS_TO_FUNC_NAME


class ViolationFinder {
public:
    ViolationFinder(LockCheckerPassData& lockCheckerPassData, const LockCoverageMap& lockCoverageMap,
                    const set<const Function*>& allocFunctions, const set<const Function*>& freeFunctions)
            : lockCheckerPassData(lockCheckerPassData), lockCoverageMap(lockCoverageMap),
              allocFunctions(allocFunctions), freeFunctions(freeFunctions) {
        for (const auto& [field, _] : lockCheckerPassData.lockFields) {
            auto ptr = make_shared<Field>(findCoreLock(field)->clone());
            ptr->next = nullptr;
            uninitializedLockFields.insert(ptr);
        }
    }

    ~ViolationFinder() = default;

    void findViolations(const Module& M);

    void showLockingRules() const;

    void showFieldBugs() const;

    void showAssertionBugs(const Module& M) const;

    void calculateInitializationValues(const Module& M);

    void fillFunctionToSyscallMap(const Module& M);

    void dumpStoreAndCallsTest(const Module& M) const;

    void deriveContexts();

private:
    using ReadWriteViolationCoverToInstructionsMap = map<LockCover, vector<pair<const Instruction*, shared_ptr<Field>>>, LockCoverComp>;

    LockCheckerPassData& lockCheckerPassData;
    const LockCoverageMap& lockCoverageMap;
    const set<const Function*>& allocFunctions, &freeFunctions;

    [[nodiscard]] shared_ptr<Field> findCoreLock(const shared_ptr<Field>& field) const;

    [[nodiscard]] bool isInstructionASafeFunctionCall(const Instruction* instruction, const set<const Function*>* optionalSafeFunctions) const;

    [[nodiscard]] bool isTransitivelyOnlyUsedInASafeFunctionCall(const Value* value, int depth, bool debug, const set<const Function*>* optionalSafeFunctions) const;

    bool interproceduralRecheckCheckFunctionCallee(const Function* function, const shared_ptr<Field>& field, const FieldCoverageData& coverageData) const;

    bool isFirstOrLastLockedField(const Instruction& instructionToBeCovered, const shared_ptr<Field>& field) const;

    void calculateInitializationValuesIndividual(const Function* function, mutex* initializationValuesMutex, mutex* finalizationValuesMutex);

    static void showAssertionBugsIndividual(const shared_ptr<Field>* field,
                                            const vector<vector<const Instruction*>>* violationPaths,
                                            mutex* outputMutex);

    void
    findAssertionBugsIndividual(const CallInst* callInst, ViolationPathMap* violationPaths, mutex* insertMutex) const;

    void showFieldBugsIndividual(mutex* outputMutex, unsigned long uncoveredCount,
                                 const shared_ptr<Field>& field,
                                 const unordered_multiset<LockCover, LockCoverHash, LockCoverEqual>* lockCovers) const;

    template<typename T, typename C>
    bool interproceduralFieldCoverCheck(const shared_ptr<Field>& field, const LockCoverageMap& lockCoverage,
                                        const BasicBlock* BB, int depthLeft,
                                        const T& callback, const C& checker, vector<const Instruction*> path,
                                        set<const Function*>& visited) const;

    map<const Function*, set<const Function*>> functionToSyscall;

    void fillFunctionToSyscallMap(const Function* syscall, const Function* function, set<const Function*>& visited,
                                  int depth);

    bool canGoBackToInitialization(Lazy<DominatorTree>* dt, const Instruction* instruction, const Value* operand, set<const Function*>& initFunctions, const Function* originFunction) const;

    void accountCriticalSourcesLockUnlockCounts(const vector<ValueWithIndirections>& cvSet, const shared_ptr<Field>& field, bool unlocked, const Value* startOperand, const shared_ptr<Field>& lockField);

    void findPotentialRules(const Module& M);

    void findPotentialRulesIndividual(const Function* function, ReadWriteViolationCoverToInstructionsMap* readWriteViolationCoverToInstructions, mutex* readWriteViolationCoverToInstructionsMutex, mutex* privateVarMutex);

    void findViolationsInFunction(const Function* function);

    optional<float> earlyRejectField(unsigned long uncoveredCount,
                          const shared_ptr<Field>& field,
                          const unordered_multiset<LockCover, LockCoverHash, LockCoverEqual>* lockCovers) const;

    unordered_map<shared_ptr<Field>, unordered_set<shared_ptr<Field>, FieldSharedPtrHash, FieldSharedPtrEqual>, FieldSharedPtrHash, FieldSharedPtrEqual> fieldLockPreference;
    map<const Function*, unsigned short> sinkFunctionCallLockedCount;
    unordered_set<Field, FieldHash> writtenToOrEscapedFields;
    unordered_map<Field, set<const CallInst*>, FieldHash> writtenToOrEscapedFieldsDeferredCalls;
    unordered_map<Field, unsigned char, FieldHash> storeCounter;

    struct LockUnlockWeights {
        float locked = 0.0f, unlocked = 0.0f, lockedCount = 0.0f, unlockedCount = 0.0f;
    };

    map<const Value*, map<const Type*, LockUnlockWeights>> valueSourceToLockUnlockCounts;
    unordered_map<Field, map<const Type*, LockUnlockWeights>, FieldHash> interfaceSourceToLockUnlockCounts;
    unordered_map<size_t, map<const Type*, LockUnlockWeights>> functionSourceToLockUnlockCounts;
#ifdef DEBUG_KEEP_HAS_TO_FUNC_NAME
    unordered_map<size_t, const Function*> hashToFunction;
#endif
    set<const Function*> concurrencySafeFunctionSinks;
    struct ContextSources {
        set<const Value*> values;
        unordered_set<size_t> functions;
        unordered_set<Field, FieldHash> interfaces;
    };
    unordered_map<shared_ptr<Field>, ContextSources, FieldSharedPtrHash, FieldSharedPtrEqual> fieldToContextsSet;

    unordered_set<shared_ptr<Field>, FieldSharedPtrHash, FieldSharedPtrEqual> mustBeliefFields;

    unordered_map<shared_ptr<Field>, set<const Function*>, FieldSharedPtrHash, FieldSharedPtrEqual> mustBeliefFunctions;

    struct LazyOperandTracker {
        struct Entry {
            const Value* operand;
            const shared_ptr<Field> field;
            bool unlocked : 1;
            bool addSet : 1;
            bool mustBelief : 1;
        };

        vector<Entry> entries;
    };
    map<const Type*, LazyOperandTracker> lazyOperandTracking;

    void deriveContextsIndividual(mutex* mutex, LazyOperandTracker* tracker);

    set<const Value*> initializationValues, finalizationValues;

    mutex uninitializedLockFieldsMutex;
    unordered_set<shared_ptr<Field>, FieldSharedPtrHash, FieldSharedPtrEqual> uninitializedLockFields;

    mutex findViolationsInFunctionStoreMutex;
    FieldCoverageDataMap fieldCoverageData;

#ifdef COUNT_HOW_MANY_TIMES_FP_RECHECK_IS_DETECTED
    set<const Function*> functionsWithFpRecheck;
    mutex functionsWithFpRecheckMutex;
#endif

#ifdef TRACK_WHICH_FUNCTIONS_CONTAIN_VIOLATIONS
    mutex trackWhichFunctionsContainViolationsMutex;
    set<const Type*> trackWhichFunctionsContainViolations;
#endif
};
