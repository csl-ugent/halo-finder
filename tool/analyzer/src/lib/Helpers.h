#pragma once

#include <string>
#include <optional>
#include <vector>
#include <set>
#include <unordered_set>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Analysis/PostDominators.h>
#include "Field.h"
#include "Analyzer.h"
#include "Lazy.h"


struct GlobalContext;
class TypeRemapper;


using namespace llvm;
using namespace std;


template<typename T>
class Deferred {
public:
    explicit Deferred(T destructor) : destructor(destructor) {}
    ~Deferred() { destructor(); }

private:
    T destructor;
};

static inline uint64_t getOffsetRaw(const ConstantInt* fieldOffset) {
	return *fieldOffset->getUniqueInteger().getRawData();
}

template<typename Cb, typename R>
static R callbackOnReturnInstruction(const Function& function, const Cb& callback, R _default) {
    for (const auto& BB : function) {
        if (isa<ReturnInst>(BB.getTerminator())) {
            auto result = callback(BB);
            if (result != _default)
                return result;
        }
    }

    return _default;
}

enum class AllowPrefix {
    Yes,
    No,
};

bool isCompositeType(const Type* type);
bool isFreeCallAlwaysExecutedRegardlessOfNullChecks(Function& containingFunction, const CallInst* call, Lazy<PostDominatorTree>& postDominatorTree);
bool canBeUsedInAnIndirectCall(const Function& function);
pair<const LockCover*, unsigned int> getMaxLockCoverCoveredCount(const LockCovers& lockCovers);
bool isWrappingType(const Type* type);
bool canCoverField(const Field& cover, const Field& field);
void chainFields(Field& field, optional<shared_ptr<Field>> chainField);
void chainFields(shared_ptr<Field>& field, optional<shared_ptr<Field>> chainField);
void findFields(const Module& module, const Value *V, FieldSourceSet& sourceSet, set<const Value *>& TrackedSet, bool chunkAllOfThem);
bool containsLockCover(const LockCovers& coverSet, const LockCover& necessaryCover, AllowPrefix allowPrefix=AllowPrefix::No);
bool isCoveredByTheNecessaryLockCovers(const LockCovers& fieldToLockMapEntry, const LockCoverageMap& lockCoverage, const BasicBlock* BB);
bool isFieldCoveredByTheNecessaryLockCovers(const shared_ptr<Field>& field, const LockCoverageMap& lockCoverage, const FieldCoverageDataMap& fieldCoverageData, const BasicBlock* BB);
bool isThereALockCoverAlike(const shared_ptr<Field>& field, const LockCoverageMap& lockCoverage, const FieldCoverageDataMap& fieldCoverageData, const BasicBlock* BB);
void getPotentialFieldOperandPointersFromInstruction(const Instruction& instruction, SmallVector<const Value*, 1>& foundOperands, bool ignoreVolatile);
const MDNode* findDebugValue(const Value* value, const Function* function);
const DIType* getBaseTypeViaDebugValueOf(const Instruction& instruction);
uint64_t getStructElementIndexFromOffset(const Module& M, const StructType& type, unsigned int byteOffset);
const StructType* getStructType(const Type* type);
optional<string> gitBlame(const string_view& repoPath, const string_view& file, unsigned int line);
uint64_t getFieldBitOffsetOf(const Module& M, const StructType& type, unsigned int fieldOffset);
const Type* getFirstAppropriateTypeForGep(const Value* sourceForGep, const Type* type, uint64_t offset);
optional<CalleeMap::const_iterator>
getCalleeIteratorForPotentialCallInstruction(const GlobalContext& Ctx, const Instruction& instruction);
