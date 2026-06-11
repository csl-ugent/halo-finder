#include "Common.h"
#include "Config.h"
#include "Helpers.h"
#include "DebugHelpers.h"
#include "LockChecker.h"
#include "ClOptForward.h"
#include <llvm/IR/InstIterator.h>
#include <llvm/Support/Casting.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/DebugInfo.h>

#include <utility>
#include <spawn.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>


bool isCompositeType(const Type* type) {
    return type->isStructTy()
           || type->isArrayTy()
           || type->isVectorTy();
}

bool isFreeCallAlwaysExecutedRegardlessOfNullChecks(Function& containingFunction, const CallInst* call, Lazy<PostDominatorTree>& postDominatorTree) {
    auto& entry = containingFunction.getEntryBlock();
    auto continueBB = &entry;

    bool changed = true;
    set<const BasicBlock*> visited;
    while (changed) {
        changed = false;
        if (!visited.insert(continueBB).second)
            return false;

        if (auto branch = dyn_cast<BranchInst>(continueBB->getTerminator())) {
            if (branch->isConditional()) {
                if (auto cmp = dyn_cast<CmpInst>(branch->getCondition())) {
                    // Continue with the basic block where the pointer is not null.
                    if (isa<ConstantPointerNull>(cmp->getOperand(0)) || isa<ConstantPointerNull>(cmp->getOperand(1))) {
                        if (cmp->getPredicate() == llvm::CmpInst::ICMP_EQ)
                            continueBB = branch->getSuccessor(1);
                        else
                            continueBB = branch->getSuccessor(0);
                        changed = true;
                        continue;
                    }
                }

                // Continue with branch that performs actions
                if (isa<ReturnInst>(branch->getSuccessor(0)->getTerminator()) && branch->getSuccessor(0)->size() == 1) {
                    continueBB = branch->getSuccessor(1);
                    changed = true;
                    continue;
                } else if (isa<ReturnInst>(branch->getSuccessor(1)->getTerminator()) && branch->getSuccessor(1)->size() == 1) {
                    continueBB = branch->getSuccessor(0);
                    changed = true;
                    continue;
                }

                // Continue with the non-assert branch
                if (isa<UnreachableInst>(branch->getSuccessor(0)->getTerminator())) {
                    continueBB = branch->getSuccessor(1);
                    changed = true;
                    continue;
                } else if (isa<UnreachableInst>(branch->getSuccessor(1)->getTerminator())) {
                    continueBB = branch->getSuccessor(0);
                    changed = true;
                    continue;
                }
            }
        }
    }

    // Trivial domination case
    if (call->getParent() == continueBB)
        return true;

    // Free call must post-dominate the continuation point
    return postDominatorTree->dominates(call->getParent(), continueBB);
}

bool canBeUsedInAnIndirectCall(const Function& function) {
    if (!function.hasAddressTaken(nullptr, true, true))
        return false;

    for (const auto* user : function.users()) {
        if (isa<GlobalValue>(user))
            continue;
        if (!all_of(user->user_begin(), user->user_end(), [&](const auto& userUser) {
            return isa<GlobalValue>(userUser) && !isCompositeType(userUser->getType());
        })) {
            return true;
        }
    }

    return false;
}

bool isWrappingType(const Type *type) {
    return type->isStructTy() && type->getStructNumElements() == 1 && !type->getStructName().contains("union");
}

bool canCoverField(const Field &cover, const Field &field) {
#if 0
    // DEBUG
    if (cover.type == field.type) {
        /*if (cover.type->getStructName().contains("fib6_info")) */{
            cover.dump(LOG_INFO);
            field.dump(LOG_INFO);
            LOG(LOG_INFO, "depths: " << cover.depth() << ", " << field.depth() << "\n");
        }
    }
#endif

    if (cover.isGlobal() != field.isGlobal())
        return false;
    if (field.isGlobal()) // Then the other is a global too!
        return true;

    // This code checks if the field type occurs within the cover
    // => Same struct or a part within the struct
    // AND d(lock) <= d(field) because the field must be deeper or at equal depth in order to be able to be protected by the lock
    return cover.typePtr() == field.typePtr() && cover.depth() <= field.depth();
}

void chainFields(Field &field, optional <shared_ptr<Field>> chainField) {
    if (chainField.has_value()) {
#if 0
        {
            if (field.isInteger()) {
                LOG(LOG_INFO, "An integer type?\n");
                field.dump(LOG_INFO);
                chainField.value()->dump(LOG_INFO);
                assert(false);
            }
        }
#endif

        shared_ptr <Field> *next = &field.next;
        while (*next) {
            next = &(*next)->next;
        }

        *next = chainField.value();

#ifdef ASSERT_FOR_CYCLES
        auto test = *next;
        while (test) {
            test = test->next;
            assert(test.get() != (*next).get() && "infinite cycle");
        }
#endif
    }
}

void chainFields(shared_ptr <Field> &field, optional <shared_ptr<Field>> chainField) {
    chainFields(*field, move(chainField));
}

static inline uint64_t getTypeSize(const Module &M, const Type &type) {
    return M.getDataLayout().getTypeSizeInBits(const_cast<Type *>(&type)) / 8;
}

static void reduceFieldFindingToGep(const Value *V, set<const Value *> &TrackedSet,
                                    set<const Value *> &results) {
    if (!TrackedSet.insert(V).second)
        return;

    if (auto SI = dyn_cast<SelectInst>(V)) {
        reduceFieldFindingToGep(SI->getTrueValue(), TrackedSet, results);
        reduceFieldFindingToGep(SI->getFalseValue(), TrackedSet, results);
    } else if (auto PN = dyn_cast<PHINode>(V)) {
        for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; ++i) {
            reduceFieldFindingToGep(PN->getIncomingValue(i), TrackedSet, results);
        }
    } else if (auto LI = dyn_cast<LoadInst>(V)) {
        const Value *LPO = LI->getPointerOperand();
        reduceFieldFindingToGep(LPO, TrackedSet, results);

        // Disabled because of accuracy issues wrt GEP & proves not beneficial for FPR
#if 0
        // Get aliases
        const Function *F = LI->getFunction();
        auto it = GlobalCtx.FuncPAResults.find(const_cast<Function*>(F));
        if (it != GlobalCtx.FuncPAResults.end()) {
            set<Value *> AliasSet;
            GlobalCtx.DFA.getAliasPointers(const_cast<Value*>(LPO), AliasSet, it->second);

            // To find all stores using the pointer using alias analysis
            for (Value *A : AliasSet) {
                for (User *U : A->users()) {
                    auto SI = dyn_cast<StoreInst>(U);
                    if (SI && A == SI->getPointerOperand()) {
                        Value *SVO = SI->getValueOperand();
                        reduceFieldFindingToGep(SVO, TrackedSet, results);
                    }
                }
            }
        }
#endif
    } else if (auto bitcast = dyn_cast<BitCastInst>(V)) {
        results.insert(V);
        reduceFieldFindingToGep(bitcast->getOperand(0), TrackedSet, results);
    } else if (isa<CallInst>(V) || isa<GEPOperator>(V)) {
        results.insert(V);
#ifdef GET_GLOBALS
    } else if (isa<GlobalValue>(V)) {
        results.insert(V);
#endif
    }
}

Field getGepFieldCandidate(const TypeRemapper &typeRemapper, const GEPOperator *GEP) {
    if (GEP->getNumOperands() < 3) // pointee, i64 pointer offset, i32 field offset
        return {};

    if (GEP->getPointerOperandType()->isStructTy()) {
        if (auto constant = dyn_cast<ConstantInt>(GEP->getOperand(1))) {
            if (!constant->isZero()) return {};
        }
    }

    bool debug = false; //GEP->getFunction()->getName().equals("igmp_timer_expire");// false;

    auto type = GEP->getSourceElementType();
    while (auto arrayType = dyn_cast<ArrayType>(type)) {
        type = arrayType->getArrayElementType();
    }

    if (!isa<StructType>(type)) {
        return {};
    }

    // Note: non-constants cannot be analysed with this analysis. This would imply code that computes the offset of a field and does type punning.
    if (auto constant = dyn_cast<ConstantInt>(GEP->getOperand(2))) {
        auto offset = getOffsetRaw(constant);
        auto realType = getFirstAppropriateTypeForGep(GEP->getPointerOperand(), type, offset);
        if (!realType)
            return {};

        // Note: we still have to do the name lookup in the original struct because otherwise there's no debug information...
        auto pointerType = const_cast<Type *>(realType)->getPointerTo();
        realType = typeRemapper.mapType(realType);
        if (auto instruction = dyn_cast<Instruction>(GEP))
            maybeRegisterFieldName(*instruction, pointerType, realType, offset);
        Field fieldCandidate(realType, offset);

#ifdef GET_GLOBALS
        if (auto global = dyn_cast<GlobalValue>(GEP->getOperand(0))) {
            Field globalFieldCandidate(global, make_shared<Field>(fieldCandidate));
            swap(fieldCandidate, globalFieldCandidate);
        }
#endif

        const Type *currentType = realType->getStructElementType(offset);
        shared_ptr <Field> *next = &fieldCandidate.next;
        for (unsigned int i = 3; i < GEP->getNumOperands(); ++i) {
            if (auto constant = dyn_cast<ConstantInt>(GEP->getOperand(i))) {
                auto offset = getOffsetRaw(constant);

                // Collapse arrays to a single element
                if (currentType->isArrayTy())
                    offset = 0;

                *next = make_shared<Field>(currentType, offset);
                next = &(*next)->next;
                if (!currentType->isStructTy() && !currentType->isArrayTy()) {
                    //currentType->dump();
                    //exit(1);
                    return {};
                }
                if (currentType->isArrayTy())
                    currentType = currentType->getArrayElementType();
                else {
                    if (offset >= currentType->getStructNumElements())
                        return {};//currentType = getFirstAppropriateTypeForGep(GEP->getFunction(), )
                    currentType = currentType->getStructElementType(offset);
                }
            } else {
                return {};
            }
        }

        if (debug) {
            LOG(LOG_INFO, "found field candidate:\n");
            fieldCandidate.dump(LOG_INFO);
        }

        return fieldCandidate;
    }

    return {};
}

static GEPOperator* createFakeGEP(const Module& module, const BitCastInst* bitcast, long byteOffsetIntoDestinationType, const GEPOperator* GEP, bool debug) {
    auto* candidateResultingType = bitcast->getDestTy()->getPointerElementType();
    if (candidateResultingType->isStructTy()) {
        auto resultingType = candidateResultingType;
        APInt newOffset(module.getDataLayout().getPointerSize() * 8, byteOffsetIntoDestinationType);
        auto indices = module.getDataLayout().getGEPIndicesForOffset(resultingType, newOffset);

        // The conversion is only valid if the new offset is zero.
        if (newOffset.getZExtValue() == 0) {
            if (debug) {
                GEP->dump();
                candidateResultingType->getPointerTo()->dump();
                LOG(LOG_INFO, "Indices:\n");
                for (const auto& index : indices) {
                    LOG(LOG_INFO, "  => " << index.getSExtValue() << "\n");
                }
            }

            // Not an array, so the i64 offset must be 0
            if (indices[0].getSExtValue() != 0)
                return nullptr;

            // TODO: replace original GEP with this?
            // TODO: cleanup fake GEP
            Value* valueIndices[indices.size()];
            for (unsigned int i = 0; i < indices.size(); ++i)
                valueIndices[i] = ConstantInt::get(module.getContext(), indices[i]);
            auto fakeGEP = GetElementPtrInst::CreateInBounds(candidateResultingType, const_cast<BitCastInst*>(bitcast), ArrayRef<Value*>(valueIndices, indices.size()), "", const_cast<BitCastInst*>(bitcast));
            return dyn_cast<GEPOperator>(fakeGEP);
        }
    }

    return nullptr;
}

void
findFields(const Module &module, const Value *V, FieldSourceSet &sourceSet, set<const Value *> &TrackedSet,
           bool chunkAllOfThem) {
    set<const Value *> toBeProcessed;
    reduceFieldFindingToGep(V, TrackedSet, toBeProcessed);

    // Debug flag
    bool debug = false;
#if 0
    if (auto I = dyn_cast<Instruction>(V)) {
        if (I->getFunction()->getName().equals(/*"neigh_timer_handler"*//*"sched_cfs_period_timer"*//*"hci_alloc_dev"*/"btrfs_free_block_groups")) {
            debug = true;
        }
    }
#endif

    for (const auto* V: toBeProcessed) {
        if (auto GEP = dyn_cast<GEPOperator>(V)) {
#ifdef TRY_TO_RECOVER_TYPE_INFORMATION
            // Collapse computed indices
            auto constant = dyn_cast<ConstantInt>(GEP->getOperand(1));
            auto constantRaw = constant == nullptr ? 0 : static_cast<int64_t>(getOffsetRaw(constant));

            // GEP results in a pointer and is from pointer arithmetic rather than field access
            if (constantRaw != 0 && GEP->getType()->isPointerTy()) {
                // Compute the byte offset starting from the base value.
                APInt GEPByteOffset(module.getDataLayout().getPointerSize() * 8, 0, true);
                auto GEPbaseValue = GEP->stripAndAccumulateConstantOffsets(module.getDataLayout(), GEPByteOffset, true);
                if (debug) {
                    LOG(LOG_INFO, "GEP reconstruct state, GEP byte offset: " << GEPByteOffset << "\n");
                    GEP->dump();
                    GEPbaseValue->dump();
                }

                // Now find other uses that are bitcasted to a struct candidate resulting type AND are of the same base value.
                // Once we have a candidate, try to index into the candidate resulting type with the offset equal to
                // the difference of the offsets.
                for (const auto* pointerOperandUser : GEP->getOperand(0)->users()) {
                    if (debug) {
                        LOG(LOG_INFO, "pointerOperandUser\n");
                        pointerOperandUser->dump();
                    }
                    // GetElementPtr %0, i64 X, ...
                    if (auto pointerOperandGEP = dyn_cast<GEPOperator>(pointerOperandUser); pointerOperandGEP && pointerOperandGEP != GEP) {
                        APInt userOffset(module.getDataLayout().getPointerSize() * 8, 0, true);
                        auto userBaseValue = pointerOperandGEP->stripAndAccumulateConstantOffsets(module.getDataLayout(), userOffset, true);

                        if (debug) {
                            LOG(LOG_INFO, "Reconstruct candidate:\n");
                            GEP->dump();
                            pointerOperandUser->dump();
                            LOG(LOG_INFO, "Offsets: " << GEPByteOffset << ", " << userOffset << "\n");
                        }

                        if (userBaseValue == GEPbaseValue) {
                            auto byteOffsetIntoDestinationType = GEPByteOffset.getSExtValue() - userOffset.getSExtValue();
                            if (byteOffsetIntoDestinationType >= 0) {
                                for (const auto* pointerOperandUserUser : pointerOperandGEP->users()) {
                                    if (auto bitcast = dyn_cast<BitCastInst>(pointerOperandUserUser)) {
                                        auto fakeGEP = createFakeGEP(module, bitcast, byteOffsetIntoDestinationType, GEP, debug);
                                        if (fakeGEP) {
                                            GEP = fakeGEP;
                                            goto skip_outer_loop;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // bitcast %0, destTy*
                    else if (auto bitcast = dyn_cast<BitCastInst>(pointerOperandUser)) {
                        APInt userOffset(module.getDataLayout().getPointerSize() * 8, 0, true);
                        auto userBaseValue = pointerOperandUser->stripAndAccumulateConstantOffsets(module.getDataLayout(), userOffset, true);

                        if (userBaseValue == GEPbaseValue) {
                            auto byteOffsetIntoDestinationType = GEPByteOffset.getSExtValue() - userOffset.getSExtValue();
                            if (byteOffsetIntoDestinationType >= 0) {
                                auto fakeGEP = createFakeGEP(module, bitcast, byteOffsetIntoDestinationType, GEP, debug);
                                if (fakeGEP) {
                                    GEP = fakeGEP;
                                    goto skip_outer_loop;
                                }
                            }
                        }
                    }
                }

                // Aliasing bitcast
                for (const auto* potentialAlias : GEP->users()) {
                    if (auto bitcast = dyn_cast<BitCastInst>(potentialAlias)) {
                        const Type* candidateResultingType = bitcast->getDestTy()->getPointerElementType();
                        if (candidateResultingType->isStructTy()) {
                            if (debug) {
                                LOG(LOG_INFO, "Aliasing bitcast\n");
                                GEP->dump();
                                bitcast->dump();
                                candidateResultingType->getPointerTo()->dump();
                            }
                            candidateResultingType = GlobalCtx.typeRemapper.mapType(candidateResultingType);

                            Field field(candidateResultingType, 0, {});
                            sourceSet.insert(move(field));
                            //return;
                        }
                    }
                }

                skip_outer_loop:;
            }

            /**
             * With some offset_of macros & friends, it's possible that the type information of what is actually dereferenced is not available
             * in the IR LLVM produces. The solution is to look into the debug information to reconstruct what the original types were.
             */
            if (GEP->getNumOperands() == 2 && GEP->getPointerOperandType()->getPointerElementType()->isPointerTy()) {
                if (auto GEPInst = dyn_cast<GetElementPtrInst>(GEP)) {
                    auto offset = constantRaw * getTypeSize(module, *GEP->getPointerOperandType());
                    if (auto baseType = getBaseTypeViaDebugValueOf(*GEPInst)) {
                        if (auto nameToType = GlobalCtx.typeRemapper.getTypeFromName(
                                    baseType->getName()); nameToType.has_value()) {
                            auto type = nameToType.value();
                            offset = getStructElementIndexFromOffset(module, *dyn_cast<StructType>(type), offset);
                            const Type *compareType = nullptr;
                            if (auto parentGEP = dyn_cast<GetElementPtrInst>(GEP->getOperand(0))) {
                                compareType = GlobalCtx.typeRemapper.mapType(
                                        parentGEP->getOperand(0)->getType()->getPointerElementType());
                            }
                            FieldWithMaybeCompareType fieldWithMaybeCompareType(Field(type, offset, {}), compareType);
#if 0
                            LOG(LOG_INFO, "Found using debug info: ");
                            fieldWithMaybeCompareType.fieldPtr()->dump(LOG_INFO);
#endif
                            sourceSet.insert(move(fieldWithMaybeCompareType));
                            continue;
                        }
                    }
                }

                continue;
            }
#endif

            if (auto candidateField = getGepFieldCandidate(GlobalCtx.typeRemapper, GEP); candidateField.isOkay()) {
                set<const Value *> visitedIntermediaries;

                struct Candidate {
                    Field field;
                    Value *reference;
                };

                stack <Candidate> candidates;
                candidates.emplace(Candidate{.field = move(candidateField), .reference = GEP->getOperand(0)});
                do {
                    auto shouldAdd = true;
                    auto candidate = candidates.top();
                    candidates.pop();

                    auto referenced = candidate.reference;
                    set<const Value *> intermediateProcessingSet;
                    reduceFieldFindingToGep(referenced, visitedIntermediaries, intermediateProcessingSet);

                    if (debug) {
                        LOG(LOG_INFO, "Reduce field finding led to:\n");
                        for (const auto &temp: visitedIntermediaries) {
                            temp->dump();
                        }
                    }

                    for (auto &temp: intermediateProcessingSet) {
                        auto parentGEP = dyn_cast<GEPOperator>(temp);
                        if (parentGEP && parentGEP->getNumOperands() >= 2) {
                            if (auto parentCandidate = getGepFieldCandidate(GlobalCtx.typeRemapper, parentGEP); parentCandidate.isOkay()) {
                                /**
                                 * Having the same shared pointer tail risks ourselves that
                                 * in case this a single field is used as a parent,
                                 * all the shared pointer tails will be extended.
                                 * This can result in infinite loops.
                                 */
                                auto chainField = make_shared<Field>(
                                        intermediateProcessingSet.size() == 1 ? candidate.field
                                                                              : candidate.field.clone());
                                if (chunkAllOfThem) {
                                    sourceSet.insert(FieldWithMaybeCompareType(chainField));
                                }

                                chainFields(parentCandidate, chainField);
                                candidates.emplace(
                                        Candidate{.field = move(parentCandidate), .reference = parentGEP->getOperand(
                                                0)});
                                shouldAdd = false;
                            }
                        }
                    }

                    if (shouldAdd) {
                        FieldWithMaybeCompareType result(move(candidate.field));
                        sourceSet.insert(move(result));
                    }
                } while (!candidates.empty());

                continue;
            }
        } else if (auto Bitcast = dyn_cast<BitCastInst>(V)) {
            auto oldSize = sourceSet.size();
            findFields(module, Bitcast->getOperand(0), sourceSet, TrackedSet, chunkAllOfThem);
            auto newSize = sourceSet.size();

            /**
             * There are cases where the origin is a pointer to a struct, which is later bitcasted to a pointer to the first member
             * as an annoying way to write &struct->first_field
             * => no GEP, need to manually handle this case...
             */
            if (newSize == oldSize) {
                if (debug) {
                    LOG(LOG_INFO, "newSize == oldSize\n");
                }
                if (Bitcast->getSrcTy()->isPointerTy()) {
                    const Type* pointee = Bitcast->getSrcTy()->getPointerElementType();

                    if (pointee->isIntegerTy()) {
                        for (const auto* user : Bitcast->getOperand(0)->users()) {
                            if (user == Bitcast)
                                continue;
                            if (auto cast = dyn_cast_or_null<BitCastInst>(user)) {
                                if (cast->getDestTy()->isPointerTy() &&
                                    cast->getDestTy()->getPointerElementType()->isStructTy()) {
                                    pointee = cast->getDestTy()->getPointerElementType();
                                    break;
                                }
                            }
                        }
                    }

                    if (pointee->isStructTy()) {
                        pointee = GlobalCtx.typeRemapper.mapType(pointee);
                        maybeRegisterFieldName(*Bitcast, V->getType(), pointee, 0);
                        Field candidate(pointee, 0);
                        if (debug) candidate.dump(LOG_INFO);
                        sourceSet.insert(std::move(candidate));
                    }
                } else {
                    if (debug) {
                        LOG(LOG_INFO, "Bitcast source is not a pointer\n");
                    }
                }
            }
        } else if (auto Call = dyn_cast<CallInst>(V)) {
            if (auto callee = Call->getCalledFunction()) {
                auto it = GlobalCtx.lockCheckFunctions.find(callee);
                if (it != GlobalCtx.lockCheckFunctions.end()) {
                    FieldSourceSet sourcesToAdapt;
                    findFields(module, Call->getArgOperand(0), sourcesToAdapt, TrackedSet, chunkAllOfThem);
                    for (auto source: sourcesToAdapt) {
                        shared_ptr <Field> field = source;
                        chainFields(field, it->second);
                        //source.dump(LOG_INFO);
                        sourceSet.emplace(move(field));
                    }
                    //findFields(Call->getArgOperand(0), SourceSet, TrackedSet, accumulatedByteOffset);
                    continue;
                }
                //LOG(LOG_VERBOSE, "Had to skip because of a call to: " << callee->getName() << "\n");
            }
#ifdef GET_GLOBALS
        } else if (auto global = dyn_cast<GlobalValue>(V)) {
            Field field(global);
            sourceSet.emplace(move(field));
#endif
        }
    }
}

static bool checkContainsPrefix(const LockCovers &coverSet,
                                const LockCover &copyNecessaryCover) {
    return any_of(coverSet, [&copyNecessaryCover](const auto &cover) {
        return copyNecessaryCover.field->isPrefixOf(*cover.first.field);
    });
}

bool containsLockCover(const LockCovers &coverSet,
                       const LockCover &necessaryCover, AllowPrefix allowPrefix) {
    LockCover copyNecessaryCover = necessaryCover; // Trivial copy

    do {
        if (coverSet.find(copyNecessaryCover) != coverSet.end() ||
            (allowPrefix == AllowPrefix::Yes && checkContainsPrefix(coverSet, copyNecessaryCover)))
            return true;

        // Go to the next nested field.
        copyNecessaryCover.field = copyNecessaryCover.field->next;
    } while (copyNecessaryCover.field);

    return false;
}

bool isCoveredByTheNecessaryLockCovers(
        const LockCovers &fieldToLockMapEntry,
        const LockCoverageMap &lockCoverage, const BasicBlock *BB) {
    auto coverageIt = lockCoverage.find(BB);
    if (coverageIt == lockCoverage.end()) // No locks are covered in this BB
        return false;

    auto [maxCover, _] = getMaxLockCoverCoveredCount(fieldToLockMapEntry);
    return containsLockCover(coverageIt->second, *maxCover);
}

bool isFieldCoveredByTheNecessaryLockCovers(const shared_ptr <Field> &field, const LockCoverageMap &lockCoverage,
                                            const FieldCoverageDataMap &fieldCoverageData, const BasicBlock *BB) {
    auto fieldCoverageDataIt = fieldCoverageData.find(field);
    if (fieldCoverageDataIt == fieldCoverageData.end())
        return true;
    return isCoveredByTheNecessaryLockCovers(fieldCoverageDataIt->second.lockCovers, lockCoverage, BB);
}

bool isThereALockCoverAlike(const shared_ptr <Field> &field, const LockCoverageMap &lockCoverage,
                            const FieldCoverageDataMap &fieldCoverageData, const BasicBlock *BB) {
    // No covers => can't contain a prefix of field.
    auto coverageIt = lockCoverage.find(BB);
    if (coverageIt == lockCoverage.end())
        return false;

    // Access style and acquisition style don't matter
    LockCover tempCover{.field = field, .originLockCall = nullptr, .lockAccessStyle = LockAccessStyle::ReadWrite, .lockAcquisitionStyle = LockAcquisitionStyle::Unconditional};
    return containsLockCover(coverageIt->second, tempCover, AllowPrefix::Yes);
}

void getPotentialFieldOperandPointersFromInstruction(const Instruction &instruction,
                                                     SmallVector<const Value *, 1> &foundOperands,
                                                     bool ignoreVolatile) {
    if (auto store = dyn_cast<StoreInst>(&instruction)) {
        if (ignoreVolatile && store->isVolatile())
            return;
        foundOperands.emplace_back(store->getOperand(1));
    } else if (auto load = dyn_cast<LoadInst>(&instruction)) {
        if (ignoreVolatile && load->isVolatile())
            return;
        foundOperands.emplace_back(load->getOperand(0));
    } else if (auto call = dyn_cast<CallInst>(&instruction)) {
        // A call may be critical, consider all address-taken arguments
#if 1
        for (unsigned int i = 0; i < call->arg_size(); ++i) {
            auto operand = call->getArgOperand(i);
            if (isa<GEPOperator>(operand) || isa<BitCastInst>(operand)) {
                foundOperands.emplace_back(operand);
            }
        }
#endif
    }
}

const MDNode *findDebugValue(const Value *value, const Function *function) {
    for (const auto &instruction: instructions(function)) {
        if (auto dbg = dyn_cast<DbgDeclareInst>(&instruction); dbg && dbg->getAddress() == value) {
            return dbg->getVariable();
        } else if (auto dbg = dyn_cast<DbgValueInst>(&instruction); dbg && dbg->getValue() == value) {
            return dbg->getVariable();
        }
    }

    return nullptr;
}

const DIType *getBaseTypeViaDebugValueOf(const Instruction &instruction) {
    if (auto debugValue = findDebugValue(instruction.getOperand(0), instruction.getFunction())) {
        if (auto diVariable = dyn_cast<DILocalVariable>(debugValue)) {
            if (auto diDerivedType = dyn_cast<DIDerivedType>(diVariable->getType())) {
                return diDerivedType->getBaseType();
            }
        }
    }
    return nullptr;
}

const StructType *getStructType(const Type *type) {
    while (type->isPointerTy())
        type = type->getPointerElementType();
    if (!type->isStructTy())
        return nullptr;
    return dyn_cast<StructType>(type);
}

static const StructLayout &getLayoutFor(const Module &M, const StructType &type) {
    return *M.getDataLayout().getStructLayout(const_cast<StructType *>(&type));
}

uint64_t getFieldBitOffsetOf(const Module &M, const StructType &type, unsigned int fieldOffset) {
    return getLayoutFor(M, type).getElementOffsetInBits(fieldOffset);
}

uint64_t getStructElementIndexFromOffset(const Module &M, const StructType &type, unsigned int byteOffset) {
    return getLayoutFor(M, type).getElementContainingOffset(byteOffset);
}

optional <string> gitBlame(const string_view &repoPath, const string_view &file, unsigned int line) {
    pid_t pid;
    int ret;

    int stdoutPipe[2];
    if (pipe2(stdoutPipe, O_CLOEXEC) < 0) {
        return {};
    }

    Deferred _([&] {
        close(stdoutPipe[0]);
    });

    char buf[32];
    snprintf(buf, sizeof(buf) - 1, "%u,%u", line, line);

    auto gitPath = "/usr/bin/git";
    const char *argv[] = {gitPath, "blame", "--no-progress", "-L", buf, file.begin(), nullptr};
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, stdoutPipe[0]);
    posix_spawn_file_actions_adddup2(&actions, stdoutPipe[1], 1);
    posix_spawn_file_actions_addclose(&actions, stdoutPipe[1]);
//    posix_spawn_file_actions_addchdir_np(&actions, repoPath.begin());
    ret = posix_spawn(&pid, gitPath, &actions, nullptr, (char **) argv, __environ);
    close(stdoutPipe[1]);
    if (!ret) {
        int status;
        while (waitpid(pid, &status, 0) < 0);
        string buffer(1024, ' ');
        ssize_t length = read(stdoutPipe[0], &buffer[0], buffer.length());
        if (length > 1) {
            buffer.resize(length - 1);
            return buffer;
        }
    }

    return {};
}

/**
 * Finds the most appropriate type for a GEP, if the offset is within the given type, that type suffices.
 * Sometimes it occurs that inheritance-like structures cause code that indexes outside a type
 * We find bitcasts that expand the type of the pointer element, these are "subclasses".
 * 
 * For example this happens in "ext4_mb_use_preallocated"
 */
const Type *getFirstAppropriateTypeForGep(const Value *sourceForGep, const Type *type, uint64_t offset) {
    auto suffices = [=](const Type *type) {
        return type->getStructNumElements() > offset;
    };

    if (suffices(type))
        return type;

    for (const auto &user: sourceForGep->users()) {
        if (auto bitcast = dyn_cast<BitCastInst>(user)) {
            // The loop is over the users of the gep, therefore we don't have to check if the operand is equal to sourceForGep anymore.
            auto destination = getStructType(bitcast->getDestTy());
            if (destination && suffices(destination)) {
                return destination;
            }
        }
    }

    return nullptr;
}

optional <CalleeMap::const_iterator>
getCalleeIteratorForPotentialCallInstruction(const GlobalContext &Ctx, const Instruction &instruction) {
    // Skip debug instructions since they do not impact the actual functionality.
    if (isa<DbgValueInst>(&instruction) || isa<DbgDeclareInst>(&instruction))
        return {};

    if (auto callInst = dyn_cast<CallInst>(&instruction)) {
        // Includes memory barriers etc
        if (callInst->isInlineAsm())
            return {};

        const auto calleeSetIt = Ctx.Callees.find(callInst);
        if (calleeSetIt != Ctx.Callees.end()) {
            return calleeSetIt;
        }
    }

    return {};
}
