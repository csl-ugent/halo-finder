#include <llvm/IR/InstIterator.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/Support/ThreadPool.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/Analysis/CFG.h>
#include "ViolationFinder.h"
#include "Common.h"
#include "Helpers.h"
#include "Config.h"
#include "ClOptForward.h"


[[nodiscard]] bool ViolationFinder::isTransitivelyOnlyUsedInASafeFunctionCall(const Value* value, int depth, bool debug, const set<const Function*>* optionalSafeFunctions) const {
    if (!FilterLikelyConcurrencySafeFunctions)
        return false;

    if (isa<DbgDeclareInst>(value) || isa<DbgValueInst>(value))
        return true;

    if (auto I = dyn_cast<CallInst>(value)) {
        return isInstructionASafeFunctionCall(I, optionalSafeFunctions);
    } else if (depth >= 0) {
        // Only GEP, Load & unaries are allowed
        if (all_of(value->users(), [this, depth, debug, optionalSafeFunctions](const User* user) {
            if (isa<GEPOperator>(user) || isa<LoadInst>(user) || isa<CastInst>(user) || isa<CallInst>(user))
                return isTransitivelyOnlyUsedInASafeFunctionCall(user, depth - 1, debug, optionalSafeFunctions);
            return false;
        })) {
            return true;
        }
    }

    if (debug) {
        OP << "isTransitivelyOnlyUsedInASafeFunctionCall DEBUG " << depth << "\n";
        value->dump();
        for (const auto* user : value->users()) {
            user->dump();
        }
    }

    return false;
}

[[nodiscard]] bool ViolationFinder::isInstructionASafeFunctionCall(const Instruction* instruction, const set<const Function*>* optionalSafeFunctions) const {
    /*if (FilterLikelyConcurrencySafeFunctions) {
        if (auto calleesIt = getCalleeIteratorForPotentialCallInstruction(GlobalCtx,
                                                                          *instruction); calleesIt.has_value()) {
            auto& it = calleesIt.value()->second;
            if (!it.empty()) {
                return all_of(it, [this](const Function* callee) {
                    return concurrencySafeFunctionSinks.find(callee) != concurrencySafeFunctionSinks.end();
                });
            }
        }
    }
    return false;*/
    if (FilterLikelyConcurrencySafeFunctions) {
        bool isSafe = false;
        if (auto calleesIt = getCalleeIteratorForPotentialCallInstruction(GlobalCtx,
                                                                          *instruction); calleesIt.has_value()) {
            auto& it = calleesIt.value()->second;
            if (!it.empty()) {
                isSafe = true;
                for (const auto *callee: it) {
                    if (concurrencySafeFunctionSinks.find(callee) == concurrencySafeFunctionSinks.end()
                        || (optionalSafeFunctions && optionalSafeFunctions->find(callee) != optionalSafeFunctions->end())) {
                        isSafe = false;
                        break;
                    }
                }
            }
        }
        return isSafe;
    }
    return false;
}

shared_ptr<Field> ViolationFinder::findCoreLock(const shared_ptr<Field>& field) const {
    auto ptr = field;
    auto ret = ptr;
    while (ptr) {
        auto type = ptr->typePtr();
        if (type->isStructTy() || type->isArrayTy()) {
            if (lockCheckerPassData.lockTypes.find(type->getPointerTo()) != lockCheckerPassData.lockTypes.end())
                break;
            ret = ptr;
        }

        ptr = ptr->next;
    }
    return ret;
}

pair<const LockCover*, unsigned int> getMaxLockCoverCoveredCount(const LockCovers& lockCovers) {
    size_t coveredCount = 0;
    const LockCover* maxCover = nullptr;
    for (const auto& [cover, localCount]: lockCovers) {
        if (localCount > coveredCount) {
            maxCover = &cover;
            coveredCount = localCount;
        }
    }
    return make_pair(maxCover, coveredCount);
}

static inline float ratioFrom(unsigned int locked, unsigned int unlocked) {
    return (float) unlocked / (locked + unlocked);
}

void ViolationFinder::fillFunctionToSyscallMap(const Function* syscall, const Function* function,
                                               set<const Function*>& visited, int depth) {
    if (depth <= 0)
        return;

    if (!visited.insert(function).second)
        return;

    functionToSyscall[function].insert(syscall);

    for (const auto& instruction: instructions(function)) {
        if (auto call = dyn_cast<CallInst>(&instruction)) {
            auto it = GlobalCtx.Callees.find(const_cast<CallInst*>(call));
            if (it == GlobalCtx.Callees.end())
                continue;
            for (const auto& callee: it->second) {
                fillFunctionToSyscallMap(syscall, callee, visited, depth - 1);
            }
        }
    }
}

void ViolationFinder::fillFunctionToSyscallMap(const vector<Function *> &functions) {
    for (const auto* function: functions) {
        if (function->isDeclaration() || !function->getName().startswith_insensitive(SyscallNamePrefix))
            continue;

        LOG(LOG_INFO, "Syscall: " << function->getName() << "\n");

        set<const Function*> visited;
        fillFunctionToSyscallMap(function, function, visited, SYSCALL_DISCOVERY_MAX_DEPTH);
    }
}

bool ViolationFinder::canGoBackToInitialization(Lazy<DominatorTree>* dt, const Instruction* instruction, const Value* operand, set<const Function*>& initFunctions, const Function* originFunction) const {
    bool debug = false; //instruction->getFunction()->getName().equals("__nilfs_btree_init"); // hci_conn_request_evt, futex_init_task, ptr_ring_init, dup_task_struct, btrfs_read_chunk_tree
    if (debug) {
        // Only interested in some fields
        FieldSourceSet sources;
        set<const Value*> tracked;
        findFields(*instruction->getModule(), operand, sources, tracked, true);
        auto found = false;
        for (const auto& source : sources) {
            if (source.fieldPtr()->getName().equals("b_ops")) {
                found = true;
                break;
            }
        }
        if (!found) debug = false;
    }

    if (initializationValues.find(const_cast<Value*>(operand)) != initializationValues.end())
        return true;

    auto doesFinalizationValueApply = [&](const Value* value, bool acceptReverseOrder) {
        if (finalizationValues.find(value) != finalizationValues.end()) {
            if (auto I = dyn_cast<Instruction>(value)) {
                return (acceptReverseOrder && isPotentiallyReachable(I, instruction, nullptr, dt->ptr(), nullptr)) || isPotentiallyReachable(instruction, I, nullptr, dt->ptr(), nullptr);
            } else {
                return true;
            }
        }
        return false;
    };

    if (doesFinalizationValueApply(operand, true))
        return true;

    set<Value*> cvset, tracked;
    lockCheckerPassData.DFA.findSourceCV(const_cast<Value*>(operand), cvset, tracked, LockInterproceduralDepth);

    if (debug) {
        LOG(LOG_INFO, "Backward analysis from :");
        operand->dump();
        LOG(LOG_INFO, "Origin function: " << originFunction->getName() << "\n");
    }

    for (const auto* source: cvset) {
#if 0
        if (debug) {
            LOG(LOG_INFO, "Source :");
            source->dump();
            if (auto i = dyn_cast<Instruction>(source)) {
                SourceLocation(i).dump(LOG_INFO);
                LOG(LOG_INFO, "\n");
            }
        }
#endif

        if (initializationValues.find(source) != initializationValues.end() || doesFinalizationValueApply(source, false)) {
            const Function* sourceFunction = nullptr;
            if (auto I = dyn_cast<Instruction>(source)) {
                sourceFunction = I->getFunction();
            } else if (auto A = dyn_cast<Argument>(source)) {
                sourceFunction = A->getParent();
            }
            if (sourceFunction == originFunction)
                return true;
            initFunctions.insert(sourceFunction);
        }

        if (auto call = dyn_cast<CallInst>(source)) {
            if (!call->isIndirectCall()) {
                auto it = getCalleeIteratorForPotentialCallInstruction(GlobalCtx, *call);
                if (it.has_value()) {
                    // The called function could be an allocator
                    for (const auto* calledFunction: it.value()->second) {
                        if (allocFunctions.find(calledFunction) != allocFunctions.end()) {
                            if (debug) {
                                LOG(LOG_INFO, "Alloc function found inside " << call->getFunction()->getName() << " by " << calledFunction->getName() << "\n");
                            }
                            // Fast path
                            if (call->getFunction() == originFunction)
                                return true;
                            initFunctions.insert(call->getFunction());
                            break;
                        }
                    }
                }
            }
        }
    }

    return false;
}

void
ViolationFinder::calculateInitializationValuesIndividual(const Function* function, mutex* initializationValuesMutex, mutex* finalizationValuesMutex) {
    Lazy<PostDominatorTree> postDominatorTree([function] {
        return PostDominatorTree(*const_cast<Function*>(function));
    });

    bool debug = false; //function->getName().equals("wl3501_config"); // nilfs_bmap_read, disk_release_events, dma_buf_release, hci_le_conn_failed

    for (const auto& BB: *function) {
        for (const auto& instruction: BB) {
            // Lock initialiser case
            if (isa<StoreInst>(instruction)) {
                if (debug) {
                    LOG(LOG_INFO, "Potential Lock Init Instruction: ");
                    instruction.dump();
                }

                SmallVector<const Value*, 1> operands;
                getPotentialFieldOperandPointersFromInstruction(instruction, operands, IgnoreVolatile);
                for (const auto* operand: operands) {
                    FieldSourceSet fields;
                    set<const Value*> visited;
                    findFields(*instruction.getModule(), operand, fields, visited, true);
                    if (debug) operand->dump();
                    auto isLock = false;
                    for (const auto& field: fields) {
                        if (debug) {
                            LOG(LOG_INFO, "In: " << BB.getParent()->getName() << "\n");
                            field.fieldPtr()->dump(LOG_INFO);
                        }

                        // Detect lock types
                        auto ptr = field.fieldPtr().get();
                        while (ptr) {
                            const Type* tmp;
                            if (lockCheckerPassData.lockTypes.find(ptr->typePtr()) != lockCheckerPassData.lockTypes.end()
                                || lockCheckerPassData.lockTypes.find(ptr->typePtr()->getPointerTo()) != lockCheckerPassData.lockTypes.end()
                                || ((tmp = ptr->fieldTypePtr()) && (lockCheckerPassData.lockTypes.find(tmp) != lockCheckerPassData.lockTypes.end() || lockCheckerPassData.lockTypes.find(tmp->getPointerTo()) != lockCheckerPassData.lockTypes.end()))) {
                                isLock = true;
                                break;
                            }
                            ptr = ptr->next.get();
                        }

                        if (isLock) break;
                    }

                    if (isLock) {
                        if (debug) {
                            LOG(LOG_INFO, "It is a lock!\n");
                        }

                        {
                            lock_guard _(uninitializedLockFieldsMutex);
                            for (const auto& field : fields) {
                                auto ptr = findCoreLock(field.fieldPtr());
                                ptr->next = nullptr;
                                uninitializedLockFields.erase(ptr);
                            }
                        }

                        if (auto bitcast = dyn_cast<BitCastOperator>(operand)) {
                            operand = bitcast->getOperand(0);
                        }

                        if (auto gep = dyn_cast<GetElementPtrInst>(operand)) {
                            auto ptr = gep->getPointerOperand();
                            lock_guard _(*initializationValuesMutex);
                            initializationValues.insert(ptr->user_begin(), ptr->user_end());
                            initializationValues.insert(ptr);

                            // Function is a lock initializer
                            if (auto argument = dyn_cast<Argument>(ptr)) {
                                if (debug) argument->dump();
                                // Track the GEP in the parent
                                auto callersIt = GlobalCtx.Callers.find(const_cast<Function*>(function));
                                if (callersIt != GlobalCtx.Callers.end()) {
                                    for (const auto *caller: callersIt->second) {
                                        if (argument->getArgNo() < caller->arg_size()) {
                                            auto callerOperand = caller->getArgOperand(argument->getArgNo());
                                            initializationValues.insert(callerOperand);

                                            if (auto bitcast = dyn_cast<BitCastOperator>(callerOperand)) {
                                                callerOperand = bitcast->getOperand(0);
                                            }

                                            if (auto gep = dyn_cast<GetElementPtrInst>(callerOperand)) {
                                                auto ptr = gep->getPointerOperand();
                                                initializationValues.insert(ptr->user_begin(), ptr->user_end());
                                                initializationValues.insert(ptr);

                                                if (debug) {
                                                    LOG(LOG_INFO, "GEP\n");
                                                    ptr->dump();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else if (auto call = dyn_cast<CallInst>(&instruction)) {
                if (call->isIndirectCall())
                    continue;
                for (const auto* callee : GlobalCtx.Callees[const_cast<CallInst*>(call)]) {
                    if (freeFunctions.find(callee) != freeFunctions.end()) {
                        auto freeingArgumentIdx = 0;//call->arg_size() - 1;
                        auto currentValue = call->getArgOperand(freeingArgumentIdx);

                        if (debug) {
                            LOG(LOG_INFO, "Debug current value:\n");
                            currentValue->dump();
                        }

                        {
                            lock_guard _(*finalizationValuesMutex);
                            finalizationValues.insert(call);
                            finalizationValues.insert(currentValue);
                            if (auto bitcast = dyn_cast<BitCastInst>(currentValue))
                                finalizationValues.insert(bitcast->getOperand(0));
                            if (auto GEP = dyn_cast<GEPOperator>(currentValue))
                                finalizationValues.insert(GEP->getOperand(0));
                        }

                        if (isFreeCallAlwaysExecutedRegardlessOfNullChecks(*const_cast<Function*>(function), call, postDominatorTree)) {
                            if (debug) {
                                LOG(LOG_INFO, "Free always executed regardless of null checks: " << function->getName() << "->" << callee->getName() << "\n");
                            }

                            set<Value *> trackedSet, cvSet;
                            lockCheckerPassData.DFA.findSourceCV(currentValue, cvSet, trackedSet, 0);

                            lock_guard _(*finalizationValuesMutex);
                            for (const auto *value: cvSet) {
                                finalizationValues.insert(value);
                                //if (debug) {
                                //    value->dump();
                                //}
                            }
                        }
                    } else if (allocFunctions.find(callee) != allocFunctions.end()) {
                        const Value* currentValue = call;

                        lock_guard _(*initializationValuesMutex);
                        initializationValues.insert(currentValue);
                    }
                }
            }
        }
    }

    if (debug) {
        LOG(LOG_INFO, "Debug exit\n");
        exit(1);
    }
}

void ViolationFinder::calculateInitializationValues(const vector<Function *> &functions) {
    ThreadPool threadPool(hardware_concurrency(ThreadCount));
    mutex initializationValuesMutex, finalizationValuesMutex;

    // Calculate the operands that lead back to an object that's initialized (by checking initialization on their locks)
    for (const auto* function: functions) {
        if (GlobalCtx.shouldSkipFunction(function))
            continue;

        threadPool.async(&ViolationFinder::calculateInitializationValuesIndividual, this, function,
                         &initializationValuesMutex, &finalizationValuesMutex);
    }

    threadPool.wait();

    OP << "Uninitialized locks:\n";
    for (const auto& entry : uninitializedLockFields) {
        entry->dump(LOG_INFO);
    }
}

bool ViolationFinder::interproceduralRecheckCheckFunctionCallee(const Function* function, const shared_ptr<Field>& field, const FieldCoverageData& coverageData) const {
    auto& entry = function->getEntryBlock();
    auto successor = entry.getUniqueSuccessor();
    if (!successor)
        return false;

    /**
     * Note: BOI (Block Of Interest) is NOT the entry! It is the unique successor,
     *       that's because our algorithm will split on the lock instruction, so the lock will be in the SECOND block!
     * 1. The BOI must be locked by the right lock
     * 2. The BOI must contain the check on the field
     */

    // 1.
    if (!isCoveredByTheNecessaryLockCovers(coverageData.lockCovers, lockCoverageMap, successor))
        return false;

    // 2.
    auto branch = dyn_cast<BranchInst>(successor->getTerminator());
    if (!branch || !branch->isConditional())
        return false;
    auto condition = dyn_cast<ICmpInst>(branch->getCondition());
    if (!condition)
        return false;
    auto operand = condition->getOperand(0);
    FieldSourceSet sourceSet;
    set<const Value*> trackedSet;
    findFields(*condition->getModule(), operand, sourceSet, trackedSet, true);
    return any_of(sourceSet.begin(), sourceSet.end(), [field](const FieldWithMaybeCompareType& entry) {
        return entry.fieldPtr()->operator==(*field);
    });
}

void ViolationFinder::findViolationsInFunction(const Function* function) {
    auto registerFpRecheck = [this, function] {
        (void) this;
        (void) function;
#ifdef COUNT_HOW_MANY_TIMES_FP_RECHECK_IS_DETECTED
        lock_guard _(functionsWithFpRecheckMutex);
        functionsWithFpRecheck.insert(function);
#endif
    };

    Lazy<DominatorTree> dt([function] {
        return DominatorTree(*const_cast<Function*>(function));
    });

    bool debug = false; //function->getName().equals(/*"aac_src_intr_message"*/"fw_core_handle_bus_reset");

    struct PairComparator {
        using E = pair<unsigned int, shared_ptr<Field>>;
        bool operator()(const E& a, const E& b) const {
            if (a.first < b.first) return true;
            if (a.first == b.first) return a.second->operator<(*b.second);
            return false;
        }
    };

    // A single field access may be duplicated in multiple basic blocks.
    // We only want to count this once.
    // We need to store a pair of the line number and which field is accessed since multiple field accesses can occur on the same line.
    set<pair<unsigned int, shared_ptr<Field>>, PairComparator> seenLineSet;

    for (const auto& instruction: instructions(function)) {
        if (initializationValues.find(&instruction) != initializationValues.end())
            continue;

        if (isInstructionASafeFunctionCall(&instruction, {}))
            continue;

        auto BB = instruction.getParent();
        SmallVector<const Value*, 1> operands;
        getPotentialFieldOperandPointersFromInstruction(instruction, operands, IgnoreVolatile);
        for (const auto* operand: operands) {
            if (debug) {
                LOG(LOG_INFO, "Operand in findViolationsInFunction:");
                operand->dump();
                LOG(LOG_INFO, "Instruction in findViolationsInFunction:");
                instruction.dump();
            }
            set<const Function*> initFunctions;
            bool operandIsInitializerOrFinalizer = canGoBackToInitialization(&dt, &instruction, operand, initFunctions, function);
            if (operandIsInitializerOrFinalizer)
                continue;

            FieldSourceSet fields;
            set<const Value*> visited;
            findFields(*instruction.getModule(), operand, fields, visited, true);
            for (auto fieldCandidate: fields) {
                bool addedUsesForThisField = false;
                shared_ptr<Field> field = fieldCandidate;

                auto coverageDataIt = fieldCoverageData.find(field);
                if (coverageDataIt == fieldCoverageData.end())
                    continue;
                
                auto& coverageData = coverageDataIt->second;

                if (debug) {
                    LOG(LOG_INFO, "Field in: " << function->getName() << "\n");
                    field->dump(LOG_INFO);
                    auto it = lockCoverageMap.find(BB);
                    for (const auto& [cover, _]: coverageData.lockCovers) {
                        LOG(LOG_INFO, "  needs: ");
                        cover.field->dump(LOG_INFO);
                        LockCoverHash h;
                        LOG(LOG_INFO, "    hash: " << h.operator()(cover) << "\n");
                        if (it != lockCoverageMap.end()) {
                            LOG(LOG_INFO, "    do we have this? " << (it->second.find(cover) != it->second.end() ? "yes" : "no") << "\n");
                        }
                    }
                    if (it != lockCoverageMap.end()) {
                        for (const auto& [cover, _]: it->second) {
                            LOG(LOG_INFO, "  has: ");
                            cover.field->dump(LOG_INFO);
                            LockCoverHash h;
                            LOG(LOG_INFO, "    hash: " << h.operator()(cover) << "\n");
                        }
                    }
                }

                if (coverageData.lockCovers.empty()) {
                    if (debug) {
                        LOG(LOG_INFO, "But this field is never covered by a lock!\n");
                    }
                    continue;
                }

                if (DILocation* diNodeInstruction = instruction.getDebugLoc().get()) {
                    if (!seenLineSet.insert(make_pair(diNodeInstruction->getLine(), field)).second) {
                        if (debug) {
                            LOG(LOG_INFO, "Skip because of duplicated line: " << diNodeInstruction->getLine() << "\n");
                        }
                        continue;
                    }
                }

                if (isCoveredByTheNecessaryLockCovers(coverageData.lockCovers, lockCoverageMap, BB)) {
                    if (debug) {
                        LOG(LOG_INFO, "But this field is covered by the necessary locks!\n");
                    }
                    continue;
                }

                // fp:recheck filter
                if (FilterFpRecheck) {
                    bool debugFpRecheck = false; //function->getName().equals("f2fs_submit_merged_ipu_write"); // fuse_dev_do_read
                    if (debugFpRecheck) {
                        OP << "debug fp recheck\n";
                        instruction.dump();
                        operand->dump();
                    }

                    // Interprocedural check
                    {
                        for (const auto* user : instruction.users()) {
                            // Check which branching instruction depends on a condition of the instruction
                            auto icmp = dyn_cast<ICmpInst>(user);
                            if (!icmp) continue;
                            auto branch = dyn_cast<BranchInst>(instruction.getParent()->getTerminator());
                            if (!branch || !branch->isConditional() || branch->getCondition() != icmp) continue;
                            // Check which branch performs a function call
                            for (unsigned int i = 0, l = branch->getNumSuccessors(); i < l; ++i) {
                                auto successor = branch->getSuccessor(i);
                                if (successor->size() == 2 /* call + terminator */) {
                                    if (auto callees = getCalleeIteratorForPotentialCallInstruction(GlobalCtx, *successor->getFirstNonPHI()); callees.has_value()) {
                                        auto& it = callees.value()->second;
                                        if (it.size() == 1 && all_of(it.begin(), it.end(), [&](const Function* target) {
                                            return interproceduralRecheckCheckFunctionCallee(target, field, coverageData);
                                        })) {
                                            registerFpRecheck();
                                            goto skip;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    for (const auto *operandUser: operand->users()) {
                        if (auto bitcast = dyn_cast<BitCastInst>(operandUser)) {
                            operandUser = *bitcast->user_begin();
                        }

                        if (auto load = dyn_cast<LoadInst>(operandUser)) {
                            if (debugFpRecheck) {
                                OP << "Potential FP recheck:\n";
                                load->dump();
                            }

                            unsigned int uncoveredCount = 0, coveredCount = 0;
                            for (const auto *loadUser: load->users()) {
                                if (auto bitcast = dyn_cast<BitCastInst>(loadUser))
                                    loadUser = *bitcast->user_begin();
                                if (auto recheckCmp = dyn_cast<ICmpInst>(loadUser)) {
                                    if (debugFpRecheck) {
                                        recheckCmp->dump();
                                    }
                                    if (!isCoveredByTheNecessaryLockCovers(coverageData.lockCovers, lockCoverageMap,
                                                                           recheckCmp->getParent())) {
                                        ++uncoveredCount;
                                    } else {
                                        ++coveredCount;
                                    }
                                }
                            }

                            if (debugFpRecheck) {
                                OP << "Counts: " << coveredCount << ", " << uncoveredCount << "\n";
                            }

                            if (coveredCount > 0 && uncoveredCount <= 1) {
                                registerFpRecheck();
                                goto skip;
                            }
                        }
                    }
                }

/*                if (isTransitivelyOnlyUsedInASafeFunctionCall(&instruction, 3, false))
                    continue;
        		bool transitivelySafe = isTransitivelyOnlyUsedInASafeFunctionCall(&instruction, 3, false, &initFunctions);*/

                bool isTransitivelyOnlyUsedInASafeFunctionCallDebug = false; //field->offset == 35 && function->getName().equals("sky2_link_up");

                auto store = [&](vector<const Instruction*>&& path) {
                    lock_guard _(findViolationsInFunctionStoreMutex);
                    //coverageData.paths.emplace_back(move(path));
                    /*if (!all_of(instruction.users(), [this](const User* user) {
                        if (isa<DbgDeclareInst>(user) || isa<DbgValueInst>(user) || isa<GetElementPtrInst>(user))
                            return true;
                        auto I = dyn_cast<Instruction>(user);
                        if (!I)
                            return false;
                        return isInstructionASafeFunctionCall(I);
                    }))*/ /*if (!transitivelySafe)*/ {
                        coverageData.paths.emplace_back(move(path));
                    }

                    if (!addedUsesForThisField) {
                        bool addedSomething = false;
                        for (auto user: instruction.users()) {
                            if (!isa<DbgDeclareInst>(user) && !isa<DbgValueInst>(user) && !isa<GetElementPtrInst>(user)) {
                                addedSomething = true; // Do this first to not add one to the counter in the fallback path
                                if (isTransitivelyOnlyUsedInASafeFunctionCall(user, 3, isTransitivelyOnlyUsedInASafeFunctionCallDebug, &initFunctions))
                                    continue;

                                coverageData.notLockedCounter.emplace(user);
                            }
                        }

                        if (!addedSomething)
                            coverageData.notLockedCounter.emplace(&instruction);

                        addedUsesForThisField = true;
                    }
                };

                auto checker = [&initFunctions](const shared_ptr <Field> &field, const LockCoverageMap &lockCoverage,
                                  const FieldCoverageDataMap &fieldCoverageData, const BasicBlock *BB) -> bool {
                    if (initFunctions.find(BB->getParent()) != initFunctions.end())
                        return true;

                    return isFieldCoveredByTheNecessaryLockCovers(field, lockCoverage, fieldCoverageData, BB);
                };

                // Use backward flow analysis to determine if there are (eventually) callsites which are covered.
                vector<const Instruction*> path{&instruction};
                set<const Function*> visitedFunctions;
                if (!interproceduralFieldCoverCheck(field, lockCoverageMap, BB,
                                                    LockInterproceduralDepth, [&](const BasicBlock* discoveredViaBB,
                                                                                  vector<const Instruction*>&& v) {
                            store(move(v));
                        }, checker, move(path), visitedFunctions)) {
                    if (debug) LOG(LOG_INFO, "Interprocedural returned false\n");
                    lock_guard _(findViolationsInFunctionStoreMutex);

                    // Account for critical sources
                    lazyOperandTracking[field->typePtr()].entries.emplace_back(LazyOperandTracker::Entry {
                            .operand = operand,
                            .field = field,
                            .unlocked = true,
                            .addSet = true,
                            .mustBelief = false,
                    });
                } else {
                    if (debug) LOG(LOG_INFO, "Interprocedural returned true\n");
                    //LOG(LOG_INFO, "Oh turns out it's fine: " << function->getName() << ": " << initFunctions.size() << "\n");

                    /*lock_guard _(findViolationsInFunctionStoreMutex);

                    // Account for critical sources
                    lazyOperandTracking[field->typePtr()].entries.emplace_back(LazyOperandTracker::Entry {
                            .operand = operand,
                            .field = field,
                            .unlocked = false,
                            .addSet = true,
                            .mustBelief = false,
                    });*/
                }
            }

            skip:;
        }
    }

    if (debug) {
        exit(1);
    }
}

static bool isLockCoverBroaderApplicable(const LockCover& currentBest, const LockCover& proposal) {
    return currentBest.lockAccessStyle == LockAccessStyle::ReadOnly &&
           proposal.lockAccessStyle == LockAccessStyle::ReadWrite;
}

/**
 * Finds the closest lock cover for a field inside a set of locks
 * The closest lock cover is the one which has the field depth closest to the lock
 * Returns null if none
 * @param accessedField
 * @param coverSet
 * @return
 */
static const LockCover*
findClosestCoverForField(const Field& accessedField, const LockCovers& coverSet) {
    int bestScore = 99999;
    const LockCover* bestCover = nullptr;
    bool first = true;
    auto depthOfField = accessedField.depth();
    bool debug = false; //accessedField.type->getStructName().contains("controller");
    if (debug) {
        LOG(LOG_INFO, "All covers available " << coverSet.size() << ":\n");
        for (const auto& [cover, _]: coverSet) {
            LOG(LOG_INFO, "\t");
            cover.field->dump(LOG_INFO);
            LOG(LOG_INFO, "\tDepth: " << cover.field->depth() << "\n");
        }
    }
    for (const auto& [cover, _]: coverSet) {
        auto coverFieldDepth = cover.field->depth();

        // d(lock) <= d(field) because the field must be deeper or at equal depth in order to be able to be protected by the lock
        if (coverFieldDepth > depthOfField)
            continue;

        auto currentScore = abs(coverFieldDepth - depthOfField);
        if (debug) {
            LOG(LOG_INFO, "current score: " << currentScore << ", best score: " << bestScore << "\n");
            accessedField.dump(LOG_INFO);
            cover.field->dump(LOG_INFO);
        }
        // If it's the first time => new best
        // If the score improves => new best
        if (first || currentScore < bestScore || (currentScore == bestScore &&
                                                  isLockCoverBroaderApplicable(*bestCover, cover))) {
            first = false;
            bestCover = &cover;
            bestScore = currentScore;
        }
    }
    return bestCover;
}

void ViolationFinder::accountCriticalSourcesLockUnlockCounts(const vector<ValueWithIndirections>& cvSet, const shared_ptr<Field>& field, bool unlocked, const Value* startOperand, const shared_ptr<Field>& lockField) {
#if 0
    if (unlocked&&field->offset == 1 && field->getName().equals("addr_list")) {
        OP << "TEST1\n";
        for (const auto& entry : cvSet) {
            if (auto I = dyn_cast<Instruction>(entry.value)) {
                OP << "\tF: " << I->getFunction()->getName() << "\n";
            }
        }
    }
#endif

    auto& contexts = fieldToContextsSet[field];
    auto lastLockType = field->typePtr();

    bool debugDumpSources = false; //field->last().getName().equals("location") && field->last().offset == 1; //field->getName().equals("op_mode") && field->offset == 37;
    for (const auto& entry : cvSet) {
        if (entry.type == ValueWithIndirections::ValueType::Interface) {
            auto& container = interfaceSourceToLockUnlockCounts[Field(entry.fieldContainingType, entry.fieldOffset)][lastLockType];
            if (unlocked) {
                container.unlocked += entry.indirections;
                container.unlockedCount++;
            } else {
                container.locked += entry.indirections;
                container.lockedCount++;
            }
            // Keep track of the relevant paths in case there is a violation
            if (unlocked) {
                contexts.interfaces.insert(Field(entry.fieldContainingType, entry.fieldOffset));
            }
        } else {
            if (isa<Argument>(entry.value)) {
                auto &container = valueSourceToLockUnlockCounts[entry.value][lastLockType];
                if (unlocked) {
                    container.unlocked += entry.indirections;
                    container.unlockedCount++;
                } else {
                    container.locked += entry.indirections;
                    container.lockedCount++;
                }
                if (debugDumpSources) {
                    LOG(LOG_INFO,
                        "Dump arg source: " << dyn_cast<Argument>(entry.value)->getParent()->getName() << "\n");
                    entry.value->dump();
                }
                // Keep track of the relevant paths in case there is a violation
                if (unlocked) {
                    contexts.values.insert(entry.value);
                }
#if 0
                if (field->getName().equals("priv") && field->last().offset == 29) {
                    if (dyn_cast<Argument>(entry.value)->getParent()->getName().equals("rtl8723be_hw_init")) {
                        if (auto a = dyn_cast<Argument>(startOperand)) {
                            OP << "ABCD1: " << a->getParent()->getName() << " " << (unlocked ? "unlocked" : "locked") << "\n";
                        } else if (auto I = dyn_cast<Instruction>(startOperand)) {
                            OP << "ABCD2: " << I->getFunction()->getName() << " " << (unlocked ? "unlocked" : "locked") << "\n";
                        }
                        field->dump(LOG_INFO);
                        entry.value->dump();
                    }
                }
#endif
            } else if (auto call = dyn_cast<CallInst>(entry.value)) {
                auto calleesIt = getCalleeIteratorForPotentialCallInstruction(GlobalCtx, *call);
                if (calleesIt.has_value()) {
                    for (const auto *target: calleesIt.value()->second) {
                        if (allocFunctions.find(target) != allocFunctions.end())
                            continue;

                        auto hash = funcHash(target, true);
                        auto &container = functionSourceToLockUnlockCounts[hash][lastLockType];
                        if (unlocked) {
                            container.unlocked += entry.indirections;
                            container.unlockedCount++;
                        } else {
                            container.locked += entry.indirections;
                            container.lockedCount++;
                        }
                        // Keep track of the relevant paths in case there is a violation
                        if (unlocked) {
#ifdef DEBUG_KEEP_HAS_TO_FUNC_NAME
                            if (auto it = hashToFunction.find(hash); it != hashToFunction.end()) {
                                if (!target->getName().equals(it->second->getName()))
                                    OP << "Expected: " << it->second->getName() << ", but have now: "
                                       << target->getName() << "\n";
                            }
                            hashToFunction[hash] = target;
#endif
                            contexts.functions.insert(hash);
                        }
                    }
                }

                if (debugDumpSources) {
                    LOG(LOG_INFO, "Dump call source:\n");
                    entry.value->dump();
                }
            }
        }
    }
}

bool ViolationFinder::isFirstOrLastLockedField(const Instruction& instructionToBeCovered, const shared_ptr<Field>& field) const {
    /**
     * We want to check if the previous line is a lock.
     * However, the previous line may be whitespace or comments.
     * Therefore, we have to find the first previous instruction which is on a different line.
     * Note: multi-line statements will have their debug info tied to the same line.
     *
     * Check by going backwards to find the first instruction with a different line.
     * If that is the one doing the lock, we know this was the first field access.
     */
    auto currentInst = &instructionToBeCovered;
    auto oldDbg = currentInst->getDebugLoc().get();
    if (!oldDbg)
        return false;
    auto oldLine = oldDbg->getLine();
    while ((currentInst = currentInst->getPrevNonDebugInstruction(true))) {
        auto currentDbg = currentInst->getDebugLoc().get();
        if (currentDbg && currentDbg->getLine() != oldLine) {
            auto callees = getCalleeIteratorForPotentialCallInstruction(GlobalCtx, *currentInst);
            if (callees.has_value()) {
                for (const auto* callee: callees.value()->second) {
                    if (lockCheckerPassData.lockers.find(callee) != lockCheckerPassData.lockers.end())
                        return true;
                }
            }

            break;
        }
    }

    // Analogous for unlock
    if (auto uniqueSuccessor = instructionToBeCovered.getParent()->getUniqueSuccessor()) {
        /**
         * 1. There is no instruction with a different line number
         * 2. The first instruction that will be executed after this one is the unlock
         */

        currentInst = &instructionToBeCovered;
        // 1.
        while ((currentInst = currentInst->getNextNonDebugInstruction(true))) {
            if (isa<BranchInst>(currentInst)) break;
            auto currentDbg = currentInst->getDebugLoc().get();
            if (currentDbg && currentDbg->getLine() != oldLine) {
                return false;
            }
        }

        // 2.
        auto maybeUnlock = uniqueSuccessor->getFirstNonPHI();
        auto callees = getCalleeIteratorForPotentialCallInstruction(GlobalCtx, *maybeUnlock);
        if (callees.has_value()) {
            for (const auto* callee: callees.value()->second) {
                if (lockCheckerPassData.unlockers.find(callee) != lockCheckerPassData.unlockers.end()) {
                    return true;
                }
            }
        }
    }

    return false;
}

void ViolationFinder::findPotentialRulesIndividual(const Function* function, ReadWriteViolationCoverToInstructionsMap* readWriteViolationCoverToInstructions, mutex* readWriteViolationCoverToInstructionsMutex, mutex* privateVarMutex) {
    //LOG(LOG_INFO, "findPotentialRulesIndividual: " << function->getName() << "\n");
    for (const auto& BB : *function) {
        auto coversIt = lockCoverageMap.find(&BB);
        if (coversIt == lockCoverageMap.end())
            continue;
        auto& covers = coversIt->second;

        bool debug = false; //BB.getParent()->getName().equals(/*"packet_mmap"*/"addrconf_verify_rtnl");
        auto end = BB.end();
        for (auto it = BB.begin(); it != end; ++it) {
            bool coveredAtLeastOnce = false;

            auto &instruction = *it;
            SmallVector<const Value *, 1> operands;
            getPotentialFieldOperandPointersFromInstruction(instruction, operands, IgnoreVolatile);
            for (const auto* operand: operands) {
                // Skip if it's a lock
                if (lockCheckerPassData.lockTypes.find(operand->getType()) != lockCheckerPassData.lockTypes.end())
                    continue;

                FieldSourceSet fields;
                set<const Value *> visited;
                findFields(*instruction.getModule(), operand, fields, visited, true);

                // Skip if it's a lock
                if (any_of(fields, [this](const FieldWithMaybeCompareType& fieldCandidate) {
                    const auto& field = fieldCandidate.fieldPtr();
                    auto fieldTypePtr = field->fieldTypePtr();
                    if (!fieldTypePtr)
                        return false;
                    return lockCheckerPassData.lockTypes.find(fieldTypePtr) != lockCheckerPassData.lockTypes.end()
                        || lockCheckerPassData.lockTypes.find(fieldTypePtr->getPointerTo()) != lockCheckerPassData.lockTypes.end();
                })) {
                    continue;
                }

                // Figure out full length
                int length = 0;
                for (const auto& fieldCandidate: fields)
                    length = max(fieldCandidate.fieldPtr()->depth(), length);

                for (auto fieldCandidate: fields) {
                    shared_ptr <Field> field = fieldCandidate;

                    // Simply don't make any rules for non-security critical fields if we need to filter for security checks.
                    // Then no violations will be reported for these fields as well (since there are no rules).
                    if (SecurityChecks && GlobalCtx.securityCriticalFields.find(field) == GlobalCtx.securityCriticalFields.end()) {
                        continue;
                    }

                    LockCovers applicableLockCoversForCurrentBBAndField;

                    bool mustBelief = false;
                    for (const auto &[cover, _]: covers) {
                        // If the cover can protect the field
                        if (cover.field->embeddedPtr() == fieldCandidate.potentialCompareType() ||
                            canCoverField(*cover.field, *field)) {
                            if (debug) {
                                LOG(LOG_INFO, "Register in lock map\n");
                                field->dump(LOG_INFO);
                                cover.field->dump(LOG_INFO);
                            }

                            bool addedSomething = false;
                            for (const auto* user: instruction.users()) {
                                if (!isa<DbgDeclareInst>(user) && !isa<DbgValueInst>(user)) {
                                    applicableLockCoversForCurrentBBAndField[cover]++;
                                    addedSomething = true;
                                }
                            }
                            if (!addedSomething)
                                applicableLockCoversForCurrentBBAndField[cover]++;

                            if (!mustBelief && field->depth() == length) {
                                auto nextInstruction = instruction.getNextNonDebugInstruction(true);
                                if (!isa<GetElementPtrInst>(nextInstruction) || find(nextInstruction->operands().begin(), nextInstruction->operands().end(), &instruction) == nextInstruction->operands().end())
                                    mustBelief = isFirstOrLastLockedField(instruction, field);
                            }
                        }
                    }

                    bool addSet = !applicableLockCoversForCurrentBBAndField.empty();

                    privateVarMutex->lock();
                    auto& fieldCoverageDataEntry = fieldCoverageData[field];
                    fieldCoverageDataEntry.lockCovers.insert(applicableLockCoversForCurrentBBAndField.begin(),
                                    applicableLockCoversForCurrentBBAndField.end());
                    lazyOperandTracking[field->typePtr()].entries.emplace_back(LazyOperandTracker::Entry {
                            .operand = operand,
                            .field = field,
                            .unlocked = false,
                            .addSet = addSet,
                            .mustBelief = mustBelief,
                    });
                    auto updateFieldLockPreferences = [&] {
                        if (auto it = fieldLockPreference.find(field); it == fieldLockPreference.end()) {
                            auto& set = fieldLockPreference[field];
                            for (const auto& [entry, _] : applicableLockCoversForCurrentBBAndField) {
                                /*if (entry.originLockCall->getFunction() == function) */{
                                    set.insert(entry.field);
                                }
                            }
                        } else {
                            auto& set = it->second;
                            auto entryIt = set.begin();
                            while (entryIt != set.end()) {
                                if (!any_of(applicableLockCoversForCurrentBBAndField, [&](const auto& cover) {
                                    return cover.first.field->operator==(*entryIt->get());
                                })) {
                                    entryIt = set.erase(entryIt);
                                } else {
                                    ++entryIt;
                                }
                            }
                        }
                    };
                    if (mustBelief) {
                        mustBeliefFields.insert(field);
                        updateFieldLockPreferences();
                    }
                    privateVarMutex->unlock();

                    if (addSet) {
                        coveredAtLeastOnce = true;
                        lock_guard _(*privateVarMutex);
                        if (RequireFieldToBeStoredOrUnsafeUsedInACallUnderALock/* && field->depth() == length*/) {
                            if (isa<StoreInst>(instruction) || isa<CallInst>(instruction)) {
                                /*if (field->last().getName().equals("cons_index") || (field->last().getName().equals("max")&&field->last().offset==2)) {
					                field->dump(LOG_INFO);
                                    OP << "FOUND IT: " << function->getName() << "\n";
                                    instruction.dump();
                                    for (const auto& cover : applicableLockCoversForCurrentBBAndField) {
                                        cover.field->dump(LOG_INFO);
                                    }
                                }*/
                            }

                            if (isa<StoreInst>(instruction)) {
                                writtenToOrEscapedFields.insert(field->last());
                            } else if (auto call = dyn_cast<CallInst>(&instruction)) {
                                bool ignore = false;
#if 0
                                unsigned int operandNrInArg = -1U;
                                for (unsigned int i = 0; i < call->arg_size(); ++i) {
                                    if (call->getArgOperand(i) == operand) {
                                        operandNrInArg = i;
                                        break;
                                    }
                                }
                                if (operandNrInArg != -1U && !call->isIndirectCall()) {
                                    auto calleesIt = GlobalCtx.Callees.find(call);
                                    if (calleesIt != GlobalCtx.Callees.end()) {
                                        // All possible targets are not writing to the argument
                                        ignore = all_of(calleesIt->second, [this, operandNrInArg](const Function *target) {
                                            auto it = lockCheckerPassData.storeTaintData.find(target);
                                            if (it == lockCheckerPassData.storeTaintData.end())
                                                return true;
                                            if (it->second.cyclic)
                                                return false;
                                            return std::find(it->second.argumentsWithStores.begin(), it->second.argumentsWithStores.end(), operandNrInArg) == it->second.argumentsWithStores.end();
                                        });
                                    }
                                }
#endif
                                if (!ignore) {
                                    if (FilterLikelyConcurrencySafeFunctions)
                                        writtenToOrEscapedFieldsDeferredCalls[field->last()].insert(call);
                                    else
                                        writtenToOrEscapedFields.insert(field->last());
                                } else {
                                    OP << "Ignore: ";
                                    field->dump(LOG_INFO);
                                }
                            }
                        }
                    }

                    if (FindReadOnlyWriteViolations && isa<StoreInst>(instruction)) {
                        auto cover = findClosestCoverForField(*field, applicableLockCoversForCurrentBBAndField);

                        if (cover && cover->lockAccessStyle == LockAccessStyle::ReadOnly) {
                            LockCover copy(*cover);
                            lock_guard _(*readWriteViolationCoverToInstructionsMutex);
                            (*readWriteViolationCoverToInstructions)[move(copy)].push_back(make_pair(&instruction, field));
                        }
                    }
                }
            }

            if (coveredAtLeastOnce && FilterLikelyConcurrencySafeFunctions) {
                auto calleesIt = getCalleeIteratorForPotentialCallInstruction(GlobalCtx, instruction);
                if (calleesIt.has_value()) {
                    lock_guard _(*privateVarMutex);
                    for (const auto *callee: calleesIt.value()->second) {
                        sinkFunctionCallLockedCount[callee]++;
                    }
                }
            }
        }
    }
}

const SourceLocation& getSourceLocationMemoized(const Instruction* ins) {
    static map<const Instruction*, SourceLocation> sourceLocationCache;
    static shared_mutex sourceLocationMutex;

    sourceLocationMutex.lock_shared();
    if (auto it = sourceLocationCache.find(ins); it != sourceLocationCache.end()) {
        sourceLocationMutex.unlock_shared();
        return it->second;
    } else {
        sourceLocationMutex.unlock_shared();
        SourceLocation sourceLocation(ins);
        sourceLocationMutex.lock();
        auto newIt = sourceLocationCache.insert({ins, move(sourceLocation)}).first;
        sourceLocationMutex.unlock();
        return newIt->second;
    }
}

void ViolationFinder::findPotentialRules(const vector<Function *> &functions) {
    ReadWriteViolationCoverToInstructionsMap readWriteViolationCoverToInstructions;
    mutex readWriteViolationCoverToInstructionsMutex, privateVarMutex;

    ThreadPool threadPool(hardware_concurrency(ThreadCount));
    for (const auto *function : functions) {
        if (GlobalCtx.shouldSkipFunction(function))
            continue;

        threadPool.async(&ViolationFinder::findPotentialRulesIndividual, this, function, &readWriteViolationCoverToInstructions, &readWriteViolationCoverToInstructionsMutex, &privateVarMutex);
    }
    threadPool.wait();

    for (const auto& [field, preferences] : fieldLockPreference) {
        if (preferences.empty())
            continue;

#if 0
        OP << "Entry:\n";
        field->dump(LOG_INFO);
        for (const auto& preference : preferences)
            preference->dump(LOG_INFO);
#endif

        auto fieldCoverageDataIt = fieldCoverageData.find(field);
        if (fieldCoverageDataIt == fieldCoverageData.end())
            continue;

        auto& set = fieldCoverageDataIt->second.lockCovers;
        auto setIt = set.begin();
        while (setIt != set.end()) {
            if (preferences.find(setIt->first.field) == preferences.end())
                setIt = set.erase(setIt);
            else
                ++setIt;
        }
    }

#if 0
    // TODO
    for (const auto& F : M) {
        if (GlobalCtx.shouldSkipFunction(&F))
            continue;
        // TODO: skip non-unified functions
        //unordered_set<Field, FieldHash> handledFields;
        for (const auto& instruction : instructions(F)) {
            if (isa<StoreInst>(&instruction) || isa<CallInst>(&instruction)) {
                SmallVector<const Value *, 1> operands;
                getPotentialFieldOperandPointersFromInstruction(instruction, operands, IgnoreVolatile);

                unordered_set<Field, FieldHash> handledFields;
                for (const auto* operand : operands) {
                    FieldSourceSet sourceSet;
                    set<const Value*> trackedSet;
                    findFields(M, operand, sourceSet, trackedSet, true);

                    for (auto source : sourceSet) {
                        shared_ptr<Field> field = source;
                        if (handledFields.insert(field->last()).second) {
                            if (field->getName().equals("adv_instance_cnt")) {
                                OP << "DEBUG3: " << F.getName() << "\n";
                                field->dump(LOG_INFO);
                                instruction.dump();
                            }

                            auto &result = storeCounter[field->last()];
                            if (result < 254) ++result;
                        }
                    }
                }
            }
        }
    }
#endif

    if (FilterLikelyConcurrencySafeFunctions) {
        for (const auto &[function, lockedCount]: sinkFunctionCallLockedCount) {
            auto totalIt = GlobalCtx.Callers.find(function);
            if (totalIt == GlobalCtx.Callers.end())
                continue;

            auto total = totalIt->second.size();
            auto ratio = ratioFrom(lockedCount, total - lockedCount);
#if 0
            OP << function->getName() << " => " << format("%.2f", ratio * 100.0f) << "%, " << lockedCount << "L | "
               << total - lockedCount << "U\n";
#endif
            if (ratio >= 0.5f /* TODO */) {
                concurrencySafeFunctionSinks.insert(function);
            }
        }
#if 0
        for (const auto &F: M) {
            if (GlobalCtx.UnifiedFuncSet.find(const_cast<Function *>(&F)) != GlobalCtx.UnifiedFuncSet.end()
                && allocFunctions.find(&F) == allocFunctions.end()
                && freeFunctions.find(&F) == freeFunctions.end()
                && sinkFunctionCallLockedCount.find(&F) == sinkFunctionCallLockedCount.end()) {
                concurrencySafeFunctionSinks.insert(&F);
            }
        }
#endif
        sinkFunctionCallLockedCount.clear();
#if 0
        for (const auto* concurrencySafeFunctionSink : concurrencySafeFunctionSinks) {
            OP << "concurrencySafeFunctionSink: " << concurrencySafeFunctionSink->getName() << "\n";
        }
#endif

        // TODO: move me
        if (RequireFieldToBeStoredOrUnsafeUsedInACallUnderALock) {
            for (auto &[field, calls]: writtenToOrEscapedFieldsDeferredCalls) {
                auto allAreSafe = all_of(calls.begin(), calls.end(), [this](const CallInst *call) {
                    if (auto calleesIt = getCalleeIteratorForPotentialCallInstruction(GlobalCtx,
                                                                                      *call); calleesIt.has_value()) {
                        auto &it = calleesIt.value()->second;
                        // All targets of this call are safe
                        return all_of(it.begin(), it.end(), [this](const Function *target) {
                            return concurrencySafeFunctionSinks.find(target) != concurrencySafeFunctionSinks.end();
                        });
                    }
                    return false;
                });

                if (!allAreSafe) {
                    // TODO
                    writtenToOrEscapedFields.insert(field);
                }
            }
        }
        writtenToOrEscapedFieldsDeferredCalls.clear();
    }

    if (FindReadOnlyWriteViolations) {
        LOG(LOG_INFO, "=============== Read-Write bugs ================\n");
        for (const auto&[cover, listOfViolations]: readWriteViolationCoverToInstructions) {
            LOG(LOG_INFO, "Found a potential violation of writing to a read-only-protected structure\n");
            LOG(LOG_INFO, "\tProtected by a read lock ");
            cover.field->dump(LOG_INFO);
            LOG(LOG_INFO, "\t\tAcquired here: ");
            getSourceLocationMemoized(cover.originLockCall).dump(LOG_INFO);
            LOG(LOG_INFO, "\n");

            for (const auto&[instruction, field]: listOfViolations) {
                LOG(LOG_INFO, "\tViolation field: ");
                field->dump(LOG_INFO);
                LOG(LOG_INFO, "\t\tViolated here: ");
                getSourceLocationMemoized(instruction).dump(LOG_INFO);
                LOG(LOG_INFO, "\n");
            }
        }
    }
}

void ViolationFinder::dumpStoreAndCallsTest(const vector<Function *> &functions) const {
    for (const auto *FPtr : functions) {
		const auto &F = *FPtr;
        if (!F.getName().contains("btrfs_free_block_groups"/*"hci_alloc_dev"*/)) continue;

        for (const auto& I : instructions(F)) {
            if (isa<StoreInst>(&I) || isa<CallInst>(&I)) {
                SmallVector<const Value *, 1> operands;
                getPotentialFieldOperandPointersFromInstruction(I, operands, IgnoreVolatile);

                for (const auto* operand : operands) {
                    operand->dump();
                    FieldSourceSet sourceSet;
                    set<const Value*> trackedSet;
                    findFields(*F.getParent(), operand, sourceSet, trackedSet, false);

                    for (const auto& source : sourceSet) {
                        source.fieldPtr()->dump(LOG_INFO);
                    }
                }
            }
        }

        LOG(LOG_INFO, "----------------------------------------\n");
        F.dump();
    }

    exit(1);
}

void ViolationFinder::findViolations(const vector<Function *> &functions) {
    LOG(LOG_INFO, "Calculating potential rules\n");
    findPotentialRules(functions);

    LOG(LOG_INFO, "Calculating violations in functions\n");

    ThreadPool threadPool(hardware_concurrency(ThreadCount));
    for (const auto* function: functions) {
        if (GlobalCtx.shouldSkipFunction(function))
            continue;

        threadPool.async(&ViolationFinder::findViolationsInFunction, this, function);
    }
    threadPool.wait();

#ifdef COUNT_HOW_MANY_TIMES_FP_RECHECK_IS_DETECTED
    LOG(LOG_INFO, "fp:recheck is detected: " << functionsWithFpRecheck.size() << " times\n");
#endif
}

//#define SHOW_INSTRUCTION_LABEL

#ifdef SHOW_INSTRUCTION_LABEL
static string_view getLabelOfInstruction(const Instruction& instruction) {
    if (isa<CallInst>(instruction)) return "[C]";
    if (isa<StoreInst>(instruction)) return "[S]";
    if (isa<LoadInst>(instruction)) return "[L]";
    return "[?]";
}
#endif

static void printPaths(raw_string_ostream& output, const vector<const Instruction*>& instructions) {
    output << "\t\t";
    for (int i = (int) instructions.size() - 1; i >= 0; --i) {
        auto instruction = instructions[i];
        auto& sourceLocation = getSourceLocationMemoized(instruction);
        sourceLocation.dumpToStringStream(output);

#ifdef SHOW_INSTRUCTION_LABEL
        if (i == 0) {
            output << ' ' << getLabelOfInstruction(*instruction);
        }
#endif

        output << " in " << instruction->getFunction()->getName();
        if (i > 0) {
            output << " => ";
        } else {
            // Show git blame information if requested and if we have the source code location.
            if (!GitBlameRepoPath.empty() && sourceLocation.isValid()) {
                output << "\n\t\t\t>>>> ";
                if (auto text = gitBlame(GitBlameRepoPath, sourceLocation.SCheckFileName,
                                         sourceLocation.SCheckLineNo); text.has_value()) {
                    output << text.value();
                } else {
                    output << "Git blame failed!";
                }
            }
        }
    }
    output << '\n';
}

optional<float> ViolationFinder::earlyRejectField(
        unsigned long uncoveredCount,
        const shared_ptr<Field>& field,
        const LockCovers* lockCovers) const {
    auto& last = field->last();
#if 0
    if (auto it = storeCounter.find(last); it != storeCounter.end()) {
        if (it->second == 1) {
            OP << "Skip: ";
            field->dump(LOG_INFO);
            return {};
        }
    }
#endif
    bool accept = !RequireFieldToBeStoredOrUnsafeUsedInACallUnderALock
                  || writtenToOrEscapedFields.find(field->last()) != writtenToOrEscapedFields.end()
                  || mustBeliefFields.find(field) != mustBeliefFields.end()
                  || (last.typePtr()->isStructTy() && last.offset < last.typePtr()->getStructNumElements() && last.typePtr()->getStructElementType(last.offset)->isStructTy());

    if (!accept) {
        LOG(LOG_VERBOSE, "Not accepted: ");
        field->dump(LOG_VERBOSE);
        return {};
    } else {
/*        LOG(LOG_INFO, "Accepted: ");
        field->dump(LOG_INFO);
        LOG(LOG_INFO, "\t" << (int)(writtenToOrEscapedFields.find(field->last()) != writtenToOrEscapedFields.end()) << "," << (int)(mustBeliefFields.find(field) != mustBeliefFields.end()) << ", " << (int)(last.typePtr()->isStructTy() && last.offset < last.typePtr()->getStructNumElements() && last.typePtr()->getStructElementType(last.offset)->isStructTy()) << "\n");
   */ }

    // For each field, get the maximum amount of occurrences of that field
    auto [_, coveredCount] = getMaxLockCoverCoveredCount(*lockCovers);

    float fraction = ratioFrom(coveredCount, uncoveredCount);
    if (fraction >= LockChecksLowerThreshold && fraction <= LockChecksThreshold) {
        return fraction;
    } else {
        return {};
    }
}

#define OUTPUT_FIELD_FUNCTION_TEST_LINES

void ViolationFinder::showFieldBugsIndividual(mutex* outputMutex,
                                              unsigned long uncoveredCount,
                                              const shared_ptr<Field>& field,
                                              const LockCovers* lockCovers) const {
    auto fractionOptional = earlyRejectField(uncoveredCount, field, lockCovers);
    if (!fractionOptional.has_value())
        return;

    bool debug = false; //(field->getName().equals("priv") && field->last().offset == 29) || (field->last().getName().equals("pending_tx_pkts") && field->last().offset == 38);

    auto lastLockField = findCoreLock(getMaxLockCoverCoveredCount(*lockCovers).first->field);
    auto lastLockType = field->typePtr();

    bool sourceCanComeFromConcurrency = false;
    if (FilterContext) {
        auto fieldContexts = fieldToContextsSet.find(field);
        if (fieldContexts != fieldToContextsSet.end()) {
#ifdef OUTPUT_FIELD_FUNCTION_TEST_LINES
            if (debug) {
                OP << "DEBUG1\n";
                field->dump(LOG_INFO);
            }
#endif

            /*for (const auto& interfaceCall : fieldContexts->second.interfaces) {
                auto& sourceData = interfaceSourceToLockUnlockCounts.find(interfaceCall)->second;
                auto sourceDataIt = sourceData.find(lastLockField);
                if (sourceDataIt != sourceData.end() && sourceDataIt->second.locked / sourceDataIt->second.lockedCount <= sourceDataIt->second.unlocked / sourceDataIt->second.unlockedCount) {
                    OP << "Interface call:\n";
                    interfaceCall.dump(LOG_INFO);
                    sourceCanComeFromConcurrency = true;
                    goto done;
                }
            }*/

            for (const auto& functionSource : fieldContexts->second.functions) {
                auto& sourceData = functionSourceToLockUnlockCounts.find(functionSource)->second;
                auto sourceDataIt = sourceData.find(lastLockType);
#ifdef OUTPUT_FIELD_FUNCTION_TEST_LINES
                if(debug && sourceDataIt != sourceData.end()){
                    OP << "TEST: "
                       #ifdef DEBUG_KEEP_HAS_TO_FUNC_NAME
                       << hashToFunction.find(functionSource)->second->getName()
                       #endif
                       << " | " << sourceDataIt->second.locked / sourceDataIt->second.lockedCount << ", " << sourceDataIt->second.unlocked / sourceDataIt->second.unlockedCount << "\n";
                }
#endif
                if (sourceDataIt != sourceData.end() && sourceDataIt->second.locked / sourceDataIt->second.lockedCount <= sourceDataIt->second.unlocked / sourceDataIt->second.unlockedCount) {
                    sourceCanComeFromConcurrency = true;
                    goto done;
                }
            }

            for (const auto* valueSource : fieldContexts->second.values) {
                if (auto arg = dyn_cast<Argument>(valueSource)) {
                    auto itt = mustBeliefFunctions.find(field);
                    if (itt != mustBeliefFunctions.end()) {
                        sourceCanComeFromConcurrency = itt->second.count(arg->getParent()) > 0;
                        if (debug && sourceCanComeFromConcurrency) {
                            LOG(LOG_INFO, "Accept anyway: ");
                            field->dump(LOG_INFO);
                        }
                        if (sourceCanComeFromConcurrency)
                            goto done;
                    }

                    if (valueSource->getType() != field->typePtr()->getPointerTo()) {
                        continue;
                    }
                }

                auto& sourceData = valueSourceToLockUnlockCounts.find(valueSource)->second;
                auto sourceDataIt = sourceData.find(lastLockType);
                if (sourceDataIt != sourceData.end() && sourceDataIt->second.locked / sourceDataIt->second.lockedCount <= sourceDataIt->second.unlocked / sourceDataIt->second.unlockedCount) {
                    if (debug) {
                        field->dump(LOG_INFO);
                        valueSource->dump();
                        if (auto arg = dyn_cast<Argument>(valueSource)) {
                            OP << "DEBUG2STUFF: " << arg->getParent()->getName() << "\n";
                        }
                    }

                    sourceCanComeFromConcurrency = true;
                    goto done;
                }
            }
        }

        done:;
    } else {
		sourceCanComeFromConcurrency = true;
	}

    if (!sourceCanComeFromConcurrency) {
        return;
    }

    auto& paths = fieldCoverageData.find(field)->second.paths;
    /*if (paths.empty())
        return;*/

    string outputString;
    raw_string_ostream output(outputString);
    field->dumpToStringStream(output);
    for (const auto& [cover, _]: *lockCovers) {
        output << "\tCover: ";
        cover.field->dumpToStringStream(output);
#if 0
        output << "\tCore lock: ";
        findCoreLock(cover.field)->dumpToStringStream(output);
#endif
        output << "\tCovered in: " << cover.originLockCall->getFunction()->getName() << "\n";
        //if (cover.originLockCall->getFunction()->getName().equals("caching_thread")) {
        //    SourceLocation tmp(cover.originLockCall);
        //    tmp.dump(LOG_INFO);
        //}
    }

    output << "\tUncovered times: " << uncoveredCount
           << " (score " << format("%.2f", fractionOptional.value() * 100.0f) << "%), source paths contributing:\n";
    unsigned int outputted = 0;
#ifdef PRINT_SYSCALL_IF_THERE_ARE
    set<const Function*> allSyscallReachables;
#endif

    // Reset the output counter when a different violating function is found.
    // The reason is that sometimes violations of no interest can be outputted, and this hides the violations
    // that are actually interesting. An example of such a case happens when a violation is reported where a violation
    // both happens in an init function and another function. But the init function has more callers than the print
    // limit, therefore burying the actual violation deep.
    const Function* lastFoundInFunction = nullptr;

    for (const auto& instructions: paths) {
        auto foundInFunction = instructions[0]->getFunction();

#ifdef TRACK_WHICH_FUNCTIONS_CONTAIN_VIOLATIONS
        if (!lastFoundInFunction) {
            const_cast<ViolationFinder *>(this)->trackWhichFunctionsContainViolationsMutex.lock();
            const_cast<ViolationFinder *>(this)->trackWhichFunctionsContainViolations.insert(field->typePtr());
            const_cast<ViolationFinder *>(this)->trackWhichFunctionsContainViolationsMutex.unlock();
        }
#endif

        if (lastFoundInFunction != foundInFunction) {
            if (lastFoundInFunction) {
                output << "\t\t...\n";
                outputted = 0;
            }
            lastFoundInFunction = foundInFunction;
        }

        if (++outputted <= PathsPrintLimit)
            printPaths(output, instructions);

#ifdef PRINT_SYSCALL_IF_THERE_ARE
        if (auto it = functionToSyscall.find(foundInFunction); it != functionToSyscall.end()) {
            allSyscallReachables.insert(it->second.begin(), it->second.end());
        }
#endif
    }
#ifdef PRINT_SYSCALL_IF_THERE_ARE
    if (!allSyscallReachables.empty()) {
        output << "Reachable via syscalls:\n";
        for (const auto& syscall : allSyscallReachables) {
            output << "\t" << syscall->getName() << "\n";
        }
    } else {
        output << "Unlikely to be reachable from a syscall\n";
    }
#endif

    outputMutex->lock();
    OP << output.str();
    outputMutex->unlock();
}

void ViolationFinder::findAssertionBugsIndividual(const CallInst* callInst, ViolationPathMap* violationPaths,
                                                  mutex* insertMutex) const {
    if (callInst->arg_size() != 1)
        return;
    auto lockVariable = callInst->getArgOperand(0);
    FieldSourceSet sources;
    set<const Value*> visited;

    bool debug = false; //callInst->getFunction()->getName().equals("ath10k_htt_rx_in_ord_ind");

    findFields(*callInst->getModule(), lockVariable, sources, visited, false);
    for (const auto& source: sources) {
        auto field = source.fieldPtr();

        // Single wrapping type, ignore this since it just wraps a primitive lock.
        if (isWrappingType(field->last().typePtr()))
            continue;

        if (debug) {
            LOG(LOG_INFO, "Lock expected: ");
            field->dump(LOG_INFO);
        }

        vector<const Instruction*> path{callInst};
        set<const Function*> visitedFunctions;
        if (!interproceduralFieldCoverCheck(field, lockCoverageMap, callInst->getParent(),
                                            LockInterproceduralDepth,
                                            [&](const BasicBlock* discoveredViaBB, vector<const Instruction*>&& v) {
                                                // Need to remember path for output
                                                lock_guard _(*insertMutex);
                                                (*violationPaths)[field].emplace_back(move(v));
                                            }, isThereALockCoverAlike, move(path), visitedFunctions)) {
            if (debug) {
                LOG(LOG_INFO, "Found uncovered path for: ");
                field->dump(LOG_INFO);
            }
        }
    }
}

void ViolationFinder::showAssertionBugsIndividual(const shared_ptr<Field>* field,
                                                  const vector<vector<const Instruction*>>* violationPaths,
                                                  mutex* outputMutex) {
    string outputString;
    raw_string_ostream output(outputString);

    (*field)->dumpToStringStream(output);
    output << "\tThere are uncovered paths, but expected to be covered:\n";
    for (const auto& instructions: *violationPaths) {
        printPaths(output, instructions);
    }

    outputMutex->lock();
    LOG(LOG_INFO, output.str());
    outputMutex->unlock();
}

void ViolationFinder::showAssertionBugs(const vector<Function *> &functions) const {
    // Maps lock -> path where the lock should be held but is not held.
    ViolationPathMap violationPaths;

    ThreadPool threadPool(hardware_concurrency(ThreadCount));

    mutex insertMutex;
    for (const auto& assertionFunction: lockCheckerPassData.lockAssertFunctions) {
        if (auto it = GlobalCtx.Callers.find(assertionFunction); it != GlobalCtx.Callers.end()) {
            for (const auto* caller: it->second) {
                threadPool.async(&ViolationFinder::findAssertionBugsIndividual, this, caller,
                                 &violationPaths, &insertMutex);
            }
        }
    }
    threadPool.wait();

    mutex outputMutex;
    for (const auto&[field, paths]: violationPaths) {
        threadPool.async(&ViolationFinder::showAssertionBugsIndividual, &field, &paths, &outputMutex);
    }
    threadPool.wait();
}

void ViolationFinder::deriveContextsIndividual(mutex* mutex, LazyOperandTracker* tracker) {
    // Account for critical sources
    for (const auto& entry : tracker->entries) {
/*        if (entry.field->typePtr()->getStructName().contains("ieee80211_hw") && entry.field->last().offset == 32 && entry.unlocked) {
            OP << "GVD\n";
        } else {
            continue;
        }*/
        set<Value*> trackedSet;
        vector<ValueWithIndirections> cvSet;
        lockCheckerPassData.DFA.findObjectCriticalSourcesAndIndirections(const_cast<Value *>(entry.operand), cvSet,
                                                                         trackedSet, LockInterproceduralDepth);

        mutex->lock();
        if (entry.addSet) {
            auto lockCover = getMaxLockCoverCoveredCount(fieldCoverageData.find(entry.field)->second.lockCovers).first;
            accountCriticalSourcesLockUnlockCounts(cvSet, entry.field, entry.unlocked, entry.operand, findCoreLock(lockCover->field));
        }

        if (entry.mustBelief) {
            for (const auto& cvSetEntry : cvSet) {
                if (cvSetEntry.type == ValueWithIndirections::ValueType::Value)
                    if (auto I = dyn_cast<Instruction>(cvSetEntry.value))
                        mustBeliefFunctions[entry.field].insert(I->getFunction());
            }
        }
        mutex->unlock();
    }
}

void ViolationFinder::deriveContexts() {
    set<const Type*> importantTypes;
    for (const auto&[field, data]: fieldCoverageData) {
        if (!data.notLockedCounter.empty()
            && earlyRejectField(data.notLockedCounter.size(), field, &data.lockCovers).has_value()) {
            importantTypes.insert(field->typePtr());
        }
    }

    ThreadPool threadPool(hardware_concurrency(ThreadCount));
    mutex mutex;

    for (const auto* type : importantTypes) {
        auto lazyOperandTrackingIt = lazyOperandTracking.find(type);
        if (lazyOperandTrackingIt == lazyOperandTracking.end()) continue;
        threadPool.async(&ViolationFinder::deriveContextsIndividual, this, &mutex, &lazyOperandTrackingIt->second);
    }

    threadPool.wait();

    // Free up memory that is no longer necessary
    lazyOperandTracking.clear();
}

void ViolationFinder::showFieldBugs() const {
    ThreadPool threadPool(hardware_concurrency(ThreadCount));
    mutex outputMutex;

    for (const auto&[field, data]: fieldCoverageData) {
        auto uncoveredCount = data.notLockedCounter.size();
        if (uncoveredCount == 0) continue;
        threadPool.async(&ViolationFinder::showFieldBugsIndividual, this, &outputMutex, uncoveredCount,
			field,  &data.lockCovers);
    }

    threadPool.wait();

#ifdef TRACK_WHICH_FUNCTIONS_CONTAIN_VIOLATIONS
    LOG(LOG_INFO, "Amount of unique functions with violations: " << trackWhichFunctionsContainViolations.size() << "\n");
#endif
}

void ViolationFinder::showLockingRules() const {
    // Debug: show which fields are locked by which cover
    for (const auto&[field, data]: fieldCoverageData) {
        auto& lockCovers = data.lockCovers;
        if (lockCovers.empty())
            continue;
        field->dump(LOG_INFO);
        LOG(LOG_INFO, "\tLocked by:\n");
        for (const auto& [cover, _]: lockCovers) {
            LOG(LOG_INFO, "\t\t");
            cover.field->dump(LOG_INFO);
#if 0
            //LOG(LOG_INFO, "found here: " << cover.originLockCall->getFunction()->getName() << "\n");
            //cover.originLockCall->dump();
            SourceLocation tmp(cover.originLockCall);
            tmp.dump(LOG_INFO);
#endif
            LOG(LOG_INFO, "\t\tIn: " << cover.originLockCall->getFunction()->getName() << "\n");
        }
    }
    for (const auto&[field, data]: fieldCoverageData) {
        auto& notLockedCounter = data.notLockedCounter;
        field->dump(LOG_INFO);
        LOG(LOG_INFO, "\tNot locked " << notLockedCounter.size() << " times\n");
        for (const auto& value: notLockedCounter) {
            if (auto instruction = dyn_cast<Instruction>(value))
                LOG(LOG_INFO, "\t\tHere: " << instruction->getFunction()->getName() << "\n");
        }
    }
}

template<typename T, typename C>
bool
ViolationFinder::interproceduralFieldCoverCheck(const shared_ptr<Field>& field, const LockCoverageMap& lockCoverage,
                                                const BasicBlock* BB, int depthLeft, const T& callback,
                                                const C& checker,
                                                vector<const Instruction*> path, set<const Function*>& visited) const {
#if 1
    // Function belongs to initialization section.
    auto BBFunction = BB->getParent();
    if (BBFunction->hasSection()) {
        auto section = BBFunction->getSection();
        if (section.contains("init") || section.contains("exit"))
            return true;
    }
#endif

    bool debug = false; //field->getName().equals("accept_list");

    auto function = BB->getParent();
    visited.emplace(function);

    if (depthLeft <= 0) {
        callback(BB, move(path));
        return false;
    }

    auto handleNoCallers = [&] {
        if (depthLeft == LockInterproceduralDepth && !function->getName().equals("main")) {
            return true;
        } else {
            callback(BB, move(path));
            return false;
        }
    };

    bool okay = true;
    auto calleeIt = GlobalCtx.Callers.find(const_cast<Function*>(function));
    if (calleeIt == GlobalCtx.Callers.end())
        return handleNoCallers();
    auto& set = calleeIt->second;
    if (set.empty())
        return handleNoCallers();
    if (set.size() > 100)
        return false;
    for (const auto* caller: set) {
        auto basicBlockOfCaller = caller->getParent();

        if (visited.find(basicBlockOfCaller->getParent()) != visited.end()) {
            if (debug) {
                LOG(LOG_INFO, "Already visited " << basicBlockOfCaller->getParent()->getName() << "\n");
            }
            continue;
        }

        if (debug) {
            LOG(LOG_INFO, "Found caller to " << function->getName() << " from " << basicBlockOfCaller->getParent()->getName() << "\n");
        }

        if (!checker(field, lockCoverage, fieldCoverageData, basicBlockOfCaller)) {
            if (debug) {
                LOG(LOG_INFO, "Checker failed on caller " << basicBlockOfCaller->getParent()->getName() << "\n");
            }
            // Recursion on callers
            decltype(path) recursePath(path);
            recursePath.push_back(caller);
            if (!interproceduralFieldCoverCheck(field, lockCoverage, basicBlockOfCaller, depthLeft - 1,
                                                callback, checker, move(recursePath), visited)) {
                if (debug) {
                    LOG(LOG_INFO, "Set okay to false from caller " << basicBlockOfCaller->getParent()->getName() << "\n");
                }
                okay = false;
            }
        } else {
            if (debug) {
                LOG(LOG_INFO, "Checker succeeded on caller " << basicBlockOfCaller->getParent()->getName() << "\n");
            }
        }
    }

    //LOG(LOG_VERBOSE, "Okay for " << BB->getParent()->getName() << ": " << okay << "\n");

    return okay;
}
