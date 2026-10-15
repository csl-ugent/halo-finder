#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Analysis/PostDominators.h>

#include "LockChecker.h"
#include "ViolationFinder.h"
#include "Common.h"
#include "Config.h"
#include "ClOptForward.h"
#include "WrapperFinder.h"
#include "DebugHelpers.h"


LockCheckerPassData::LockCheckerPassData(const LockCheckerPass& lockCheckerPass)
        : DFA(*const_cast<DataFlowAnalysis*>(&lockCheckerPass.DFA)),
          lockTypes(lockCheckerPass.lockTypes),
          lockAssertFunctions(lockCheckerPass.lockAssertFunctions),
          lockers(lockCheckerPass.lockers), unlockers(lockCheckerPass.unlockers),
          storeTaintData(lockCheckerPass.storeTaintData),
          lockFields(lockCheckerPass.LockFields) {
}


static ifstream ifstreamFor(const string& file) {
    string exepath = sys::fs::getMainExecutable(nullptr, nullptr);
    string exedir = exepath.substr(0, exepath.find_last_of('/'));
    ifstream stream(exedir + "/" + ConfigPath + "/" + file);
    return stream;
}

template<typename T>
static void loadFunctions(const string& file, const T& cb) {
    string line;
    auto stream = ifstreamFor(file);
    if (stream.is_open()) {
        while (!stream.eof()) {
            getline(stream, line);
            if (line.length() > 1) {
                cb(line);
            }
        }
    }
}

static void loadFunctionsWithCallback(const Module& M, const string& file,
                                      const function<void(const Function&, optional<string_view>)>& callback,
                                      bool allowFunctionsWithoutArgument) {
    loadFunctions(file, [&](const string_view& data) {
        //LOG(LOG_INFO, "data: " << data << "\n");
        auto tabIndex = data.find('\t');
        optional<string_view> additionalData;
        string_view name = data;
        if (tabIndex != string_view::npos) {
            additionalData = data.substr(tabIndex + 1);
            //LOG(LOG_INFO, "Additional data found: '" << additionalData.value() << "'\n");
            name = data.substr(0, tabIndex);
        }
        auto nameLength = name.size();

        bool inserted = false;
        for (const auto& func: M) {
            if (!allowFunctionsWithoutArgument && func.getFunctionType()->getNumParams() == 0)
                continue;
            //if (GlobalCtx.UnifiedFuncSet.find(const_cast<Function*>(&func)) == GlobalCtx.UnifiedFuncSet.end())
            //    continue;

            auto functionName = func.getName();
            // Necessary because of the variants, e.g. __raw_spin_unlock.111335
            if (functionName.startswith(name) && (functionName.size() == nameLength || (functionName.size() > nameLength && functionName[nameLength] == '.'))) {
                callback(func, additionalData);
                inserted = true;
            }
        }

        if (!inserted)
            LOG(LOG_VERBOSE, "Warning: function '" << name << "' not found\n");
    });
}

static void
loadFunctionsIntoMap(const Module& M, const string& file, unordered_map<const Function*, LockUnlockerData>& map, unordered_set<const Type*>& lockTypes) {
    loadFunctionsWithCallback(M, file, [&](const Function& func, optional<string_view> additionalData) {
        auto lockAcquisitionStyle = LockAcquisitionStyle::Unconditional;
        auto lockAccessStyle = LockAccessStyle::ReadWrite;
        if (additionalData.has_value()) {
            auto& additionalDataValue = additionalData.value();
            auto splitIndex = additionalDataValue.find(',');
            if (splitIndex != string_view::npos) {
                auto lockAcquisitionStyleStr = additionalData->substr(0, splitIndex);
                auto lockAccessStyleStr = additionalData->substr(splitIndex + 1);
#if 0
                LOG(LOG_INFO, "lockAcquisitionStyleStr: " << lockAcquisitionStyleStr << "\n");
                LOG(LOG_INFO, "lockAccessStyle: " << lockAccessStyleStr << "\n");
#endif

                if (lockAcquisitionStyleStr == "conditional")
                    lockAcquisitionStyle = LockAcquisitionStyle::Conditional;
                else if (lockAcquisitionStyleStr == "unconditional")
                    lockAcquisitionStyle = LockAcquisitionStyle::Unconditional;
                else
                    LOG(LOG_INFO, "Unknown lock acquisition data type: " << lockAcquisitionStyleStr << '\n');

                if (lockAccessStyleStr == "rw")
                    lockAccessStyle = LockAccessStyle::ReadWrite;
                else if (lockAccessStyleStr == "ro")
                    lockAccessStyle = LockAccessStyle::ReadOnly;
                else
                    LOG(LOG_INFO, "Unknown lock access data type: " << lockAccessStyleStr << '\n');
            } else {
                LOG(LOG_INFO, "Missing information about access style: " << additionalDataValue << '\n');
            }
        }
        LockUnlockerData data(lockAcquisitionStyle, lockAccessStyle, 0);
        data.addEntry(nullptr, 0);
        map.insert({&func, move(data)});

        auto functionType = func.getFunctionType();
        if (functionType->getNumParams() == 1) {
            lockTypes.insert(functionType->getParamType(0));
        }
    }, false);
}

bool LockCheckerPass::doInitialization(Module* M) {
    LOG(LOG_INFO, "Reading function lists\n");
    loadFunctionsIntoMap(*M, "lock-funcs", lockers, lockTypes);
    loadFunctionsIntoMap(*M, "unlock-funcs", unlockers, lockTypes);
    loadTransformers(*M);
    loadSimpleFunctionLists(*M);
    return false;
}

bool LockCheckerPass::doFinalization(Module* M) {
    return false;
}

bool LockCheckerPass::isFunctionALocker(const Function& function) const {
    return lockers.find(&function) != lockers.end();
}

bool LockCheckerPass::isFunctionAnUnLocker(const Function& function) const {
    return unlockers.find(&function) != unlockers.end();
}

void LockCheckerPass::handleFunctionForLockAndUnLockFields(Function& function) {
    bool debug = false; //function.getName().equals("batadv_tt_local_resize_to_mtu"); //function.getName().equals("task_lock");

    for (auto& instruction: instructions(function)) {
        if (auto callInst = dyn_cast<CallInst>(&instruction)) {
            // First, no operands may mean that it's a wrapper that uses a global variable spinlock
            // Second, even with a single operand, it's possible that it is NOT a lock (but for example a stored flags variable) and that the wrapper uses a global variable just like the previous case
            if (callInst->arg_size() == 0)
                continue;

            // A call instruction, record which fields are locks and unlocks
            for (const auto* calledFunction: Ctx->Callees[callInst]) {
                if (debug) {
                    callInst->dump();
                    LOG(LOG_INFO, "called function: " << calledFunction->getName() << "\n");
                }
                bool isLocker = isFunctionALocker(*calledFunction);
                bool isUnLocker = isFunctionAnUnLocker(*calledFunction);
                if (isLocker || isUnLocker) {
                    if (debug) LOG(LOG_INFO, "is locker: " << isLocker << ", is unlocker: " << isUnLocker << "\n");

                    if (isLocker &&
                        lockers.find(&function) == lockers.end()) { // Contains a locker but isn't itself a locker
                        // Validate whether a fallible lock has its return value checked.
                        auto &lockUnlockerData = lockers.find(calledFunction)->second;
                        if (lockUnlockerData.lockAcquisitionStyle == LockAcquisitionStyle::Conditional) {
                            if (!any_of(callInst->user_begin(), callInst->user_end(), [](const User *user) {
                                // Phi node stops the analysis because no deep data flow analysis here.
                                // Return instruction simply means the error is passed to the callers.
                                return isa<CmpInst>(user) || isa<PHINode>(user) || isa<ReturnInst>(user) ||
                                       isa<StoreInst>(user);
                            })) {
                                LOG(LOG_INFO, "Potential missing check on fallible lock: ");
                                SourceLocation sourceLocation(callInst);
                                sourceLocation.dump(LOG_INFO);
                                LOG(LOG_INFO, "\n");
                            }
                        }
                    }

                    auto &calledFunctionFieldData = isLocker ? lockers[calledFunction] : unlockers[calledFunction];

                    for (const auto &calledFunctionFieldDataEntry: calledFunctionFieldData.entries) {
                        auto calledFieldArgumentIndex = calledFunctionFieldDataEntry.index;
                        auto lockVariable = callInst->getArgOperand(calledFieldArgumentIndex);

                        auto handleFieldCandidate = [&](const shared_ptr <Field> &fieldCandidate) {
#ifdef TEST_CASE_FIND_LOCK_FIELDS
                            fieldCandidate.dump(LOG_INFO);
#endif

                            auto insertInto = [&](decltype(LockFields) & map) {
                            map[fieldCandidate].sources.push_back(callInst);
                        };

                            if (isLocker) insertInto(LockFields);
                            else if (isUnLocker) insertInto(UnLockFields);
                        };

                        FieldSourceSet sources;
                        set<const Value *> visited;
                        findFields(*instruction.getModule(), lockVariable, sources, visited, false);

                        if (debug) {
                            LOG(LOG_INFO, "Field dump:\n");
                            for (const auto& fieldCandidate : sources) {
                                fieldCandidate.fieldPtr()->dump(LOG_INFO);
                            }
                            LOG(LOG_INFO, "---\n");
                        }

                        if (sources.empty()) {
                            if (auto& fieldCandidate = calledFunctionFieldDataEntry.field) {
                                handleFieldCandidate(make_shared<Field>(
                                        *fieldCandidate)); // Intentional copy because of the move
                            }
                        } else {
                            for (auto fieldCandidate: sources) {
                                shared_ptr<Field> fieldCopy = fieldCandidate;
                                chainFields(fieldCopy, calledFunctionFieldDataEntry.field);
                                if (debug) {
                                    LOG(LOG_INFO, "  after chaining: ");
                                    fieldCopy->dump(LOG_INFO);
                                }

                                handleFieldCandidate(fieldCopy);
                            }
                        }
                    }
                }
            }
        }
    }
}

void LockCheckerPass::findLockAndUnLockFields(Module* M) {
    for (auto& funcIt: *M) {
        Function* function = &funcIt;
        if (Ctx->shouldSkipFunction(function))
            continue;

        //LOG(LOG_VERBOSE, "Visiting " << function->getName() << "\n");

#ifdef TEST_CASE_FIND_LOCK_FIELDS
        //if (!function->getName().equals("efi_thunk_get_variable"))
        //	continue;
        //if (!function->getName().equals("ext4_mb_use_preallocated"))
        //	continue;
        //if (!function->getName().equals("timerfd_show"))
        //	continue;
        //if (!function->getName().equals("sync_global_pgds_l4"))
        //	continue;
        //if (!function->getName().equals("rpc_timeout_upcall_queue"))
        //	continue;
        if (!function->getName().equals(/*"hci_prepare_suspend"*/"dbs_work_handler"))
            continue;
#endif

        handleFunctionForLockAndUnLockFields(*function);
    }

#if 0
    LOG(LOG_INFO, "Found " << LockFields.size() << " lock fields\n");
    LOG(LOG_INFO, "Found " << UnLockFields.size() << " unlock fields\n");

    LOG(LOG_INFO, "List of lock fields:\n");
    for (const auto& [field, _] : LockFields) {
        field.dump(LOG_INFO);
    }

    if (LockFields.size() != UnLockFields.size()) {
        LOG(LOG_INFO, "Inconsistency: the amount of fields that occur in taking a lock doesn't equal the amount of fields that occur in an unlock!\n");
        LOG(LOG_INFO, "Lock fields not in unlocks:\n");
        for (const auto& [field, _] : LockFields) {
            if (UnLockFields.find(field) == UnLockFields.end()) {
                field.dump(LOG_INFO);
            }
        }
        LOG(LOG_INFO, "Unlock fields not in locks:\n");
        for (const auto& [field, _] : UnLockFields) {
            if (LockFields.find(field) == LockFields.end()) {
                field.dump(LOG_INFO);
            }
        }
    }
#endif

#ifdef DUMP_LOCK_TYPES
    for (const auto& type : lockTypes) {
        LOG(LOG_INFO, "Lock type: ");
        type->dump();
    }

    //exit(1);
#endif
}

bool LockCheckerPass::processLockUnlockFunctionCall(unordered_map<const Function*, LockUnlockerData>& map,
                                                    const CallInst* caller, const Function* function) {
    // caller in callerFunction calls function
    auto callerFunction = caller->getFunction();
    auto chainIt = map.find(function);
    if (chainIt == map.end())
        return false;
    auto& chain = chainIt->second;

    for (const auto& chainEntry : chain.entries) {
        auto fieldArgumentIndex = chainEntry.index;

        // Figure out what field candidate this gives
        if (caller->arg_size() <= fieldArgumentIndex)
            return false;
        auto argumentVariable = caller->getArgOperand(fieldArgumentIndex);

        FieldSourceSet fields;
        set<const Value *> visited;
        findFields(*caller->getModule(), argumentVariable, fields, visited, false);

        // Update lock types
        if (auto argumentType = argumentVariable->getType(); !argumentType->isPointerTy() ||
                                                             !argumentType->getPointerElementType()->isIntegerTy()) {
            for (const auto &field: fields) {
                auto &last = field.fieldPtr()->last();
                if (!last.isGlobal() && last.typePtr()->isStructTy()) {
                    auto structElement = last.typePtr()->getStructElementType(last.offset);
                    if (isWrappingType(structElement)) {
                        lockTypes.insert(structElement->getPointerTo());
                    }
                }
            }
        }

        auto insertEntry = [&](const shared_ptr<Field>& fieldPtr, ArgumentIndex argumentIndex) {
            auto mapIt = map.find(callerFunction);
            if (mapIt == map.end()) {
                mapIt = map.insert({callerFunction, LockUnlockerData(LockAcquisitionStyle::Unconditional,
                                                                     chain.lockAccessStyle, chain.depth + 1)}).first;
            }
            mapIt->second.addEntry(fieldPtr, argumentIndex);
        };

        bool added = false;
        for (const auto &field: fields) {
            if (field.fieldPtr()->isGlobal())
                continue;
            auto callerArgumentIndex = getArgumentIndexForField(GlobalCtx.typeRemapper, field, *callerFunction);
            if (!callerArgumentIndex.has_value()) continue;

            auto fieldPtr = field.fieldPtr();
            chainFields(fieldPtr, chainEntry.field);
            insertEntry(fieldPtr, callerArgumentIndex.value());

#ifdef LOG_ADDING_OF_WRAPPER
            LOG(LOG_INFO,
                "Add transform " << callerFunction->getName() << " " << callerArgumentIndex.value() << "->" << fieldArgumentIndex
                       << ": " << (chain.lockAccessStyle == LockAccessStyle::ReadWrite ? "RW" : "RO") << "\n");
#endif

            added = true;
            break;
        }

        // Try a pass-through
        if (!added) {
            // Chain fields: it'll be the same as what this caller wrapped
            if (auto argument = dyn_cast<Argument>(argumentVariable)) {
                auto callerArgumentIndex = argument->getArgNo();
                insertEntry(chainEntry.field, callerArgumentIndex);
#ifdef LOG_ADDING_OF_WRAPPER
                LOG(LOG_INFO,
                    "Add pass-through " << callerFunction->getName() << " " << callerArgumentIndex << "->" << fieldArgumentIndex
                           << ": " << (chain.lockAccessStyle == LockAccessStyle::ReadWrite ? "RW" : "RO") << "\n");
#endif
            }

#ifdef LOG_ADDING_OF_WRAPPER
            LOG(LOG_INFO, "Cannot add " << callerFunction->getName() << " as the argument index is unknown\n");
#endif
        }

#if 0
        for (const auto& field : fields) {
            field.fieldPtr()->dump(LOG_INFO);
        }
        LOG(LOG_INFO, "---\n");
#endif
    }

    return true;
}

void LockCheckerPass::findLockWrappers() {
    WrapperFinder wrapperFinder(Ctx, lockers, unlockers);
    wrapperFinder.calculate();

    auto processFunctionCallsInCandidates = [&](const set<const Function*>& inputSet, decltype(lockers)& type) {
        stack<const Function*> functionCheckStack;
        for (const auto& [f, _]: type) {
            functionCheckStack.push(f);
        }

        set<const Function*> alreadyProcessedFunctions;
        while (!functionCheckStack.empty()) {
            auto* function = functionCheckStack.top();
            functionCheckStack.pop();

            if (!alreadyProcessedFunctions.insert(function).second)
                continue;

            if (inputSet.find(function) != inputSet.end()) {
                auto& callers = Ctx->Callers[const_cast<Function*>(function)];
                for (const auto &caller: callers) {
                    if (!caller->isIndirectCall()) {
                        if (caller->getFunction() != function && inputSet.find(caller->getFunction()) != inputSet.end()) {
                            //LOG(LOG_INFO, "Adding for " << function->getName() << " from caller in "
                            //                            << caller.call->getFunction()->getName() << ")" << inputSet.count(caller.call->getFunction()) << "\n");
                            if (processLockUnlockFunctionCall(type, caller, function))
                                functionCheckStack.push(caller->getFunction());
                        }
                    }
                }
            }
        }
    };

    processFunctionCallsInCandidates(wrapperFinder.getFunctionsThatEventuallyCallALocker(), lockers);
    processFunctionCallsInCandidates(wrapperFinder.getFunctionsThatEventuallyCallAnUnLocker(), unlockers);
}

void LockCheckerPass::findWrappers() {
    findLockWrappers();

    auto printLockerOrUnlockerInformation = [](const Function* function, const LockUnlockerData& data) {
        LOG(LOG_INFO, "\t" << function->getName() << "\n");
        data.dump(LOG_INFO);
        if (auto diSubprogram = dyn_cast<DISubprogram>(function->getMetadata("dbg"))) {
            LOG(LOG_INFO, "\t\tIn: " << diSubprogram->getFilename() << ":" << diSubprogram->getLine() << "\n");
        }
    };

    (void) printLockerOrUnlockerInformation;

#ifdef DISPLAY_FOUND_WRAPPERS_FOR_LOCKERS
    LOG(LOG_INFO, "List of lockers (" << lockers.size() << "):\n");
    for (const auto& [locker, data] : lockers) {
        printLockerOrUnlockerInformation(locker, data);
    }
#endif

#ifdef DISPLAY_FOUND_WRAPPERS_FOR_UNLOCKERS
    LOG(LOG_INFO, "List of unlockers (" << unlockers.size() << "):\n");
    for (const auto& [unlocker, data] : unlockers) {
        printLockerOrUnlockerInformation(unlocker, data);
    }
#endif
}

struct CompareBasicBlockCoverPair {
    bool operator()(const pair<const BasicBlock*, LockCover>& a, const pair<const BasicBlock*, LockCover>& b) const {
        if (a.first < b.first) return true;
        else if (a.first > b.first) return false;
        return a.second.field->operator<(*b.second.field);
    }
};

static inline bool findBasicBlockCoverageIsDebug(const BasicBlock& BB) {
    return false; //BB.getParent()->getName().equals("batadv_tt_local_resize_to_mtu");
}

using UnlockBarriers = set<pair<const BasicBlock*, LockCover>, CompareBasicBlockCoverPair>;

template<typename Mark, typename HasLockCover>
static void propagateLockCover(const BasicBlock& BB, const LockCover& lockCover, const UnlockBarriers& unlockBarriers,
                               set<const BasicBlock*>& visited, const Mark& mark, const HasLockCover& hasLockCover) {
    if (!visited.insert(&BB).second)
        return;

    if (unlockBarriers.find(make_pair(&BB, lockCover)) != unlockBarriers.end())
        return;

    mark(&BB, lockCover);

    for (const auto& successor: successors(&BB)) {
        propagateLockCover(*successor, lockCover, unlockBarriers, visited, mark, hasLockCover);
    }
}

template<typename Callback>
static void
loopOverAllLockCoversOf(LockCover lockCover, const unordered_set<const Type*>& lockTypes, const Callback& callback) {
    // If we hold a lock on A->B->C then we also hold it on
    // B->C and C. The loop below performs the splitting.
#ifdef SPLIT_LOCKS_INTO_ALL_PARTS
    do {
        callback(lockCover);
        lockCover.field = lockCover.field->next;
    } while (lockCover.field && lockTypes.find(lockCover.field->typePtr()->getPointerTo()) == lockTypes.end());
#else
    callback(lockCover);
#endif
}

void LockCheckerPass::findBasicBlockCoverage(Module* M, LockCoverageMap& lockCoverage) {
    // Split the basic blocks such that locking calls and unlocking calls always are the first instruction of the block.
    // This way we can just mark basic blocks instead of marking individual instructions.
    auto performSplits = [&](decltype(LockFields)& map) {
        for (const auto&[lockField, data]: map) {
            for (auto& source: data.sources) {
                if (findBasicBlockCoverageIsDebug(*source->getParent())) {
                    LOG(LOG_INFO, "In: " << source->getFunction()->getName() << "\n");
                    source->dump();
                    lockField->dump(LOG_INFO);
                }

                source->getParent()->splitBasicBlock(source);
            }
        }
    };
    performSplits(LockFields);
    performSplits(UnLockFields);

    UnlockBarriers unlockBarriers;
    UnlockBarriers alreadyAdded;

    auto insertIntoCoverage = [&lockCoverage, &alreadyAdded](const BasicBlock* BB, const LockCover& lockCover) {
        auto it = lockCoverage.find(BB);
        if (it != lockCoverage.end()) {
            it->second.emplace(lockCover);
        } else {
            lockCoverage.insert({BB, {lockCover}});
        }
        alreadyAdded.emplace(make_pair(BB, lockCover));
    };

    auto hasLockCover = [&lockCoverage](const BasicBlock* BB, const LockCover& lockCover) -> bool {
        auto it = lockCoverage.find(BB);
        if (it == lockCoverage.end())
            return false;
        return it->second.find(lockCover) != it->second.end();
    };

    // Register unlocks as <containing basic block, unlock cover> such that
    // the propagation of lock covers stops at these pairs.
    for (const auto&[lockField, data]: UnLockFields) {
        for (const auto& source: data.sources) {
            auto containingBB = source->getParent();
            LockCover lockCover{.field = lockField, .originLockCall = source, .lockAccessStyle = LockAccessStyle::ReadWrite, .lockAcquisitionStyle = LockAcquisitionStyle::Unconditional};
            loopOverAllLockCoversOf(lockCover, lockTypes, [&](const LockCover& lockCover) {
                unlockBarriers.emplace(make_pair(containingBB, lockCover));
            });
        }
    }

#if 0
    for (const auto& [BB, cover] : unlockBarriers) {
        LOG(LOG_INFO, "Unlock barrier: ");
        BB->dump();
        cover.field->dump(LOG_INFO);
    }
#endif

    // Seeds of the lock covers for propagation.
    for (const auto&[lockField, data]: LockFields) {
        for (const auto& source: data.sources) {
            auto it = getCalleeIteratorForPotentialCallInstruction(*Ctx, *source);
            if (!it.has_value()) continue;

            bool debug = false; //source->getFunction()->getName().equals("mmu_interval_notifier_remove");
            if (debug) {
                LOG(LOG_INFO, "Lock field: ");
                lockField->dump(LOG_INFO);
                for (const auto& target : it.value()->second)
                    LOG(LOG_INFO, "Debug: " << target->getName() << "\n");
                LOG(LOG_INFO, "---\n");
            }

            // If one of the accessors is read-write, mark it as read-write.
            // if one of the accessors is fallible, mark it as fallible.
            auto lockAccessStyle = LockAccessStyle::ReadOnly;
            auto lockAcquisitionStyle = LockAcquisitionStyle::Unconditional;
            for (const auto& callee : it.value()->second) {
                const auto& lockersRef = lockers[callee];
                if (lockersRef.lockAccessStyle == LockAccessStyle::ReadWrite)
                    lockAccessStyle = LockAccessStyle::ReadWrite;
                if (lockersRef.lockAcquisitionStyle == LockAcquisitionStyle::Conditional)
                    lockAcquisitionStyle = LockAcquisitionStyle::Conditional;
            }

            auto containingBB = source->getParent();
            LockCover lockCover{.field = lockField, .originLockCall = source, .lockAccessStyle = lockAccessStyle, .lockAcquisitionStyle = lockAcquisitionStyle};
            loopOverAllLockCoversOf(lockCover, lockTypes, [&](const LockCover& lockCover) {
                set<const BasicBlock*> visited;
                propagateLockCover(*containingBB, lockCover, unlockBarriers, visited, insertIntoCoverage, hasLockCover);
            });
        }
    }

    if (LockChecksIPC) {
        // Inter-procedural deriving basic block covers using fixpoint: the algorithm keeps going until the sets converge
        // The intersection of the covers of a functions callers are the covers that will definitely always be active on functions enter
        unsigned int changed;
        int i = 0;
        do {
            changed = 0;
            for (auto& funcIt: *M) {
                Function* function = &funcIt;
                if (Ctx->shouldSkipFunction(function))
                    continue;

                if (isFunctionALocker(*function) || isFunctionAnUnLocker(*function))
                    continue;

                // Find the intersection of the lock cover sets of the callers of this function.
                unordered_set<LockCover, LockCoverHash, LockCoverEqual> lockCoversIntersection;
                bool first = true;
                for (const auto& caller: Ctx->Callers[function]) {
                    auto callingBB = caller->getParent();
                    //LOG(LOG_INFO, "Looking at caller " << callingBB->getParent()->getName() << " for " << function->getName() << "\n");

                    auto callingCoversIt = lockCoverage.find(callingBB);
                    if (callingCoversIt == lockCoverage.end()) {
                        lockCoversIntersection.clear();
                        break;
                    }

                    auto& callingCovers = callingCoversIt->second;
#if 0
                    // DEBUG
                    for (const auto& callingCover : callingCovers) {
                        if (callingCover.field->type->getStructName().contains("inode") && callingCover.field->getName().equals("i_rwsem")) {
                            LOG(LOG_INFO, "inode->i_rwsem travels from " << caller->getFunction()->getName() << " to " << function->getName() << "\n");
                        }
                    }
#endif

                    if (first) {
                        lockCoversIntersection.insert(callingCovers.begin(), callingCovers.end());
                        first = false;
                    } else {
                        for (auto it = lockCoversIntersection.begin(); it != lockCoversIntersection.end();) {
                            if (callingCovers.find(*it) == callingCovers.end())
                                it = lockCoversIntersection.erase(it);
                            else
                                ++it;
                        }

                        // If the intersection became empty, it can never grow again and contribute to the lock covers
                        if (lockCoversIntersection.empty())
                            break;
                    }
                }

                //LOG(LOG_INFO, "Intersection size: " << lockCoversIntersection.size() << "\n");

                // Union
                for (const auto& cover: lockCoversIntersection) {
                    auto count = lockCoversIntersection.count(cover);
                    //LOG(LOG_INFO, "Cover: ");
                    //cover.field->dump(LOG_INFO);
                    for (const auto& BB: *function) {
                        if (alreadyAdded.insert(make_pair(&BB, cover)).second
                            && unlockBarriers.find(make_pair(&BB, cover)) == unlockBarriers.end()) {
                            auto& currentCovers = lockCoverage[&BB];

                            for (decltype(count) addCounter = 0; addCounter < count; ++addCounter)
                                currentCovers.insert(cover);
                            ++changed;
                        }
                    }
                }
            }

            ++i;
            LOG(LOG_VERBOSE, "Iteration " << i << ", changed " << changed << "\n");
        } while (changed > 0);
    }

#ifdef DUMP_BB_COVERS
    LOG(LOG_INFO, "Dump BB covers:\n");
    bool shown = false;
    for (const auto& [BB, covers] : lockCoverage) {
        if (!BB->getParent()->getName().equals(/*"pm_clk_suspend"*//*"fsnotify_grab_connector"*//*"write_cache_extent_entries"*//*"sched_cfs_period_timer"*//*"neigh_timer_handler"*/"mon_bin_error"))
            continue;

        if (!shown) {
            BB->getParent()->dump();
            shown = true;
        }
        LOG(LOG_INFO, "BB: " << getBasicBlockName(BB) << " in " << BB->getParent()->getName() << "\n");
        for (const auto& cover : covers) {
            LOG(LOG_INFO, "\t");
            cover.field->dump(LOG_INFO);
            LOG(LOG_INFO, "\tType Hash: " << typeHash(cover.field->typePtr()) << "\n");
        }

        if (covers.empty()) {
            LOG(LOG_INFO, "Empty cover: " << getBasicBlockName(BB) << " in " << BB->getParent()->getName() << "\n");
        }
    }

    exit(1);
#endif
}

void LockCheckerPass::findViolations(Module* M) {
    LOG(LOG_INFO, "Computing coverage\n");
    LockCoverageMap lockCoverage;
    findBasicBlockCoverage(M, lockCoverage);

    LockCheckerPassData lockCheckerPassData(*this);
    ViolationFinder violationFinder(lockCheckerPassData, lockCoverage, allocFunctions, freeFunctions);
    if (FilterInitAndCleanup)
        violationFinder.calculateInitializationValues(*M);
#ifdef PRINT_SYSCALL_IF_THERE_ARE
    violationFinder.fillFunctionToSyscallMap(*M);
#endif
#ifdef DUMP_STORE_CALL_TEST
    violationFinder.dumpStoreAndCallsTest(*M);
#endif
    violationFinder.findViolations(*M);

    if (DumpLockingCounts) {
        violationFinder.showLockingRules();
    }

    if (DetectLockAssertionViolations) {
        LOG(LOG_INFO, "================ Assertion bugs ================\n");
        violationFinder.showAssertionBugs(*M);
    }
    LOG(LOG_INFO, "================   Field bugs   ================\n");
    violationFinder.deriveContexts();
    violationFinder.showFieldBugs();
}

void LockCheckerPass::loadTransformers(const Module& M) {
    // Functions that don't take or release locks but just transform the lock in one way or another and typically perform checks.
    loadFunctionsWithCallback(M, "lock-check-funcs", [&](const Function& func, optional<string_view>) {
        auto argument = func.getArg(0);
        FieldSourceSet fields;
        set<const Value*> trackedSet;

        for (const auto& user: argument->users())
            findFields(M, user, fields, trackedSet, false);

        if (fields.size() != 1) {
            if (fields.empty()) {
                LOG(LOG_INFO, "Warning: No fields to add for '" << func.getName() << "' as a transformer.\n");
            } else {
                LOG(LOG_INFO, "Warning: can't register '" << func.getName()
                                                          << "' as a transformer because it has more than one field access ("
                                                          << fields.size() << ") for the to-transform argument.\n");
            }
        } else {

            GlobalCtx.lockCheckFunctions.insert({&func, fields.begin()->fieldPtr()});
        }
    }, false);
}

void LockCheckerPass::loadSimpleFunctionLists(const Module& M) {
    loadFunctionsWithCallback(M, "alloc-funcs", [&](const Function& func, optional<string_view>) {
        allocFunctions.insert(&func);
    }, true);
    loadFunctionsWithCallback(M, "free-funcs", [&](const Function& func, optional<string_view>) {
        freeFunctions.insert(&func);
    }, false);
    loadFunctionsWithCallback(M, "lock-assert-funcs", [&](const Function& func, optional<string_view>) {
        lockAssertFunctions.insert(&func);
    }, false);

#if DUMP_ALLOC_AND_FREE_FUNCTIONS
    for (const auto& allocFunction : allocFunctions) {
        LOG(LOG_INFO, "Alloc function: " << allocFunction->getName() << "\n");
    }

    for (const auto& freeFunction : freeFunctions) {
        LOG(LOG_INFO, "Free function: " << freeFunction->getName() << "\n");
    }
#endif
}

void LockCheckerPass::taintAnalyseAllocFunctions() {
    stack<const Function*> todoStack;
    for (const auto* allocFunction : allocFunctions)
        todoStack.emplace(allocFunction);
    set<const Function*> banSet;
    while (!todoStack.empty()) {
        auto allocFunction = todoStack.top();
        todoStack.pop();

        if (!banSet.insert(allocFunction).second)
            continue;

        // No callers => no callers to taint.
        auto callersIt = GlobalCtx.Callers.find(allocFunction);
        if (callersIt == GlobalCtx.Callers.end())
            continue;

        for (const auto* candidateAllocFunctionCaller : callersIt->second) {
            auto candidateAllocFunction = candidateAllocFunctionCaller->getFunction();

            if (!candidateAllocFunction->getReturnType()->isPointerTy())
                continue;

            // Find all ret instructions
            set<Value *> returnValues;
            for (auto &basicBlock: *candidateAllocFunction) {
                if (auto retInst = dyn_cast<ReturnInst>(basicBlock.getTerminator())) {
                    auto returnValue = retInst->getReturnValue();
                    returnValues.insert(const_cast<Value *>(returnValue));
                }
            }

            // Now detect if these values can come from a call to an allocation function
            auto tainted = any_of(returnValues.begin(), returnValues.end(), [&](Value *returnValue) {
                set<Value *> cvSet, trackedSet;
                DFA.findSourceCV(returnValue, cvSet, trackedSet);

                for (const auto *cv: cvSet) {
                    if (auto callCv = dyn_cast<CallInst>(cv)) {
                        if (!callCv->isIndirectCall()) {
                            auto it = getCalleeIteratorForPotentialCallInstruction(GlobalCtx, *callCv);
                            if (it.has_value()) {
                                for (const auto* calledFunction : it.value()->second)
                                    if (allocFunctions.find(calledFunction) != allocFunctions.end())
                                        return true;
                            }
                        }
                    }
                }

                return false;
            });

            if (tainted) {
                allocFunctions.insert(candidateAllocFunction);
                todoStack.emplace(candidateAllocFunction);
            }
        }
    }
}

void LockCheckerPass::taintAnalyseFreeFunctions() {
    stack<const Function*> todoStack;
    for (const auto* freeFunction : freeFunctions)
        todoStack.emplace(freeFunction);
    set<const Function*> banSet;
    while (!todoStack.empty()) {
        auto freeFunction = todoStack.top();
        todoStack.pop();

        if (!banSet.insert(freeFunction).second)
            continue;

        // No callers => no callers to taint.
        auto callersIt = GlobalCtx.Callers.find(freeFunction);
        if (callersIt == GlobalCtx.Callers.end())
            continue;

        for (auto* candidateFreeFunctionCaller : callersIt->second) {
            auto candidateFreeFunction = candidateFreeFunctionCaller->getFunction();

            /*// Function must take one pointer argument to a struct
            if (candidateFreeFunction->arg_size() != 1)
                continue;*/
            if (candidateFreeFunction->arg_size() == 0)
                continue;
            auto argumentType = candidateFreeFunction->getArg(0)->getType();
            if (!argumentType->isPointerTy() || !argumentType->getPointerElementType()->isStructTy())
                continue;

            Lazy<PostDominatorTree> postDominatorTree([candidateFreeFunction] {
                return PostDominatorTree(*candidateFreeFunction);
            });

            if (!isFreeCallAlwaysExecutedRegardlessOfNullChecks(*candidateFreeFunction, candidateFreeFunctionCaller, postDominatorTree))
                continue;

            // Function must actually use the argument
            auto argument = candidateFreeFunctionCaller->getArgOperand(0);
            set<Value *> cvSet, trackedSet;
            DFA.findSourceCV(argument, cvSet, trackedSet, 0);

            for (const auto* cv : cvSet) {
                if (auto arg = dyn_cast<Argument>(cv)) {
                    if (arg->getArgNo() == 0) {
                        freeFunctions.insert(candidateFreeFunction);
                        todoStack.emplace(candidateFreeFunction);
                    }
                    break;
                }
            }
        }
    }
}

void LockCheckerPass::taintStore(const Function* function) {
    // Place sentinel if there isn't one already
    if (auto it = storeTaintData.find(function); it == storeTaintData.end())
        storeTaintData[function].fresh = true;
    else {
        if (it->second.fresh) {
            it->second.cyclic = true;
        }
        return;
    }

    set<Value*> cvSet;
    bool cyclic = false;
    for (const auto& instruction : instructions(function)) {
        if (auto SI = dyn_cast<StoreInst>(&instruction)) {
            set<Value*> trackedSet;
            DFA.findSourceCV(const_cast<Value*>(SI->getPointerOperand()), cvSet, trackedSet);
        } else if (auto Call = dyn_cast<CallInst>(&instruction)) {
            if (Call->isIndirectCall() || Call->isInlineAsm()) {
                cyclic = true; // HACK: not cyclic but we don't analyse beyond the indirect call boundary or inline asm
                goto break2;
            }
            auto calleesIt = GlobalCtx.Callees.find(Call);
            if (calleesIt == GlobalCtx.Callees.end())
                continue;
            for (const auto* target : calleesIt->second) {
                taintStore(target);
                auto& targetData = storeTaintData.find(target)->second;
                if (targetData.cyclic) {
                    cyclic = true;
                    goto break2;
                }
                for (const auto& argWithStore : targetData.argumentsWithStores) {
                    if (argWithStore < Call->arg_size()) {
                        set<Value*> trackedSet;
                        DFA.findSourceCV(Call->getArgOperand(argWithStore), cvSet, trackedSet);
                    }
                }
            }
        }
    }
    break2:;

    auto& data = storeTaintData[function];
    data.fresh = false;
    data.cyclic = cyclic;
    if (cyclic)
        return;
    for (const auto* value : cvSet) {
        if (auto arg = dyn_cast<Argument>(value)) {
            data.argumentsWithStores.push_back(arg->getArgNo());
        }
    }
}

bool LockCheckerPass::doModulePass(Module* M) {
    LOG(LOG_INFO, "Finding lock wrappers\n");
    findWrappers();
    LOG(LOG_INFO, "Finding lock fields\n");
    findLockAndUnLockFields(M);
    LOG(LOG_INFO, "Running allocation taint analysis\n");
    taintAnalyseAllocFunctions();
    LOG(LOG_INFO, "Running free taint analysis\n");
    taintAnalyseFreeFunctions();

#if 0
    for (const auto* allocFunction : allocFunctions) {
        OP << "alloc function: " << allocFunction->getName() << "\n";
    }

    exit(1);
#endif

#if 0
    for (const auto* freeFunction : freeFunctions) {
        OP << "free function: " << freeFunction->getName() << "\n";
    }

    exit(1);
#endif

#if 0
    {
        for (const auto& function : *M) {
            if (GlobalCtx.shouldSkipFunction(&function))
                continue;

            taintStore(&function);
        }
#if 0
        for (const auto& [function, data] : storeTaintData) {
            if (data.cyclic || data.argumentsWithStores.empty())
                continue;
            OP << "Function: " << function->getName() << "\n";
            for (const auto& arg : data.argumentsWithStores) {
                OP << "\t" << (unsigned int) arg << "\n";
            }
        }
#endif
    }
#endif

    findViolations(M);
    return false;
}
