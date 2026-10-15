#include <stack>
#include <thread>
#include "WrapperFinder.h"
#include "Config.h"
#include "Helpers.h"
#include "DebugHelpers.h"


static string_view escapeDecisionToStrView(WrapperFinder::EscapeDecision decision) {
    if (decision == WrapperFinder::EscapeDecision::EscapesLock) return "L";
    if (decision == WrapperFinder::EscapeDecision::EscapesUnLock) return "U";
    if (decision == (WrapperFinder::EscapeDecision::EscapesLock | WrapperFinder::EscapeDecision::ConditionalFlag)) return "?L?";
    if (decision == (WrapperFinder::EscapeDecision::EscapesUnLock | WrapperFinder::EscapeDecision::ConditionalFlag)) return "?U?";
    if (decision == WrapperFinder::EscapeDecision::None) return "/";
    return {};
}

WrapperFinder::EscapeDecision WrapperFinder::calculateEscapeDecisionForFunction(const Function& function, set<const Function*>& visitedFunctions) {
    if (function.size() > MAX_WRAPPER_BB_SIZE)
        return EscapeDecision::None;

    // Result cache
    auto it = decisions.find(&function);
    if (it != decisions.end())
        return it->second;

    if (lockers.find(&function) != lockers.end())
        return EscapeDecision::EscapesLock;
    if (unlockers.find(&function) != unlockers.end())
        return EscapeDecision::EscapesUnLock;

    if (!visitedFunctions.insert(&function).second)
        return EscapeDecision::None;

    set<const BasicBlock*> visited;
    auto result = callbackOnReturnInstruction(function, [&](const auto& BB) {
        return backTrackEscapingLockers(BB, visited, visitedFunctions, 0);
    }, EscapeDecision::None);

    decisions.insert({&function, result});

    return result;
}

WrapperFinder::EscapeDecision WrapperFinder::backTrackEscapingLockers(const BasicBlock& BB, set<const BasicBlock*>& visited, set<const Function*>& visitedFunctions, int lockBalance) {
    bool debug = false; //BB.getParent()->getName().equals("perf_lock_task_context"/*"locked_inode_to_wb_and_lock_list"*//*"fsnotify_grab_connector"*/);

    if (!visited.insert(&BB).second)
        return EscapeDecision::None;

    for (BasicBlock::const_reverse_iterator it = BB.rbegin(); it != BB.rend(); ++it) {
        auto& instruction = *it;
        auto caller = dyn_cast<CallInst>(&instruction);
        if (!caller || caller->isIndirectCall())
            continue;

        auto calleeSetIt = getCalleeIteratorForPotentialCallInstruction(*Ctx, instruction);
        if (!calleeSetIt.has_value())
            continue;

        // Consider the possible callees of this caller, if it is an unlocker, we know we this path always unlocks.
        // Otherwise, there's still a possibility this path locks.
        for (const auto* callee: calleeSetIt.value()->second) {
            auto result = calculateEscapeDecisionForFunction(*callee, visitedFunctions);
            if (debug) LOG(LOG_INFO, getBasicBlockName(&BB) << ", Intermediate result for " << callee->getName() << ": " << escapeDecisionToStrView(result) << ", " << lockBalance << "\n");
            if (result == EscapeDecision::EscapesLock) {
                ++lockBalance;
            } else if (result == EscapeDecision::EscapesUnLock) {
                --lockBalance;
            }
        }
    }

#if 1
    // Don't know yet, look at predecessors
    optional<EscapeDecision> previousResult;
    EscapeDecision finalResult = EscapeDecision::None;
    bool unanimous = true;
    for (const auto* predecessor: predecessors(&BB)) {
        set<const BasicBlock*> visitedCopy {visited};
        auto result = backTrackEscapingLockers(*predecessor, visitedCopy, visitedFunctions, lockBalance);
        if (result != EscapeDecision::None)
            finalResult = result;
        if (previousResult.has_value()) {
            if (previousResult.value() != result)
                unanimous = false;
        } else
            previousResult = result;
    }

    if (finalResult != EscapeDecision::None) {
        if (!unanimous)
            finalResult = (EscapeDecision) (finalResult | EscapeDecision::ConditionalFlag);
        if (debug) LOG(LOG_INFO, "final result return: " << escapeDecisionToStrView(finalResult) << "\n");
        return finalResult;
    }
#else
    // Don't know yet, look at predecessors
    for (const auto& predecessor: predecessors(&BB)) {
        auto result = backTrackEscapingLockers(*predecessor, visited, visitedFunctions, lockBalance);
        if (result != EscapeDecision::None)
            return result;
    }
#endif

    if (&BB.getParent()->getEntryBlock() != &BB) {
        if (debug) LOG(LOG_INFO, "No result from predecessors, but at " << getBasicBlockName(&BB) << ", which is not the entry, " << lockBalance << "\n");
        return EscapeDecision::None;
    }

    auto result = EscapeDecision::None;
    if (lockBalance < 0)
        result = EscapeDecision::EscapesUnLock;
    if (lockBalance > 0)
        result = EscapeDecision::EscapesLock;
    if (debug) LOG(LOG_INFO, "Decision: " << escapeDecisionToStrView(result) << "\n");
    return result;
}

void WrapperFinder::findEventualCallers(set<const Function*>& destinationSet, unordered_map<const Function*, LockUnlockerData>& source) {
    stack<const Function*> functionCheckStack;
    for (const auto& [f, _]: source) {
        destinationSet.insert(f);

        for (const auto& caller: Ctx->Callers[const_cast<Function*>(f)]) {
            auto function = caller->getFunction();
            functionCheckStack.push(function);
        }
    }
    set<const Function*> visitedFunctions;
    while (!functionCheckStack.empty()) {
        auto& function = *functionCheckStack.top();
        functionCheckStack.pop();

        if (!visitedFunctions.insert(&function).second)
            continue;

        if (Ctx->shouldSkipFunction(&function))
            continue;

        if (destinationSet.insert(&function).second) {
            auto it = Ctx->Callers.find(const_cast<Function*>(&function));
            if (it != Ctx->Callers.end()) {
                for (const auto &caller: it->second) {
                    if (!caller->isIndirectCall())
                        functionCheckStack.emplace(caller->getFunction());
                }
            }
        }
    }
}

void WrapperFinder::findEventualCallersThreadWrapper(set<const Function*>* destinationSet, unordered_map<const Function*, LockUnlockerData>* source) {
    findEventualCallers(*destinationSet, *source);
}

void WrapperFinder::calculate() {
    thread t1(&WrapperFinder::findEventualCallersThreadWrapper, this, &functionsThatEventuallyCallALocker, &lockers);
    thread t2(&WrapperFinder::findEventualCallersThreadWrapper, this, &functionsThatEventuallyCallAnUnLocker, &unlockers);
    t1.join();
    t2.join();

    decltype(functionsThatEventuallyCallALocker) workSet;
    workSet.insert(functionsThatEventuallyCallALocker.begin(), functionsThatEventuallyCallALocker.end());
    workSet.insert(functionsThatEventuallyCallAnUnLocker.begin(), functionsThatEventuallyCallAnUnLocker.end());

    set<const Function*> visitedFunctions;
    for (auto* workItem : workSet) {
        auto result = static_cast<EscapeDecision>(calculateEscapeDecisionForFunction(*workItem, visitedFunctions) /*& ~EscapeDecision::ConditionalFlag*/);
        LOG(LOG_VERBOSE, "Result for " << workItem->getName() << ": " << escapeDecisionToStrView(result) << "\n");

        if (result != EscapeDecision::EscapesLock)
            functionsThatEventuallyCallALocker.erase(workItem);
        if (result != EscapeDecision::EscapesUnLock)
            functionsThatEventuallyCallAnUnLocker.erase(workItem);
    }
}

