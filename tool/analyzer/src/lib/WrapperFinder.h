#pragma once

#include "Analyzer.h"

struct LockUnlockerDataEntry {
    // Null if just passing the argument, otherwise a field
    shared_ptr<Field> field;
    ArgumentIndex index;

    LockUnlockerDataEntry(const shared_ptr<Field>& field, ArgumentIndex index)
            : field(field), index(index) {}

    void dump(int logLevel) const {
        LOG(logLevel, "\t\tIndex " << index << ", Field: ");
        if (field)
            field->dump(logLevel);
        else
            LOG(logLevel, "N/A\n");
    }

    bool operator<(const LockUnlockerDataEntry& other) const {
        if (index < other.index) return true;
        else if (index > other.index) return false;
        if (!field && other.field) return true;
        else if (!other.field) return false;
        else return field->operator<(*other.field);
    }
};

struct LockUnlockerData {
    set<LockUnlockerDataEntry> entries;
    LockAcquisitionStyle lockAcquisitionStyle : 1;
    LockAccessStyle lockAccessStyle : 1;
    unsigned short depth;

    LockUnlockerData()
            : lockAcquisitionStyle(LockAcquisitionStyle::Unconditional), lockAccessStyle(LockAccessStyle::ReadWrite), depth(0) {
    }

    explicit LockUnlockerData(LockAcquisitionStyle lockAcquisitionStyle, LockAccessStyle lockAccessStyle, unsigned short depth)
            : lockAcquisitionStyle(lockAcquisitionStyle), lockAccessStyle(lockAccessStyle), depth(depth) {
    }

    void addEntry(const shared_ptr<Field>& field, ArgumentIndex index) {
        entries.emplace(field, index);
    }

    void dump(int logLevel = LOG_VERBOSE) const {
        for (const auto& entry : entries)
            entry.dump(logLevel);
    }
};

class WrapperFinder {
public:
    explicit WrapperFinder(GlobalContext* Ctx, unordered_map<const Function*, LockUnlockerData>& lockers, unordered_map<const Function*, LockUnlockerData>& unlockers)
        : Ctx(Ctx), lockers(lockers), unlockers(unlockers) {}

    enum EscapeDecision : char {
        None = 0,
        EscapesLock = 1,
        EscapesUnLock = 2,
        ConditionalFlag = 4,
    };

    void calculate();

    [[nodiscard]] inline const set<const Function*>& getFunctionsThatEventuallyCallALocker() const {
        return functionsThatEventuallyCallALocker;
    }

    [[nodiscard]] inline const set<const Function*>& getFunctionsThatEventuallyCallAnUnLocker() const {
        return functionsThatEventuallyCallAnUnLocker;
    }
private:
    GlobalContext* Ctx;
    unordered_map<const Function*, LockUnlockerData>& lockers, &unlockers;

    unordered_map<const Function*, EscapeDecision> decisions;

    set<const Function*> functionsThatEventuallyCallALocker, functionsThatEventuallyCallAnUnLocker;

    void findEventualCallers(set<const Function*>& destinationSet, unordered_map<const Function*, LockUnlockerData>& source);
    void findEventualCallersThreadWrapper(set<const Function*>* destinationSet, unordered_map<const Function*, LockUnlockerData>* source);

    EscapeDecision calculateEscapeDecisionForFunction(const Function& function, set<const Function*>& visitedFunctions);
    EscapeDecision backTrackEscapingLockers(const BasicBlock& BB, set<const BasicBlock*>& visited, set<const Function*>& visitedFunctions, int lockBalance);
};
