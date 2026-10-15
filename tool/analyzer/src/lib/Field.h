#pragma once

#include "Common.h"
#include "LockStyles.h"
#include <memory>
#include <cassert>
#include <utility>
#include <set>
#include <unordered_set>


void maybeRegisterFieldName(const Instruction& instruction, const Type* lookupInWhichType, const Type* registerToWhichType, uint32_t offset);
StringRef getFieldName(const Type* type, uint32_t offset);


struct Field {
private:
    union {
        const Type* type;
        const GlobalValue* global;
        const void* ptr;
    };
public:
    uint32_t offset;
    shared_ptr<Field> next;

    Field() noexcept:
            ptr(nullptr),
            offset(0),
            next(nullptr) {
    }

    Field(const Field& o) noexcept = default;

    Field(const Type* type, uint32_t offset, shared_ptr<Field> next = nullptr) noexcept:
            type(type),
            offset(offset),
            next(move(next)) {
    }

    Field(const GlobalValue* global, shared_ptr<Field> next = nullptr) noexcept:
            global(global),
            offset(-1U),
            next(move(next)) {
    }

    Field(Field&& o) noexcept:
            ptr(o.ptr),
            offset(o.offset),
            next(move(o.next)),
            cachedTypeString_(move(o.cachedTypeString_)){
        o.type = nullptr;
    }

    ~Field() = default;

    Field& operator=(Field&& o) noexcept {
        type = o.type;
        offset = o.offset;
        next = move(o.next);
        o.type = nullptr;
        cachedTypeString_ = move(o.cachedTypeString_);
        return *this;
    }

    [[nodiscard]] inline const void* embeddedPtr() const { return ptr; }

    [[nodiscard]] inline const Type* typePtr() const {
        assert(!isGlobal());
        return type;
    }

    [[nodiscard]] const Type* fieldTypePtr() const;

    [[nodiscard]] const Field& last() const;

    [[nodiscard]] Field clone() const;

    [[nodiscard]] inline bool isOkay() const {
        return type;
    }

    [[nodiscard]] int depth() const;

    [[nodiscard]] unsigned int longestMatchingPrefixLength(const Field& other) const;

    [[nodiscard]] StringRef getName() const;

    [[nodiscard]] bool isPointer() const;

    [[nodiscard]] bool isInteger() const;

    [[nodiscard]] bool isGlobal() const;

    void dumpToStringStream(raw_string_ostream& output) const;

    void dump(int logLevel = LOG_VERBOSE) const {
        if (VerboseLevel >= logLevel) {
            string outputString;
            raw_string_ostream output(outputString);
            dumpToStringStream(output);
            OP << output.str();
        }
    }

    bool operator==(const Field& other) const {
        if (type == other.type && offset == other.offset && (next != nullptr) == (other.next != nullptr))
            return next == nullptr || next->operator==(*other.next);
        return false;
    }

    bool operator<(const Field& other) const {
        if (type < other.type)
            return true;
        else if (type > other.type)
            return false;
        if (offset < other.offset)
            return true;
        else if (offset > other.offset)
            return false;
        if (next == nullptr && other.next == nullptr)
            return false;
        if (next == nullptr && other.next != nullptr)
            return true;
        if (next != nullptr && other.next == nullptr)
            return false;
        return next->operator<(*other.next);
    }

    /**
     * Returns true if this field is a prefix of the other field.
     * e.g. a->b->c is a prefix of a->b->c->d->e
     * @param other
     * @return
     */
    [[nodiscard]] bool isPrefixOf(const Field& other) const;

private:
    const string& cachedTypeString() const;

    mutable string cachedTypeString_;
};

struct FieldWithMaybeCompareTypeHash;

struct FieldWithMaybeCompareType {
public:
    FieldWithMaybeCompareType(Field&& field, const Type* potentialCompareType = nullptr)
            : _field(make_shared<Field>(move(field))), _potentialCompareType(potentialCompareType) {
    }

    FieldWithMaybeCompareType(shared_ptr<Field>&& field, const Type* potentialCompareType = nullptr)
            : _field(move(field)), _potentialCompareType(potentialCompareType) {
    }

    FieldWithMaybeCompareType(shared_ptr<Field>& field, const Type* potentialCompareType = nullptr)
            : _field(field), _potentialCompareType(potentialCompareType) {
    }

    operator shared_ptr<Field>() {
        return move(_field);
    }

    [[nodiscard]] const shared_ptr<Field>& fieldPtr() const {
        return _field;
    }

    /**
     * Due to inheritance and pointer casts, the comparing type may be extended to a potential different comparing type.
     * E.g. when a lock is taken on A->lock and A is cast to type B, B is considered covered by A->lock, despite
     * A and B being different types.
     *
     * @return const Type*
     */
    [[nodiscard]] inline const Type* potentialCompareType() const {
        return _potentialCompareType;
    }

    bool operator==(const FieldWithMaybeCompareType& other) const {
        return _potentialCompareType == other._potentialCompareType && _field == other._field;
    }

private:
    shared_ptr<Field> _field;
    const Type* _potentialCompareType;

    friend struct FieldWithMaybeCompareTypeHash;
};

struct FieldHash {
    size_t operator()(const Field& P) const {
        if (P.isGlobal()) {
            return 7919 + 33 * reinterpret_cast<size_t>(P.embeddedPtr()) + (P.next != nullptr) * 5381;
        } else {
            auto type = P.typePtr();
            auto elements = type->isStructTy() ? type->getStructNumElements() : 1;
            return std::hash<uint32_t>()(elements) * 33 + std::hash<uint64_t>()(P.offset) * 31 +
                   (P.next != nullptr) * 5381;
        }
    }
};

struct FieldSharedPtrHash {
    size_t operator()(const shared_ptr<Field>& P) const {
        FieldHash h;
        return h(*P);
    }
};

struct FieldSharedPtrEqual {
    bool operator()(const shared_ptr<Field>& a, const shared_ptr<Field>& b) const {
        return a->operator==(*b);
    }
};

struct FieldSharedPtrCompare {
    bool operator()(const shared_ptr<Field>& a, const shared_ptr<Field>& b) const {
        return a->operator<(*b);
    }
};

struct FieldWithMaybeCompareTypeHash {
    size_t operator()(const FieldWithMaybeCompareType& P) const {
        FieldSharedPtrHash h;
        return h(P._field);
    }
};

struct LockCover {
    shared_ptr<Field> field;
    const Instruction* originLockCall;
    LockAccessStyle lockAccessStyle : 1;
    LockAcquisitionStyle lockAcquisitionStyle : 1;
};

struct LockCoverComp {
    bool operator()(const LockCover& a, const LockCover& b) const {
        return a.field->operator<(*b.field);
    }
};

struct LockCoverCompOrigin {
    bool operator()(const LockCover& a, const LockCover& b) const {
        if (a.originLockCall < b.originLockCall)
            return true;
        else if (a.originLockCall > b.originLockCall)
            return false;
        LockCoverComp c;
        return c.operator()(a, b);
    }
};

struct LockCoverCompPtr {
    bool operator()(const LockCover* a, const LockCover* b) const {
        LockCoverComp compare;
        return compare.operator()(*a, *b);
    }
};

struct LockCoverHash {
    size_t operator()(const LockCover& a) const {
        FieldHash h;
        return h.operator()(*a.field);
    }
};

struct LockCoverEqual {
    bool operator()(const LockCover& a, const LockCover& b) const {
        return a.field->operator==(*b.field);
    }
};


using LockCoverageMap = unordered_map<const BasicBlock*, unordered_multiset<LockCover, LockCoverHash, LockCoverEqual>>;
using FieldSourceSet = unordered_set<FieldWithMaybeCompareType, FieldWithMaybeCompareTypeHash>;


using ViolationPaths = vector<vector<const Instruction*>>;
using ViolationPathMap = unordered_map<shared_ptr<Field>, ViolationPaths, FieldSharedPtrHash, FieldSharedPtrEqual>;

struct FieldCoverageData {
    ViolationPaths paths;
    set<const Value*> notLockedCounter;
    unordered_multiset<LockCover, LockCoverHash, LockCoverEqual> lockCovers;
};

using FieldCoverageDataMap = unordered_map<shared_ptr<Field>, FieldCoverageData, FieldSharedPtrHash, FieldSharedPtrEqual>;


using ArgumentIndex = uint16_t;

optional<ArgumentIndex> getArgumentIndexForField(const class TypeRemapper& typeRemapper, const FieldWithMaybeCompareType& field, const Function& function);
