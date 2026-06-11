#include "Field.h"
#include "DebugHelpers.h"
#include "Helpers.h"


map<pair<const Type*, uint32_t>, StringRef> fieldNameLookupMap;
shared_mutex fieldNameLookupMapLock;


[[nodiscard]] const Type* Field::fieldTypePtr() const {
    if (typePtr()->isStructTy()) {
        if (offset >= typePtr()->getStructNumElements())
            return nullptr;
        return typePtr()->getStructElementType(offset);
    }
    return nullptr;
}

optional<ArgumentIndex> getArgumentIndexForField(const TypeRemapper& typeRemapper, const FieldWithMaybeCompareType& field, const Function& function) {
    bool debug = false; //function.getName().equals("queue_requeue_list_stop");
    auto fieldType = field.fieldPtr()->typePtr();
    auto numArguments = function.getFunctionType()->getNumParams();
    for (unsigned int i = 0; i < numArguments; ++i) {
        const Type* argumentType = function.getArg(i)->getType();
        argumentType = getStructType(argumentType);
        argumentType = typeRemapper.mapType(argumentType);

        if (debug) {
            LOG(LOG_INFO, "getArgumentIndexForField debug " << i << ":\n");
            argumentType->dump();
            fieldType->dump();
        }

        if (argumentType == fieldType || argumentType == field.potentialCompareType())
            return i;
    }
    return {};
}

void maybeRegisterFieldName(const Instruction& instruction, const Type* lookupInWhichType, const Type* registerToWhichType, uint32_t offset) {
    auto pair = make_pair(registerToWhichType, offset);
    fieldNameLookupMapLock.lock();
    if (fieldNameLookupMap.find(pair) == fieldNameLookupMap.end()) {
        auto name = getFieldNameFrom(*instruction.getModule(), instruction.getFunction(), const_cast<Type*>(lookupInWhichType), offset);
        fieldNameLookupMap[pair] = name;
    }
    fieldNameLookupMapLock.unlock();
}

StringRef getFieldName(const Type* type, uint32_t offset) {
    Deferred _([&] {
        fieldNameLookupMapLock.unlock_shared();
    });
    fieldNameLookupMapLock.lock_shared();
    auto pair = make_pair(type, offset);
    if (auto it = fieldNameLookupMap.find(pair); it == fieldNameLookupMap.end())
        return {};
    else
        return it->second;
}

const Field& Field::last() const {
    auto* ptr = this;
    while (ptr->next.get()) {
        ptr = ptr->next.get();
    }
    return *ptr;
}

Field Field::clone() const {
    if (next)
        return {type, offset, make_shared<Field>(next->clone())};
    else
        return {type, offset, {}};
}

int Field::depth() const {
    if (isWrappingType(type))
        return 0;
    if (next)
        return 1 + next->depth();
    else
        return 1;
}

unsigned int Field::longestMatchingPrefixLength(const Field& other) const {
    if (type != other.type || offset != other.offset) // Mismatch
        return 0;
    if (other.next != nullptr && next != nullptr)
        return 1 + next->longestMatchingPrefixLength(*other.next);
    else
        return 1;
}

StringRef Field::getName() const {
    return getFieldName(type, offset);
}

bool Field::isPrefixOf(const Field& other) const {
    if (type != other.type || offset != other.offset) // Mismatch
        return false;
    if (other.next == nullptr && next != nullptr) // a->b->c, other a->b
        return false;
    if (other.next != nullptr && next == nullptr) // a->b, other a->b->c
        return true;
    if (other.next == nullptr && next == nullptr) // They are equal => also a prefix
        return true;

    return next->isPrefixOf(*other.next);
}

bool Field::isPointer() const {
    auto* ptr = this;
    do {
        if (ptr->type->isStructTy() && ptr->type->getStructNumElements() > ptr->offset && ptr->type->getStructElementType(ptr->offset)->isPointerTy())
            return true;
    } while ((ptr = ptr->next.get()) != nullptr);
    return false;
}

bool Field::isInteger() const {
    auto* ptr = this;
    do {
        if (ptr->type->isStructTy() && ptr->type->getStructNumElements() > ptr->offset && ptr->type->getStructElementType(ptr->offset)->isIntegerTy())
            return true;
    } while ((ptr = ptr->next.get()) != nullptr);
    return false;
}

bool Field::isGlobal() const {
    return offset == -1U;
}

const string& Field::cachedTypeString() const {
    if (!cachedTypeString_.empty())
        return cachedTypeString_;

    string tmpStr;
    raw_string_ostream rso(tmpStr);
    type->print(rso);
    auto equalsOffset = rso.str().find(" = ");
    string_view strView{tmpStr};
    //type->dump();
    //LOG(LOG_INFO, "Full type str: " << typeStr << "\n");
    if (equalsOffset != std::string::npos) {
        cachedTypeString_ = strView.substr(0, equalsOffset);
#ifdef SHOW_TYPE_ADDRESSES
        string tmpFormatterStr;
        raw_string_ostream tmpFormatter(tmpFormatterStr);
        tmpFormatter << '{' << type << '}';
        cachedTypeString_ += tmpFormatter.str();
#endif
    } else {
        cachedTypeString_ = move(tmpStr);
    }

    return cachedTypeString_;
}

void Field::dumpToStringStream(raw_string_ostream& output) const {
    if (isGlobal()) {
        output << "[G]";
        global->printAsOperand(output, false);
    } else {
        output << "[F]" << cachedTypeString() << ": " << getName() << "(" << offset << ")";
    }

    // Print all the next pointers
    auto it = next;
    while (it) {
        assert(!it->isGlobal());
#ifdef SHOW_TYPE_ADDRESSES
        output << '{' << it->ptr << '}';
#endif
        output << '.';
        if (auto itName = it->getName(); !itName.empty())
            output << itName;
        output << "(" << it->offset << ")";
        if (!it->next) { // Last entry
            if (it->type->isStructTy() && it->type->getStructElementType(it->offset)->isPointerTy()) {
                output << " (is a pointer)";
            }
        }
        it = it->next;
    }
    output << '\n';
}
