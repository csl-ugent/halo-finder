#include "TypeRemapperPass.h"

DenseMap<const LLVMContext *, const DataLayout *> ctxToLayout;

void TypeRemapper::build(const Module& M) {
    ctxToLayout[&M.getContext()] = &M.getDataLayout();

    auto structTypeList = M.getIdentifiedStructTypes();
    unordered_map<string_view, const Type*> baseLookup;
    for (const auto type: structTypeList) {
        auto myName = type->getName();
        auto dotOffset = myName.find('.', 7);
        if (dotOffset == string::npos) {
            baseLookup.insert({myName, type});
            nameToType.insert({myName.substr(7), type});
        }
    }
    for (const auto type: structTypeList) {
        auto myName = type->getName();
        auto dotOffset = myName.find('.', 7);
        if (dotOffset != string::npos) {
            auto targetType = baseLookup[myName.substr(0, dotOffset)];
            if (targetType && type->getStructNumElements() == targetType->getStructNumElements()) {
                typeMapper.insert({type, targetType});
                hashToType[typeHash(targetType)] = targetType;
            }
        }
    }

#if 0
    for (const auto& [type1, type2] : typeMapper) {
        LOG(LOG_INFO, "Map " << type1->getStructName() << " -> " << type2->getStructName() << "\n");
        LOG(LOG_INFO, "Hashes: " << typeHash(type1) << ", " << typeHash(type2) << "\n");
    }

    exit(1);
#endif
}

optional<const Type*> TypeRemapper::getTypeFromName(const string_view& str) const {
    auto it = nameToType.find(str);
    if (it == nameToType.end()) {
        return {};
    } else {
        return it->second;
    }
}

const Type* TypeRemapper::mapType(const Type* type) const {
    if (!type) return nullptr;

    // Fast path
    auto typeMapperIt = typeMapper.find(type);
    if (typeMapperIt != typeMapper.end())
        return typeMapperIt->second;

    // Slower hashing path
    auto hashIt = hashToType.find(typeHash(type));
    if (hashIt != hashToType.end())
        return hashIt->second;

    return type;
}

bool TypeRemapperPass::doInitialization(Module* M) {
    return false;
}

bool TypeRemapperPass::doFinalization(Module* M) {
    return false;
}

bool TypeRemapperPass::doModulePass(Module* M) {
    Ctx->typeRemapper.build(*M);
    return false;
}
