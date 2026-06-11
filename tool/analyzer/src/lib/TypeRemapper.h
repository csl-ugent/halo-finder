#pragma once

#include <string_view>
#include <llvm/IR/Instructions.h>

using namespace llvm;

class TypeRemapper {
public:
    void build(const Module& M);
    const Type* mapType(const Type* type) const;
    optional<const Type*> getTypeFromName(const string_view& str) const;

private:
    unordered_map<size_t, const Type*> hashToType;
    unordered_map<const Type*, const Type*> typeMapper;
    unordered_map<string_view, const Type*> nameToType;
};
