#include "Helpers.h"
#include "DebugHelpers.h"
#include "Common.h"
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Constants.h>

using namespace std;

//#define DEBUG

string getBasicBlockName(const BasicBlock* BB) {
	string str;
	raw_string_ostream rso(str);
    rso << BB->getParent()->getName() << ':';
	BB->printAsOperand(rso, false);
	return rso.str();
}


void dumpDebugValue(const Function* function) {
    for (const auto& instruction : instructions(function)) {
		if (auto dbg = dyn_cast<DbgDeclareInst>(&instruction)) {
			dbg->getAddress()->getType()->dump();
			dbg->getAddress()->dump();
		} else if (auto dbg = dyn_cast<DbgValueInst>(&instruction)) {
			dbg->getValue()->getType()->dump();
			dbg->getValue()->dump();
		}
	}
}

const MDNode* findDebugValue(const Type* type, const Function* function) {
    for (const auto& instruction : instructions(function)) {
        if (auto dbg = dyn_cast<DbgDeclareInst>(&instruction); dbg && dbg->getAddress() && dbg->getAddress()->getType() == type) {
            return dbg->getVariable();
        } else if (auto dbg = dyn_cast<DbgValueInst>(&instruction); dbg && dbg->getValue() && dbg->getValue()->getType() == type) {
            return dbg->getVariable();
        }
    }
	return nullptr;
}

StringRef getFieldNameFrom(const Module& M, const Function* function, Type* type, uint64_t offset) {
	const MDNode* mdNode = findDebugValue(type, function);

	if (mdNode) {
#ifdef DEBUG
		mdNode->dump();
#endif

		if (auto diLocalVar = dyn_cast<DILocalVariable>(mdNode)) {
#ifdef DEBUG
			diLocalVar->getType()->dump();
#endif
			if (auto diDerivedType = dyn_cast<DIDerivedType>(diLocalVar->getType())) {
				auto baseType = diDerivedType->getBaseType();
				while (baseType) {
					if (auto test = dyn_cast<DIDerivedType>(baseType))
						baseType = test->getBaseType();
					else
						break;
				}
				if (baseType) {
#ifdef DEBUG
					baseType->dump();
#endif
					if (auto diCompositeType = dyn_cast<DICompositeType>(baseType)) {
#ifdef DEBUG
						diCompositeType->dump();
#endif
						auto elements = diCompositeType->getElements();
						if (elements && offset < elements->getNumOperands()) {
							auto structType = getStructType(type);
							if (!structType)
								return {};

							/**
							 * Fun fact: bitfields in LLVM are not considered as seperate entries in type = { ... }, but they are seperate entries in the debug information!
							 * Therefore, the offset of a field in the type and in debug information is not the same!
							 * Solution: use bit offset...
							 */

							auto bitOffset = getFieldBitOffsetOf(M, *structType, offset);

							if (bitOffset == -1ULL) {
								LOG(LOG_INFO, "  inside: " << function->getName() << "\n");
								exit(1);
							}
#ifdef DEBUG
							LOG(LOG_INFO, "Bit offset: " << bitOffset << "\n");
#endif

							for (unsigned int i = 0; i < elements->getNumOperands(); ++i) {
								if (auto diNode = dyn_cast<DIDerivedType>(elements[i])) {
									if (diNode->getOffsetInBits() == bitOffset)
										return diNode->getName();
								}
							}
						}
					}
				}
			}
		}
	}

	return {};
}
