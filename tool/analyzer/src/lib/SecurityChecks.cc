#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/CFG.h>
#include <llvm/Analysis/CallGraph.h>
#include <stack>

#include "SecurityChecks.h"
#include "Common.h"
#include "Helpers.h"


#define MAX_BLOCKS_SUPPORT 100

#define ERRNO_PREFIX 0x4cedb000
#define ERRNO_MASK   0xfffff000

#define ERR_RETURN_MASK 0xF
#define ERR_HANDLE_MASK 0xF0

// 1: only consider pre-defined default error codes such as EFAULT;
// 2: default error codes + <-4095, -1>
#define ERRNO_TYPE 	1
#define ERROR_NULL_PTR

//#define DEBUG_PRINT
//#define TEST_CASE

// Refine the assembly functions to detect more SecurityChecks
//#define ASM_FUNC
//static const std::regex pattern("[a-zA-Z_]+(\\s*)(?=\\()");

using namespace llvm;
using namespace std;

// SelectInsts that take error codes
set<Instruction *>SecurityChecksPass::ErrSelectInstSet;

static inline bool isInterestingErrno(int64_t value) {
    constexpr int64_t ACCEPTED_ERRNOS[] = {
            // Invalid data passed, which might change due to a race
            EINVAL, ENXIO, E2BIG, EFAULT, ENOMEM, ENFILE, EPIPE, ENODEV, ENOENT,
            // Access control
            EPERM, EACCES, EROFS
    };

    for (size_t i = 0; i < sizeof(ACCEPTED_ERRNOS) / sizeof(ACCEPTED_ERRNOS[0]); ++i) {
        auto acceptedErrno = ACCEPTED_ERRNOS[i] | ERRNO_PREFIX;
        if (acceptedErrno == value || acceptedErrno == -value)
            return true;
    }

    return false;
}

/// Check if the value is an errno.
bool SecurityChecksPass::isValueErrno(Value *V, Function *F) {
    // Invalid input.
    if (!V)
        return false;

    // The value is a constant integer.
    if (ConstantInt *CI = dyn_cast<ConstantInt>(V)) {
        const int64_t value = CI->getValue().getSExtValue();
        // The value is an errno (negative or positive).
        if (isInterestingErrno(value)
#if ERRNO_TYPE == 2
            || (-4096 < value && value < 0)
#endif
                ) {
            return true;
        }
    }

#ifdef ERROR_NULL_PTR
    if (isa<ConstantPointerNull>(V)) {
        if (F->getReturnType()->isPointerTy())
            return true;
    }
#endif

    // The value is a constant expression.
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(V)) {
        if (CE) {
            for (unsigned i = 0, e = CE->getNumOperands();
                 i != e; ++i) {
                if (isValueErrno(CE->getOperand(i), F))
                    return true;
            }
        }
    }

    return false;
}

/// Dump the marked CFG edges.
void SecurityChecksPass::dumpErrEdges(EdgeErrMap &edgeErrMap) {
    for (auto it = edgeErrMap.begin(); it != edgeErrMap.end(); ++it) {
        CFGEdge edge = it->first;
        int flag = it->second;
        Instruction *TI = edge.first;

        if (nullptr == TI) {
            OP << "    An errno ";
            OP << (flag & Must_Return_Err ? "must" : "may");
            OP << " be returned.\n";
            continue;
        }

        BasicBlock *predBB = TI->getParent();
        BasicBlock *succBB = edge.second;

        OP << "    ";
        predBB->printAsOperand(OP, false);
        OP << " -> ";
        succBB->printAsOperand(OP, false);
        OP << ": <";
        OP << (flag & ERR_RETURN_MASK);
        OP<<", ";
        OP << (flag & ERR_HANDLE_MASK);
        OP<<">\n";
    }
}


/////////////////////////////////////////////////////////////////////
// Implementation of SecurityChecksPass
/////////////////////////////////////////////////////////////////////

/// Find error code based on error handling functions
void SecurityChecksPass::findErrorCodes(Function *F) {
#if 0
    DILocation *Loc = getSourceLocation(I);
	if (!Loc)
		return "";
	unsigned lineno = Loc->getLine();
	std::string fn_str = getFileName(Loc);
	for (inst_iterator i = inst_begin(F), e = inst_end(F);
			i != e; ++i) {

		CallInst *CI = dyn_cast<CallInst>(&*i);
		if (!CI)
			continue;

		StringRef FName = getCalledFuncName(CI);
		auto FIter = Ctx->ErrorHandleFuncs.find(FName.str());
		if (FIter == Ctx->ErrorHandleFuncs.end())
			continue;

		// collect storeinst
		BasicBlock *BB = CI->getParent();
		for (BasicBlock::iterator I = BB->begin(),
				IE = BB->end(); I != IE; ++I) {
			StoreInst *SI = dyn_cast<StoreInst>(I);
			if (!SI)
				continue;
			Value *SVO = SI->getValueOperand();
			if (isa<Constant>(SVO)) {
				//Metadata *MD = SI->getMetadata(LLVMContext::MD_dbg);
				//MD->print(OP);

				string line = getSourceLine(SI);
				if (line == "")
					continue;
				while(line[0] == ' ' || line[0] == '\t')
					line.erase(line.begin());
			}
		}
		// collect conditional statements
		for (BasicBlock *PB : predecessors(BB)) {
			Instruction *TI = PB->getTerminator();
			if (TI->getNumSuccessors() < 2)
				continue;
			Value *Cond = nullptr;
			BranchInst *BI;
			SwitchInst *SI;

			if (BranchInst * BI = dyn_cast<BranchInst>(TI))
				Cond = BI->getCondition();
			else if (SwitchInst * SI = dyn_cast<SwitchInst>(TI))
				Cond = SI->getCondition();
			else
				continue;
			if (!Cond)
				continue;
			ICmpInst *IC = dyn_cast<ICmpInst>(Cond);
			if (!IC)
				continue;
			if (!IC->isEquality())
				continue;
			string line = getSourceLine(dyn_cast<Instruction>(Cond));
			if (line == "")
				continue;
			while(line[0] == ' ' || line[0] == '\t')
				line.erase(line.begin());
		}
	}
#endif
}

/// Incorporate flags
void SecurityChecksPass::updateReturnFlag(int &errFlag, int &newFlag) {

    int ErrReturnMask = ERR_RETURN_MASK;

    // update flag for error returning
    if (newFlag & ErrReturnMask)
        errFlag = (errFlag & ~ErrReturnMask) | (newFlag & ErrReturnMask);
}

void SecurityChecksPass::updateHandleFlag(int &errFlag, int &newFlag) {

    int ErrHandleMask = ERR_HANDLE_MASK;

    // Assume handle flag cannot be updated from Must to May
    if (errFlag & Must_Handle_Err)
        return;

    // update flag for error handling
    if (newFlag & ErrHandleMask)
        errFlag = (errFlag & ~ErrHandleMask) | (newFlag & ErrHandleMask);
}

void SecurityChecksPass::mergeFlag(int &errFlag, int &newFlag) {

    int tempFlag = 0;

    if ((errFlag & Must_Return_Err) && (newFlag & Must_Return_Err))
        tempFlag |= Must_Return_Err;
    else if ((errFlag & May_Return_Err) || (newFlag & May_Return_Err))
        tempFlag |= May_Return_Err;
    else if (!(errFlag & ERR_RETURN_MASK))
        tempFlag |= (newFlag & ERR_RETURN_MASK);
    else
        tempFlag |= (errFlag & ERR_RETURN_MASK);

    if ((errFlag & Must_Handle_Err) && (newFlag & Must_Handle_Err))
        tempFlag |= Must_Handle_Err;
    else if ((errFlag & May_Handle_Err) || (newFlag & May_Handle_Err))
        tempFlag |= May_Return_Err;
    else if (!(errFlag & ERR_HANDLE_MASK))
        tempFlag |= (newFlag & ERR_HANDLE_MASK);
    else
        tempFlag |= (errFlag & ERR_HANDLE_MASK);

    // update
    errFlag = tempFlag;
}

/// Marking the flag for the block
void SecurityChecksPass::markBBErr(BasicBlock *BB,
                                   ErrFlag flag, BBErrMap &bbErrMap) {

    assert(BB);

    if (bbErrMap.count(BB) != 0)
        bbErrMap[BB] |= flag;
    else
        bbErrMap[BB] = flag;

#ifdef DEBUG_PRINT
    OP << "# Marking "<<flag<<" for basic block ";
	BB->printAsOperand(OP, false);
	OP<<"\n";
#endif
}

/// Recursively mark all edges from the given block
void SecurityChecksPass::recurMarkEdgesFromBlock(CFGEdge &CE, int flag,
                                                 BBErrMap &bbErrMap, EdgeErrMap &edgeErrMap) {
    BasicBlock *BB = CE.second;

    // If BB resets the error, stop tracking
    if (bbErrMap.count(BB) != 0 && bbErrMap[BB] & ERR_RETURN_MASK)
        return;

    std::set<CFGEdge> PE;
    std::stack<std::pair<CFGEdge, int>> EEP;

    EEP.emplace(std::make_pair(CE, flag));
    while (!EEP.empty()) {

        std::pair<CFGEdge, int> TEP = EEP.top();
        EEP.pop();
        if (PE.count(TEP.first) != 0)
            continue;
        PE.insert(TEP.first);

        BasicBlock *TB = TEP.first.second;
        // Iterate on each successor basic block.
        Instruction* TI = TB->getTerminator();
        // No successors, stop
        if (TI->getNumSuccessors() == 0)
            continue;

        // Integrate flags of all incoming edges
        int IntFlag = TEP.second;
        for (BasicBlock *PredBB : predecessors(TB)) {
            if (PredBB == TEP.first.first->getParent())
                continue;
            Instruction *TI = PredBB->getTerminator();
            CFGEdge Edge = std::make_pair(TI, TB);
            if (edgeErrMap.count(Edge) == 0)
                edgeErrMap[Edge] = 0;
            mergeFlag(IntFlag, edgeErrMap[Edge]);
        }
        for (BasicBlock *Succ : successors(TB)) {
            CFGEdge CE = std::make_pair(TI, Succ);
            if ((IntFlag & ERR_RETURN_MASK) != (edgeErrMap[CE] & ERR_RETURN_MASK)) {
                updateReturnFlag(edgeErrMap[CE], IntFlag);
                EEP.emplace(std::make_pair(CE, IntFlag));
            }
        }
    }
}

/// Recursively mark all edges to the given block
void SecurityChecksPass::recurMarkEdgesToBlock(CFGEdge &CE, int flag,
                                               BBErrMap &bbErrMap, EdgeErrMap &edgeErrMap) {

    std::set<CFGEdge> PE;
    std::stack<std::pair<CFGEdge, int>> EEP;

    EEP.emplace(std::make_pair(CE, flag));
    while (!EEP.empty()) {

        std::pair<CFGEdge, int> TEP = EEP.top();
        EEP.pop();
        if (PE.count(TEP.first) != 0)
            continue;
        PE.insert(TEP.first);

        BasicBlock *TB = TEP.first.first->getParent();
        // No predecessors, stop
        if (pred_size(TB) == 0)
            continue;

        int IntFlag = TEP.second;
        // No impact to predecessor edges, so stop
        if (!(IntFlag & ERR_RETURN_MASK))
            continue;

        // If the current edge is May_Return_Err, all predecessor edges
        // become May_Return_Err
        if (IntFlag & May_Return_Err) {
            recurMarkEdgesToErrReturn(TB, May_Return_Err, edgeErrMap);
            continue;
        }

        // The current edge is Must_Return_Err
        // Integrate flags of all outgoing edges
        bool AllMust = true, AllZero = true;
        for (BasicBlock *Succ : successors(TB)) {
            if (Succ == TEP.first.second)
                continue;
            CFGEdge Edge = std::make_pair(TB->getTerminator(), Succ);
            //if (edgeErrMap.count(Edge) == 0) {
            //	edgeErrMap[Edge] = 0;
            //}
            if (!(edgeErrMap[Edge] & Must_Return_Err))
                AllMust = false;
            else if (edgeErrMap[Edge] & May_Return_Err) {
                AllMust = false;
                AllZero = false;
            }
            else {
                AllZero = false;
            }
            if (!AllZero && !AllMust) {
                break;
            }
        }
        if (AllMust) {
            IntFlag = Must_Return_Err;
            //markEdgesToErrReturn(TB, IntFlag, edgeErrMap);
            for (BasicBlock *predBB : predecessors(TB)) {
                Instruction *TI = predBB->getTerminator();
                CFGEdge CE = std::make_pair(TI, TB);
                if (!(edgeErrMap[CE] & IntFlag)) {
                    updateReturnFlag(edgeErrMap[CE], IntFlag);
                    EEP.emplace(std::make_pair(CE, IntFlag));
                }
            }
        }
        else if (!AllZero && !AllMust) {
            recurMarkEdgesToErrReturn(TB, May_Return_Err, edgeErrMap);
            continue;
        }
        else {
            // FIXME: may want to further track if the flag of predecessors
            // is zero, but this should a minor issue
            continue;
        }
    }
}

/// Recursively mark edges from the error-handling block to the
/// closest branches
void SecurityChecksPass::recurMarkEdgesToErrHandle(BasicBlock *BB,
                                                   EdgeErrMap &edgeErrMap) {
    // Invalid input.
    if (!BB)
        return;

    std::set<BasicBlock *> PB;
    std::stack<BasicBlock *> EB;

    EB.emplace(BB);
    while (!EB.empty()) {

        BasicBlock *TB = EB.top();
        EB.pop();
        if (PB.count(TB) != 0)
            continue;
        PB.insert(TB);
        // Iterate on each predecessor basic block.
        for (BasicBlock *predBB : predecessors(TB)) {
            Instruction *TI = predBB->getTerminator();
            CFGEdge CE = std::make_pair(TI, TB);
            int NewHandleFlag = Must_Handle_Err;
            if (edgeErrMap[CE] & NewHandleFlag)
                continue;
            updateHandleFlag(edgeErrMap[CE], NewHandleFlag);
            // reaches a branch, stop
            if (TI->getNumSuccessors() > 1)
                continue;
            EB.emplace(predBB);
        }
    }
}

/// Recursively mark edges to the error-returning block
void SecurityChecksPass::recurMarkEdgesToErrReturn(BasicBlock *BB,
                                                   int flag, EdgeErrMap &edgeErrMap) {

    if (!BB)
        return;

    std::set<BasicBlock *> PB;
    std::stack<BasicBlock *> EB;

    EB.emplace(BB);
    while (!EB.empty()) {

        BasicBlock *TB = EB.top();
        EB.pop();
        if (PB.count(TB) != 0)
            continue;
        PB.insert(TB);
        // Iterate on each predecessor basic block.
        for (BasicBlock *predBB : predecessors(TB)) {
            Instruction *TI = predBB->getTerminator();
            CFGEdge CE = std::make_pair(TI, TB);
            if ((edgeErrMap[CE] & ERR_RETURN_MASK) ==
                (flag & ERR_RETURN_MASK))
                continue;
            updateReturnFlag(edgeErrMap[CE], flag);
            EB.emplace(predBB);
        }
    }
}

/// Mark direct edges to the error-returning block
void SecurityChecksPass::markEdgesToErrReturn(BasicBlock *BB,
                                              int flag, EdgeErrMap &edgeErrMap) {

    // Iterate on each predecessor basic block.
    for (BasicBlock *predBB : predecessors(BB)) {
        Instruction *TI = predBB->getTerminator();
        CFGEdge CE = std::make_pair(TI, BB);
        if ((edgeErrMap[CE] & ERR_RETURN_MASK)
            == (flag & ERR_RETURN_MASK))
            continue;
        updateReturnFlag(edgeErrMap[CE], flag);
    }
}

/// Traverse the CFG to mark all edges with an error flag
bool SecurityChecksPass::markAllEdgesErrFlag(Function *F, BBErrMap &bbErrMap,
                                             EdgeErrMap &edgeErrMap) {

    if (bbErrMap.size() == 0)
        return false;

    // Recursively mark flags
    for (Function::iterator b = F->begin(), e = F->end();
         b != e; ++b) {

        BasicBlock *BB = &*b;

        // No error-related operations
        if (bbErrMap.count(BB) == 0)
            continue;

        // Upon error-related operations, update edges
        int NewFlag = bbErrMap[BB];
        // The only marking for error-handling cases
        if (NewFlag & Must_Handle_Err) {
            recurMarkEdgesToErrHandle(BB, edgeErrMap);
        }

        // Marking error-returning cases
        if ((NewFlag & ERR_RETURN_MASK)) {
            // First update all edges to the block
            // mark all predecessor edges with the flag
            for (BasicBlock *Pred : predecessors(BB)) {
                CFGEdge CE = std::make_pair(Pred->getTerminator(), BB);
                updateReturnFlag(edgeErrMap[CE], NewFlag);
                recurMarkEdgesToBlock(CE, NewFlag, bbErrMap, edgeErrMap);
            }
            // Then update all edges from the block
            for (BasicBlock *Succ : successors(BB)) {
                CFGEdge CE = std::make_pair(BB->getTerminator(), Succ);
                updateReturnFlag(edgeErrMap[CE], NewFlag);
                recurMarkEdgesFromBlock(CE, NewFlag, bbErrMap, edgeErrMap);
            }
        }
    }

    return true;
}

/// Efficiently but inprecisely check if the function may return an
/// error
bool SecurityChecksPass::mayReturnErr(Function *F) {

    std::set<Function *> PF;
    std::stack<Function *> EF;

    EF.emplace(F);

    while (!EF.empty()) {

        Function *TF = EF.top();
        EF.pop();

        if (PF.count(TF) != 0)
            continue;
        PF.insert(TF);

        if (TF->empty())
            continue;

        for (Function::iterator b = TF->begin(), e = TF->end();
             b != e; ++b) {
            BasicBlock *BB = &*b;
            for (BasicBlock::iterator I = BB->begin(),
                         IE = BB->end(); I != IE; ++I) {
                StoreInst *SI = dyn_cast<StoreInst>(&*I);
                if (SI) {
                    Value *SV = SI->getValueOperand();
                    if (isValueErrno(SV, TF)) {
                        return true;
                    }
                    continue;
                }
                CallInst *CI = dyn_cast<CallInst>(&*I);
                if (CI) {
                    Type * Ty= CI->getType();
                    if (Ty->isPointerTy())
                        return true;
                    Function *CF = CI->getCalledFunction();
                    if (!CF)
                        continue;
                    StringRef FName = getCalledFuncName(CI);
                    if (FName == "ERR_PTR" || FName == "PTR_ERR")
                        return true;
                    // Get the actual called function
                    if (Ctx->Callees[CI].size() == 0)
                        continue;
                    CF = *(Ctx->Callees[CI].begin());
                    if (CF) {
                        EF.emplace(CF);
                        continue;
                    }

                    continue;
                }
                ReturnInst *RI = dyn_cast<ReturnInst>(&*I);
                if (RI) {
                    Value *RV = RI->getReturnValue();
                    if (!RV)
                        continue;
                    if (CallInst *RCI = dyn_cast<CallInst>(RV)) {
                        if (Ctx->Callees[RCI].size() == 0)
                            continue;
                        Function *RF = *(Ctx->Callees[RCI].begin());
                        if (RF)
                            EF.emplace(RF);
                    }
                    continue;
                }
            }
        }
    }
    return false;
}

/// Check if the returned value must be or may be an errno.
/// And mark the traversed edges in the CFG.
void SecurityChecksPass::checkErrReturn(Function *F,
                                        BBErrMap &bbErrMap) {

    // Check all return instructions in this function and mark
    // edges that are sure to return an errno.
    std::set<Value *> PV;

    for (inst_iterator i = inst_begin(F), e = inst_end(F);
         i != e; ++i) {
        ReturnInst *RI = dyn_cast<ReturnInst>(&*i);

        if (!RI)
            continue;

        // Backtrack returned value
        checkErrValueFlow(F, RI, PV, bbErrMap);
    }

    return;
}

/// Find error handling code
void SecurityChecksPass::checkErrHandle(Function *F,
                                        BBErrMap &bbErrMap) {

    for (Function::iterator b = F->begin(), e = F->end();
         b != e; ++b) {
        BasicBlock *BB = &*b;
        for (BasicBlock::iterator I = BB->begin(),
                     IE = BB->end(); I != IE; ++I) {
            CallInst *CI = dyn_cast<CallInst>(&*I);
            if (CI) {
                StringRef FuncName = getCalledFuncName(CI);

                // For inline assembly code, just take the first substring
                // without a space
                if(FuncName.find(' ') != std::string::npos)
                    FuncName = FuncName.substr(0, FuncName.find(' '));

                string funcName = FuncName.str();
                auto FIter = Ctx->ErrorHandleFuncs.find(funcName); // TODO: let this use a string ref to avoid allocation?
                // The called function handles an error, so mark the edge
                if (FIter != Ctx->ErrorHandleFuncs.end()) {
                    markBBErr(BB, Must_Handle_Err, bbErrMap);
                    continue;
                }

                // Detect BUG, BUG_ON, WARN_ON more precisely
#ifdef ASM_FUNC
                if (FuncName.find("llvm") != std::string::npos || FuncName.empty())
					continue;

				smatch match;
				string line;
				getSourceCodeLine(CI, line);

				if (regex_search(line, match, pattern)) {
					auto FIter = Ctx->ErrorHandleFuncs.find(match[0].str());

					if (FIter != Ctx->ErrorHandleFuncs.end()) {
						markBBErr(BB, Must_Handle_Err, bbErrMap);
						continue;
					}
				}
#endif
            }
        }
    }
}

/// Traverse the CFG and find security checks.
void SecurityChecksPass::identifySecurityChecks(Function *F,
                                                EdgeErrMap &edgeErrMap) {

    BBErrMap bbErrMap;

    edgeErrMap.clear();

#ifdef TEST_CASE
    // Only test the specified functions
	if (F->getName() != "tfrc_li_init")
		return;
#endif

#ifdef DEBUG_PRINT
    OP << "\n== Working on function: "
		<< "\033[32m" << F->getName() << "\033[0m" << '\n';
#endif

    // Find and record basic blocks that set error returning code
    checkErrReturn(F, bbErrMap);

    // Find and record basic blocks that have error handling code
    checkErrHandle(F, bbErrMap);

    if (!bbErrMap.empty()) {
#ifdef DEBUG_PRINT
        OP << "\n\033[32m" << F->getName() <<
			"\033[0m may return or handle an error" << '\n';
#endif
    }

    // Mark edges in the CFG. It tells if an errno is sure or maybe returned
    // on this edge. The index is the edge, i.e., the terminator instruction and
    // the index of the successor of the terminator instruction. This data structure
    // may need to be promoted to SecurityChecksPass.
    markAllEdgesErrFlag(F, bbErrMap, edgeErrMap);

#ifdef DEBUG_PRINT
    dumpErrEdges(edgeErrMap);
#endif


    // Filtering
    if (edgeErrMap.empty() 	&&
        ErrSelectInstSet.empty())
        return;

    //
    // Find blocks that contain security checks by traversing the
    // marked CFG represented by edgeErrMap
    //
    for (inst_iterator i = inst_begin(F),
                 ei = inst_end(F); i != ei; ++i) {

        Instruction *Inst = &*i;
        Value *Cond = nullptr;

        // Case 1: branch instruction for checks
        // && case 2: switch instruction for checks
        if (isa<BranchInst>(Inst) || isa<SwitchInst>(Inst)) {

            BranchInst *BI = dyn_cast<BranchInst>(Inst);
            SwitchInst *SI = nullptr;
            if (BI) {
                if (BI->getNumSuccessors() < 2)
                    continue;
            }
            else {
                SI = dyn_cast<SwitchInst>(Inst);
                if (SI->getNumSuccessors() < 2)
                    continue;
            }


            BasicBlock *BB = Inst->getParent();
            int errFlag = 0;
            int NumMayErrReturn = 0, NumMustErrReturn = 0;
            int NumMayErrHandle = 0, NumMustErrHandle = 0;
            for (BasicBlock *Succ : successors(BB)) {
                errFlag = edgeErrMap[std::make_pair(Inst, Succ)];
                if (errFlag & Must_Return_Err)
                    ++NumMustErrReturn;
                else
                    ++NumMayErrReturn;

                if (errFlag & Must_Handle_Err)
                    ++NumMustErrHandle;
                else
                    ++NumMayErrHandle;
            }

            // Not a security check
            if (!(NumMustErrReturn && NumMayErrReturn)
                && !(NumMustErrHandle && NumMayErrHandle)) {
                continue;
            }
            // A security check
            if (BI)
                Cond = BI->getCondition();
            else
                Cond = SI->getCondition();
        }
            // Case 3: select instruction for checks
        else if (SelectInst *SI = dyn_cast<SelectInst>(Inst)) {
            if (ErrSelectInstSet.find(SI) == ErrSelectInstSet.end()) {
                continue;
            }
            // A security check
            Cond = SI->getCondition();
        }

        if (Cond) {
            addSecurityCheck(Cond, Inst);
#ifdef DEBUG_PRINT
            printSourceCodeInfo(Cond);
#endif
        }
    }
}

/// Collect all blocks operate on return value
void SecurityChecksPass::checkErrValueFlow(
        Function *F,
        ReturnInst *RI,
        std::set<Value *> &PV,
        BBErrMap &bbErrMap) {

    Value *RV = RI->getReturnValue();
    if (!RV)
        return;

    std::stack<EdgeValue> EEV;

    EEV.emplace(std::make_pair(std::make_pair(nullptr,
                                                RI->getParent()), RV));

    while (!EEV.empty()) {

        EdgeValue EV = EEV.top();
        Value *V = EV.second;
        EEV.pop();

        if (!V || PV.count(V) != 0)
            continue;
        PV.insert(V);
        Instruction *I = dyn_cast<Instruction>(V);
        if (!I)
            continue;
        // Current block
        BasicBlock *BB = I->getParent();

        // The value is a load. Let's find out the previous stores.
        if (auto LI = dyn_cast<LoadInst>(V)) {

            Value *LPO = LI->getPointerOperand();
            for (User *U : LPO->users()) {
                if (LI == U)
                    continue;
                StoreInst *SI = dyn_cast<StoreInst>(U);
                if (SI && LPO == SI->getPointerOperand()) {
                    Value *SVO = SI->getValueOperand();
                    if (isa<Constant>(SVO)) {
                        if (isValueErrno(SVO, F))
                            markBBErr(SI->getParent(), Must_Return_Err, bbErrMap);
                        else
                            // Maybe mark as Not_Return_Err
                            markBBErr(SI->getParent(), May_Return_Err, bbErrMap);
                    }
                    else {
                        CFGEdge	NE = make_pair(SI->getParent()->getTerminator(), BB);
                        EEV.emplace(make_pair(NE, SVO));
                    }
                }
            }
            continue;
        }

        // The value is a phinode.
        PHINode *PN = dyn_cast<PHINode>(V);
        if (PN) {
            // Check each incoming value.
            for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; ++i) {
                Value *IV = PN->getIncomingValue(i);
                BasicBlock *inBB = PN->getIncomingBlock(i);

                // The incoming value is a constant.
                if (isa<Constant>(IV)) {
                    if (isValueErrno(IV, F))
                        markBBErr(inBB, Must_Return_Err, bbErrMap);
                    else
                        markBBErr(inBB, May_Return_Err, bbErrMap);
                }
                else {
                    // Add the incoming value and the corresponding edge to the list.
                    Instruction *TI = inBB->getTerminator();
                    EEV.emplace(std::make_pair(std::make_pair(TI, BB), IV));
                }
            }
            continue;
        }

        // The value is a select instruction.
        SelectInst *SI = dyn_cast<SelectInst>(V);
        if (SI) {
            Value *SV;
            bool flag1 = false;
            bool flag2 = false;

            SV = SI->getTrueValue();
            if (isa<Constant>(SV)) {
                if(isValueErrno(SV, F))
                    flag1 = true;
            } else {
                EEV.emplace(std::make_pair(make_pair(SI->getParent()->getTerminator(), BB),
                                             SV));
            }

            SV = SI->getFalseValue();
            if (isa<Constant>(SV)) {
                if (isValueErrno(SV, F))
                    flag2 = true;
            } else {
                EEV.emplace(std::make_pair(make_pair(SI->getParent()->getTerminator(), BB),
                                             SV));
            }

            if (flag1 && flag2) {
                markBBErr(SI->getParent(), Must_Return_Err, bbErrMap);
            }
            else if (flag1 || flag2) {
                markBBErr(SI->getParent(), May_Return_Err, bbErrMap);
                // Only one branch in this case
                ErrSelectInstSet.insert(SI);
            }

            continue;
        }

        // The value is a getelementptr instruction.
        GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(V);
        if (GEP) {
            Value *PO = GEP->getPointerOperand();

            if (isa<Constant>(PO)) {
                if (isValueErrno(PO, F))
                    markBBErr(GEP->getParent(), Must_Return_Err, bbErrMap);
                else
                    markBBErr(GEP->getParent(), May_Return_Err, bbErrMap);
                continue;
            }
            EEV.emplace(std::make_pair(make_pair(GEP->getParent()->getTerminator(), BB),
                                         PO));

            continue;
        }

        // The value is a call instruction.
        CallInst *CaI = dyn_cast<CallInst>(V);
        if (CaI) {
            Function *CF = CaI->getCalledFunction();
            if (!CF)
                continue;
            StringRef FName = getCalledFuncName(CaI);
            // TODO: may need a list of must-return-error functions
#if ERRNO_TYPE == 2
            if (FName == "PTR_ERR" || FName == "ERR_PTR") {
                markBBErr(CaI->getParent(), Must_Return_Err, bbErrMap);
                continue;
            }
#endif
            auto FIter = Ctx->CopyFuncs.find(FName.str());
            if (FIter != Ctx->CopyFuncs.end()) {
                if (get<1>(FIter->second) == -1) {
                    Value *Arg =
                            CaI->getArgOperand(get<0>(FIter->second));
                    if (isValueErrno(Arg, F)) {
                        markBBErr(CaI->getParent(), Must_Return_Err, bbErrMap);
                        continue;
                    }
                    else {
                        EEV.emplace(make_pair(make_pair(
                                CaI->getParent()->getTerminator(), BB), Arg));
                        continue;
                    }
                }
            }
            // Get the actual called function
            if (Ctx->Callees[CaI].size() == 0)
                continue;
            CF = *(Ctx->Callees[CaI].begin());
            if (!CF)
                continue;
            if (mayReturnErr(CF)) {
                BasicBlock *CallBB = CaI->getParent();
                markBBErr(CallBB, May_Return_Err, bbErrMap);
                // FIXME: assume it will return an error
                // Assume an immediate check for the return value
                Instruction *TI = CallBB->getTerminator();
                if (TI->getNumSuccessors() > 1) {
                    // Decide if the branch condition is the return value
                    Instruction *Cond = nullptr;
                    if (BranchInst *BI = dyn_cast<BranchInst>(TI))
                        Cond = dyn_cast<Instruction>(BI->getCondition());
                    else if (SwitchInst *SI = dyn_cast<SwitchInst>(TI))
                        Cond = dyn_cast<Instruction>(SI->getCondition());
                    if (!Cond)
                        continue;
                    std::set<Value *>VSet;
                    findSameVariablesFrom(CaI, VSet);
                    bool Checked = false;
                    for (unsigned i = 0, ie = Cond->getNumOperands(); i < ie; i++) {
                        if (VSet.find(Cond->getOperand(i)) != VSet.end()) {
                            Checked = true;
                            break;
                        }
                    }
                    if (!Checked)
                        continue;

                    int BrId = inferErrBranch(Cond);
                    if (BranchInst *BI = dyn_cast<BranchInst>(TI)) {
                        markBBErr(BI->getSuccessor(BrId), Must_Return_Err, bbErrMap);
                    }
                    else if (SwitchInst *SI = dyn_cast<SwitchInst>(TI)) {
                        markBBErr(SI->getSuccessor(BrId), Must_Return_Err, bbErrMap);
                    }
                }
            }
            else {
                markBBErr(CaI->getParent(), May_Return_Err, bbErrMap);
            }
            continue;
        }

        // The value is a icmp instruction. Skip it.
        ICmpInst *ICI = dyn_cast<ICmpInst>(V);
        if (ICI)
            continue;

        // The value is a parameter of the fucntion. Skip it.
        if (isa<Argument>(V))
            continue;

        if (isa<Constant>(V))
            continue;

        // The value is an unary instruction.
        UnaryInstruction *UI = dyn_cast<UnaryInstruction>(V);
        if (UI) {
            Value *UO = UI->getOperand(0);
            if (isa<Constant>(UO)) {
                if (isValueErrno(UO, F))
                    markBBErr(UI->getParent(), Must_Return_Err, bbErrMap);
                else
                    markBBErr(UI->getParent(), May_Return_Err, bbErrMap);
                continue;
            }
            EEV.emplace(std::make_pair(make_pair(UI->getParent()->getTerminator(), BB),
                                         UO));

            continue;
        }

        // The value is a binary operator.
        BinaryOperator *BO = dyn_cast<BinaryOperator>(V);
        if (BO) {
            markBBErr(BO->getParent(), May_Return_Err, bbErrMap);
            continue;
        }

        // TODO: support more LLVM IR types.
#ifdef DEBUG_PRINT
        OP << "== Warning: unsupported LLVM IR:"
			<< *V << '\n';
		assert(0);
#endif

    }
}

//#define LOG_ADDED_CHECKS

/// Add the identified check to the set
void SecurityChecksPass::addSecurityCheck(Value *SC, Instruction *Br) {
    set<Value*> sources, visited;
    DFA.findSources(SC, sources, visited);

#ifdef LOG_ADDED_CHECKS
    bool shownHeader = false;
#endif

    for (const auto& source : sources) {
        FieldSourceSet fieldSourceSet;
        set<const Value*> trackedSet;
        findFields(*Br->getModule(), source, fieldSourceSet, trackedSet, true);

        for (auto field : fieldSourceSet) {
            shared_ptr<Field> fieldPtr = field;

#ifdef LOG_ADDED_CHECKS
            if (!shownHeader) {
                LOG(LOG_INFO, "Security sensitive fields found at: ");
                SourceLocation tmp(Br);
                tmp.dump(LOG_INFO);
                LOG(LOG_INFO, "\n");
                shownHeader = true;
            }

            LOG(LOG_INFO, "  ");
            fieldPtr->dump(LOG_INFO);
#endif
            Ctx->securityCriticalFields.emplace(move(fieldPtr));
        }
    }
}

/// Find same-origin variables from the given variable
void SecurityChecksPass::findSameVariablesFrom(Value *V,
                                               std::set<Value *> &VSet) {

    VSet.insert(V);
    std::set<Value *> PV;
    std::stack<Value *> EV;

    EV.emplace(V);

    while (!EV.empty()) {

        Value *TV = EV.top();
        EV.pop();
        if (PV.find(TV) != PV.end())
            continue;
        PV.insert(TV);

        for (User *U : TV->users()) {

            StoreInst *SI = dyn_cast<StoreInst>(U);
            if (SI && TV == SI->getValueOperand()) {
                for (User *SU : SI->getPointerOperand()->users()) {
                    LoadInst *LI = dyn_cast<LoadInst>(SU);
                    if (LI) {
                        VSet.insert(LI);
                        EV.emplace(LI);
                    }
                }
            }
        }
    }
}

/// Infer error-handling branch for a condition
int SecurityChecksPass::inferErrBranch(Instruction *Cond) {

    // TODO: determine the error-handling branch

    return 0;
}

bool SecurityChecksPass::doInitialization(Module *M) {
    return false;
}

bool SecurityChecksPass::doFinalization(Module *M) {
    ErrSelectInstSet.clear();

#if 1
    LOG(LOG_INFO, "Security critical fields:\n");
    for (const auto& field : Ctx->securityCriticalFields) {
        field->dump(LOG_INFO);
    }
#endif

    return false;
}

bool SecurityChecksPass::doModulePass(Module *M) {

    for(Module::iterator f = M->begin(), fe = M->end();
        f != fe; ++f) {
        Function *F = &*f;

        if (F->empty())
            continue;

        if (F->size() > MAX_BLOCKS_SUPPORT)
            continue;

        // TODO
        //if (Ctx->UnifiedFuncSet.find(F) == Ctx->UnifiedFuncSet.end())
        //    continue;

        // Marked CFG
        EdgeErrMap edgeErrMap;
        // Traverse the CFG and find security checks for each errno.
        identifySecurityChecks(F, edgeErrMap);
    } // End function iteration

    return false;
}
