#pragma once

#include <llvm/Support/CommandLine.h>

enum MLTAMode {
    NoIndirectCalls,
    MatchSignatures,
    FullMLTA
};

extern cl::opt<bool> LockChecksIPC;
extern cl::opt<float> LockChecksThreshold;
extern cl::opt<float> LockChecksLowerThreshold;
extern cl::opt<int> LockInterproceduralDepth;
extern cl::opt<string> GitBlameRepoPath;
extern cl::opt<string> ConfigPath;
extern cl::opt<bool> IgnoreVolatile;
extern cl::opt<bool> DumpLockingCounts;
extern cl::opt<bool> FilterFpRecheck;
extern cl::opt<string> SyscallNamePrefix;
extern cl::opt<unsigned int> PathsPrintLimit;
extern cl::opt<unsigned int> ThreadCount;
extern cl::opt<bool> DetectLockAssertionViolations;
extern cl::opt<bool> FindReadOnlyWriteViolations;
extern cl::opt<bool> SecurityChecks;
extern cl::opt<bool> FilterInitAndCleanup;
extern cl::opt<bool> FilterLikelyConcurrencySafeFunctions;
extern cl::opt<bool> RequireFieldToBeStoredOrUnsafeUsedInACallUnderALock;
extern cl::opt<MLTAMode> MLTA;
extern cl::opt<bool> FilterContext;

struct GlobalContext;
extern GlobalContext GlobalCtx;
