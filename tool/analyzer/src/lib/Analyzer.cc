//===-- Analyzer.cc - the kernel-analysis framework--------------===//
//
// This file implements the analysis framework. It calls the pass for
// building call-graph and the pass for finding security checks.
//
// ===-----------------------------------------------------------===//

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/Signals.h"
#include <llvm/Support/ThreadPool.h>

#include "Analyzer.h"
#include "CallGraph.h"
#include "PointerAnalysis.h"
#include "LockChecker.h"
#include "SecurityChecks.h"
#include "TypeRemapperPass.h"
#include "ClOptForward.h"

// Command line parameters.
cl::list<string> InputFilenames(
    cl::Positional, cl::OneOrMore, cl::desc("<input bitcode files>"));

cl::opt<int> VerboseLevel(
    "verbose-level", cl::desc("Print information at which verbose level"),
    cl::init(0));

cl::opt<bool> LockChecksIPC(
		"ip-c",
		cl::desc("Enable inter-procedural analysis for determining lock covers"),
		cl::NotHidden, cl::init(true));

cl::opt<float> LockChecksThreshold(
		"t",
		cl::desc("Lock check threshold between [0, 1]"),
		cl::NotHidden, cl::init(0.15f));

cl::opt<float> LockChecksLowerThreshold(
		"lt",
		cl::desc("Lock check lower threshold between [0, 1]"),
		cl::NotHidden, cl::init(0.0f));

cl::opt<int> LockInterproceduralDepth(
		"d",
		cl::desc("Lock check inter-procedural depth"),
		cl::NotHidden, cl::init(4));

cl::opt<string> GitBlameRepoPath(
		"blame",
		cl::desc("Display the git blame for the offending line"),
		cl::NotHidden, cl::init(string {}));

cl::opt<string> ConfigPath(
		"config",
		cl::desc("The path to the configuration directory relative to the executable"),
		cl::NotHidden, cl::init("configs/linux"));

cl::opt<bool> IgnoreVolatile(
		"ignore-volatile",
		cl::desc("Ignore volatile loads & stores (READ_ONCE & WRITE_ONCE macros use these)"),
		cl::NotHidden, cl::init(true));

cl::opt<bool> DumpLockingCounts(
		"dump-locking-counts",
		cl::desc("Show locking and not locking counts, which can help understand the inferred rules and help debugging"),
		cl::NotHidden, cl::init(false));

cl::opt<bool> FilterFpRecheck(
		"filter-recheck",
		cl::desc("Filter cases where a check occurs without a lock if it also rechecks under the required lock."),
		cl::NotHidden, cl::init(true));

cl::opt<string> SyscallNamePrefix(
		"syscall-name-prefix",
		cl::desc("The prefix of syscall function names"),
		cl::NotHidden, cl::init("__do_sys_"));

cl::opt<unsigned int> PathsPrintLimit(
		"path-print-limit",
		cl::desc("The maximum amount of lines to print when printing paths"),
		cl::NotHidden, cl::init(5));

cl::opt<unsigned int> ThreadCount(
        "c",
        cl::desc("The amount of threads to use"),
        cl::NotHidden, cl::init(2));

cl::opt<bool> DetectLockAssertionViolations(
        "asserts",
        cl::desc("Detect lock assertion violations (such as violations against lockdep_assert_held in Linux)"),
        cl::NotHidden, cl::init(false));

cl::opt<bool> FindReadOnlyWriteViolations(
        "wv",
        cl::desc("Find violations caused by store instructions that are done on a struct protected by a read-only lock"),
        cl::NotHidden, cl::init(false));

cl::opt<bool> SecurityChecks(
        "sc",
        cl::desc("Filter the violations by only considering fields used in security checks"),
        cl::NotHidden, cl::init(false));

cl::opt<bool> FilterInitAndCleanup(
        "filter-init-cleanup",
        cl::desc("Filter initialisation and cleanup operations from violations"),
        cl::NotHidden, cl::init(true));

cl::opt<bool> FilterLikelyConcurrencySafeFunctions(
        "filter-likely-concurrency-safe-functions",
        cl::desc("Filter likely concurrency safe functions from sinks"),
        cl::NotHidden, cl::init(true));

cl::opt<bool> RequireFieldToBeStoredOrUnsafeUsedInACallUnderALock(
        "require-fields-to-be-stored-or-unsafe-used-in-a-call-under-a-lock",
        cl::desc("Require the fields to be stored or used unsafe in a call under a lock: proof it needs to be protected from concurrency."),
        cl::NotHidden, cl::init(true));

cl::opt<bool> FilterContext(
		"filter-context",
		cl::desc("Filter context"),
		cl::NotHidden, cl::init(true));

cl::opt<MLTAMode> MLTA(
        "mlta-mode",
        cl::desc("Sets in which mode MLTA runs"),
        cl::values(
                clEnumVal(NoIndirectCalls, "No indirect call analysis"),
                clEnumVal(MatchSignatures, "Consider all matching type signatures as possible call targets"),
                clEnumVal(FullMLTA, "Full MLTA implementation")
        ),
        cl::NotHidden, cl::init(FullMLTA)
);

GlobalContext GlobalCtx;


void IterativeModulePass::run(ModuleList &modules) {

  ModuleList::iterator i, e;
  OP << "[" << ID << "] Initializing " << modules.size() << " modules ";
  bool again = true;
  while (again) {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      again |= doInitialization(i->first);
      OP << ".";
    }
  }
  OP << "\n";

  unsigned iter = 0, changed = 1;
  while (changed) {
    ++iter;
    changed = 0;
    unsigned counter_modules = 0;
    unsigned total_modules = modules.size();
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      OP << "[" << ID << " / " << iter << "] ";
      OP << "[" << ++counter_modules << " / " << total_modules << "] ";
      OP << "[" << i->second << "]\n";

      bool ret = doModulePass(i->first);
      if (ret) {
        ++changed;
        OP << "\t [CHANGED]\n";
      } else
        OP << "\n";
    }
    OP << "[" << ID << "] Updated in " << changed << " modules.\n";
  }

  OP << "[" << ID << "] Postprocessing ...\n";
  again = true;
  while (again) {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      again |= doFinalization(i->first);
    }
  }

  OP << "[" << ID << "] Done!\n\n";
}
// Setup functions that handle errors
[[maybe_unused]] static void SetErrorHandleFuncs(set<string> &ErrorHandleFuncs) {
	string exepath = sys::fs::getMainExecutable(nullptr, nullptr);
	string exedir = exepath.substr(0, exepath.find_last_of('/'));
	string line;
	ifstream errfile(exedir + "/" + ConfigPath + "/err-funcs");
	if (errfile.is_open()) {
		while (!errfile.eof()) {
			getline (errfile, line);
			if (line.length() > 1) {
				ErrorHandleFuncs.insert(line);
			}
		}
		errfile.close();
	}

	string ErrorHandleFN[] = {
		"BUG",
		"BUG_ON",
		"ASM_BUG",
		"panic",
		"ASSERT",
		"assert",
		"dump_stack",
		"__warn_printk",
		"usercopy_warn",
		"signal_fault",
		"pr_err",
		"pr_warn",
		"pr_warning",
		"pr_alert",
		"pr_emerg",
		"pr_crit",
	};
	for (auto& F : ErrorHandleFN) {
		ErrorHandleFuncs.insert(F);
	}
}

// Setup functions that copy/move/cast values.
static void SetCopyFuncs(
		// <src, dst, size>
		map<string, tuple<int8_t, int8_t, int8_t>> &CopyFuncs) {

	CopyFuncs["memcpy"] = make_tuple(1, 0, 2);
	CopyFuncs["__memcpy"] = make_tuple(1, 0, 2);
	CopyFuncs["llvm.memcpy.p0i8.p0i8.i32"] = make_tuple(1, 0, 2);
	CopyFuncs["llvm.memcpy.p0i8.p0i8.i64"] = make_tuple(1, 0, 2);
	CopyFuncs["strncpy"] = make_tuple(1, 0, 2);
	CopyFuncs["memmove"] = make_tuple(1, 0, 2);
	CopyFuncs["__memmove"] = make_tuple(1, 0, 2);
	CopyFuncs["llvm.memmove.p0i8.p0i8.i32"] = make_tuple(1, 0, 2);
	CopyFuncs["llvm.memmove.p0i8.p0i8.i64"] = make_tuple(1, 0, 2);
}


void LoadStaticData(GlobalContext *GCtx) {
    // Note: this is needed for the security check pass!

	// Load error-handling functions
	SetErrorHandleFuncs(GCtx->ErrorHandleFuncs);
	// load functions that copy/move values
	SetCopyFuncs(GCtx->CopyFuncs);
}

void loadModule(const char* argv[], unsigned i, mutex* modulesVectorMutex) {
	SMDiagnostic Err;
	auto LLVMCtx = new LLVMContext();
	unique_ptr<Module> M = parseIRFile(InputFilenames[i], Err, *LLVMCtx);

	if (!M) {
		OP << argv[0] << ": error loading file '" << InputFilenames[i] << "': " << Err.getMessage() << "\n";
		return;
	}

	Module *Module = M.release();
#if 0
	OP << "Amount of instructions in " << InputFilenames[i] << ": " << Module->getInstructionCount() << "\n";
#endif
	StringRef MName(strdup(InputFilenames[i].data()));
	lock_guard _(*modulesVectorMutex);
	GlobalCtx.Modules.push_back(make_pair(Module, MName));
}

int main(int argc, const char *argv[]) {

	const auto time_start{std::chrono::steady_clock::now()};

	// Print a stack trace if we signal out.
	sys::PrintStackTraceOnErrorSignal(argv[0]);
	PrettyStackTraceProgram X(argc, argv);

	llvm_shutdown_obj Y;  // Call llvm_shutdown() on exit.

	cl::ParseCommandLineOptions(argc, argv, "global analysis\n");
	SMDiagnostic Err;

	// Loading modules
	mutex modulesVectorMutex;
	ThreadPool loadPool;
	for (unsigned i = 0; i < InputFilenames.size(); ++i) {
		loadPool.async(&loadModule, argv, i, &modulesVectorMutex);
	}
	loadPool.wait();

	// Main workflow
	LoadStaticData(&GlobalCtx);

#if 0
    PointerAnalysisPass PPass(&GlobalCtx);
    PPass.run(GlobalCtx.Modules);
#endif

    TypeRemapperPass TRPass(&GlobalCtx);
    TRPass.run(GlobalCtx.Modules);

#if 0
    PointerAnalysisPass PAP(&GlobalCtx);
    PAP.run(GlobalCtx.Modules);
#endif

    if (SecurityChecks) {
        SecurityChecksPass SCPass(&GlobalCtx);
        SCPass.run(GlobalCtx.Modules);
    }

	CallGraphPass CGPass(&GlobalCtx);
	CGPass.run(GlobalCtx.Modules);

	LockCheckerPass LPass(&GlobalCtx);
	{
		vector<Function *> functions;
		for (auto &[M, _] : GlobalCtx.Modules) {
			for (auto &F : *M) {
				functions.push_back(&F);
			}
		}
		LPass.doInitialization(functions);
		LPass.run(functions);
	}

	const auto time_end{std::chrono::steady_clock::now()};
	const std::chrono::duration<double> elapsed_seconds{time_end - time_start};
	std::cout << "Elapsed seconds: " << std::chrono::duration_cast<std::chrono::seconds>(elapsed_seconds).count() << "s\n";

	return 0;
}

