set (AnalyzerSourceCodes
	Common.h
	Common.cc
	Analyzer.h
	Analyzer.cc
	CallGraph.h
	CallGraph.cc
	ClOptForward.h
	Field.cc
	Field.h
	PointerAnalysis.h
	PointerAnalysis.cc
	DataFlowAnalysis.h
	DataFlowAnalysis.cc
	Helpers.h
	Helpers.cc
	DebugHelpers.h
	DebugHelpers.cc
	ViolationFinder.h
	ViolationFinder.cc
	Lazy.h
	LockChecker.h
	LockChecker.cc
	LockStyles.h
	SecurityChecks.cc
	SecurityChecks.h
	TypeRemapperPass.cc
	TypeRemapperPass.h
	WrapperFinder.cc
	WrapperFinder.h
	)

file(COPY configs/ DESTINATION configs)

set(CMAKE_MACOSX_RPATH 0)

# Build libraries.
add_library (AnalyzerObj OBJECT ${AnalyzerSourceCodes})
#add_library (Analyzer SHARED $<TARGET_OBJECTS:AnalyzerObj>)
add_library (AnalyzerStatic STATIC $<TARGET_OBJECTS:AnalyzerObj>)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

# Build executable.
set (EXECUTABLE_OUTPUT_PATH ${ANALYZER_BINARY_DIR})
link_directories (${ANALYZER_BINARY_DIR}/lib)
add_executable(kanalyzer ${AnalyzerSourceCodes})
target_link_libraries(kanalyzer 
	LLVMAsmParser 
	LLVMSupport 
	LLVMCore 
	LLVMAnalysis
	LLVMIRReader
	AnalyzerStatic
	)
