#pragma once

// Configuration flags for lock analysis
#define SPLIT_LOCKS_INTO_ALL_PARTS
#define TRY_TO_RECOVER_TYPE_INFORMATION
//#define TEST_CASE_FIND_LOCK_FIELDS
//#define DISPLAY_FOUND_WRAPPERS_FOR_LOCKERS
//#define DISPLAY_FOUND_WRAPPERS_FOR_UNLOCKERS
//#define DUMP_BB_COVERS
//#define DUMP_ALLOC_AND_FREE_FUNCTIONS
//#define PRINT_SYSCALL_IF_THERE_ARE
#define SYSCALL_DISCOVERY_MAX_DEPTH 50
#define MAX_WRAPPER_BB_SIZE 20
//#define GET_GLOBALS
//#define LOG_ADDING_OF_WRAPPER
//#define SHOW_TYPE_ADDRESSES // Used for debugging, prints the address of types when dumping fields as {0xptr}
//#define ASSERT_FOR_CYCLES // Used for debugging, asserts there are no cycles when appending fields
//#define DUMP_LOCK_TYPES // Used for debugging
//#define DUMP_STORE_CALL_TEST
//#define COUNT_HOW_MANY_TIMES_FP_RECHECK_IS_DETECTED
//#define TRACK_WHICH_FUNCTIONS_CONTAIN_VIOLATIONS
