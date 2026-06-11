#pragma once

enum class LockAcquisitionStyle : unsigned char {
    Conditional,
    Unconditional,
};

enum class LockAccessStyle : unsigned char {
    ReadOnly,
    ReadWrite,
};
