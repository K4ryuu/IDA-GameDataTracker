/*
 * core/types.h - types & structs
 */

#ifndef K4_TRACKER_TYPES_H
#define K4_TRACKER_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

#include <ida.hpp>

namespace tracker {

//=============================================================================
// Priority tiers
//=============================================================================

enum class ModulePriority : uint8_t {
    SIGNATURE  = 0,   // Strongest — direct byte pattern match
    UNIQUE_STR = 1,   // Very strong — string unique to one function
    CONVAR     = 2,   // Strong — ConVar registration name
    VTABLE     = 3,   // Structural — stable inheritance hierarchy
    LIBRARY    = 4,   // Medium — library call (stable but not unique)
    RELATIONAL = 5,   // Medium — caller/callee with signature
    DATA_PTR   = 6,   // Weak — RVA-based, shifts with binary layout
    PROXIMITY  = 7,   // Weakest — neighbor hint via shared string
    CALLCHAIN  = 8,   // Call-graph traversal to landmark function
    XREF       = 9,   // Shared data xref to landmark function
};

inline const char* priority_name(ModulePriority p) {
    switch (p) {
        case ModulePriority::SIGNATURE:  return "SIGNATURE";
        case ModulePriority::UNIQUE_STR: return "UNIQUE_STR";
        case ModulePriority::CONVAR:     return "CONVAR";
        case ModulePriority::VTABLE:     return "VTABLE";
        case ModulePriority::LIBRARY:    return "LIBRARY";
        case ModulePriority::RELATIONAL: return "RELATIONAL";
        case ModulePriority::DATA_PTR:   return "DATA_PTR";
        case ModulePriority::PROXIMITY:  return "PROXIMITY";
        case ModulePriority::CALLCHAIN: return "CALLCHAIN";
        case ModulePriority::XREF:      return "XREF";
        default: return "UNKNOWN";
    }
}

//=============================================================================
// Sig pattern + wildcard mask
//=============================================================================

struct Signature {
    std::vector<uint8_t> bytes;
    std::vector<bool> mask;      // true = fixed byte, false = wildcard
    uint32_t offset = 0;         // Offset from function start

    bool empty() const { return bytes.empty(); }
    size_t length() const { return bytes.size(); }

    // IDA-style pattern string: "55 48 89 E5 ? ? ? ? 41 57"
    std::string to_ida() const {
        std::string result;
        result.reserve(bytes.size() * 3);
        for (size_t i = 0; i < bytes.size(); ++i) {
            if (i > 0) result += ' ';
            if (mask[i]) {
                char buf[4];
                qsnprintf(buf, sizeof(buf), "%02X", bytes[i]);
                result += buf;
            } else {
                result += '?';
            }
        }
        return result;
    }

    // Gamedata-style: "\x55\x48\x89\xE5\x2A\x2A"
    std::string to_gamedata() const {
        std::string result;
        result.reserve(bytes.size() * 4);
        for (size_t i = 0; i < bytes.size(); ++i) {
            if (mask[i]) {
                char buf[8];
                qsnprintf(buf, sizeof(buf), "\\x%02X", bytes[i]);
                result += buf;
            } else {
                result += "\\x2A";
            }
        }
        return result;
    }
};

//=============================================================================
// Identity — stable structural traits
//=============================================================================

//=============================================================================
// Structural bitflags
//=============================================================================

namespace identity_flags {
    static constexpr uint32_t HAS_LOOP        = 1 << 0;  // Backward conditional branch
    static constexpr uint32_t HAS_FLOAT_OPS   = 1 << 1;  // Scalar float (movss/addss/etc)
    static constexpr uint32_t HAS_SIMD        = 1 << 2;  // Packed SIMD (movaps/addps/etc)
    static constexpr uint32_t HAS_DIV         = 1 << 3;  // div/idiv instruction
    static constexpr uint32_t HAS_MUL         = 1 << 4;  // imul instruction
    static constexpr uint32_t HAS_LARGE_STACK = 1 << 5;  // Stack frame > 256 bytes
    static constexpr uint32_t HAS_REP_OPS     = 1 << 6;  // rep movsb/stosb/etc
    static constexpr uint32_t HAS_CMOV        = 1 << 7;  // Conditional move instructions
}

struct Identity {
    std::string return_type;              // "int", "void*", "CBaseEntity*"
    std::vector<std::string> param_types; // ["CBaseEntity*", "int", "float"]
    uint8_t param_count = 0;
    bool has_return = false;
    bool has_indirect_call = false;       // Contains call via register/memory
    bool has_switch = false;              // Contains switch/jump table
    uint32_t struct_flags = 0;            // Bitflags (identity_flags::*)
};

//=============================================================================
// Reinforcement — soft validation data
//=============================================================================

struct Reinforcement {
    uint32_t size = 0;                    // Function size in bytes
    uint16_t bb_count = 0;               // Basic block count
    uint16_t cyclomatic = 0;             // Cyclomatic complexity
    uint32_t caller_count = 0;           // How many functions call this
    uint32_t callee_count = 0;           // How many functions this calls
    std::vector<std::string> strings;    // Internal strings (for validation, not anchoring)
    std::vector<uint64_t> constants;     // Notable immediate values (sorted, deduped)
};

//=============================================================================
// Anchor — single trackable reference
//=============================================================================

struct Anchor {
    ModulePriority priority;              // Which module found this
    std::string name;                     // String / vtable name / library name / convar
    Signature signature;                  // Byte pattern (signature module, relational)
    uint32_t index = 0;                   // VTable slot / string ref count
    uint32_t vtable_size = 0;             // VTable slot count (vtable module)
    uint32_t vtable_neighbor_before = 0;  // Func size at slot [index-1] (0 if none/first)
    uint32_t vtable_neighbor_after = 0;   // Func size at slot [index+1] (0 if none/last)
    uint64_t rva = 0;                     // Relative virtual address (data_ptr, vtable)
    uint32_t fanout = 0;                  // Caller+callee count of anchor func
    ea_t resolved_ea = BADADDR;           // What the anchor points to in current binary

    // Call-chain / xref traversal fields (CALLCHAIN, XREF modules)
    uint8_t chain_depth = 0;              // How many hops to reach landmark (0 = direct)
    uint8_t chain_directions = 0;         // Bitmask per hop: bit=0 → caller, bit=1 → callee
    uint8_t chain_landmark_type = 0;      // 0=string, 1=vtable, 2=convar, 3=data_ptr
    uint32_t func_size = 0;               // Tracked function's byte size (for size filtering in finder)
};

//=============================================================================
// CrawlResult
//=============================================================================

struct CrawlResult {
    Identity identity;
    Reinforcement reinforcement;
    std::vector<Anchor> anchors;
};

//=============================================================================
// MatchVerdict
//=============================================================================

enum class MatchVerdict : uint8_t {
    NONE      = 0,   // Not found
    AMBIGUOUS = 1,   // Multiple candidates, not resolvable
    MATCH     = 2,   // Reliable match
};

inline const char* verdict_name(MatchVerdict v) {
    switch (v) {
        case MatchVerdict::NONE:      return "NONE";
        case MatchVerdict::AMBIGUOUS: return "AMBIGUOUS";
        case MatchVerdict::MATCH:     return "MATCH";
        default: return "UNKNOWN";
    }
}

//=============================================================================
// FinderResult
//=============================================================================

struct FinderResult {
    ea_t candidate = BADADDR;        // Found function address
    ModulePriority source;           // Which finder produced this
    std::string detail;              // e.g. "unique_string: PLAYER_ANIM_SYNC"
};

//=============================================================================
// MatchResult
//=============================================================================

struct MatchResult {
    MatchVerdict verdict = MatchVerdict::NONE;
    ea_t matched_ea = BADADDR;
    std::string method;              // Which finder(s) matched
    uint32_t votes = 0;             // How many finders agreed
    uint32_t structural = 0;        // Structural verifications (VTABLE_OK, DATAPTR_OK, etc.)
    bool identity_passed = false;    // Passed identity gate?
    float reinforcement_score = 0;   // 0.0-1.0, soft property match ratio
};

//=============================================================================
// TrackedFunc
//=============================================================================

struct TrackedFunc {
    std::string name;
    ea_t original_ea = BADADDR;

    // Crawler output
    Identity identity;
    Reinforcement reinforcement;
    std::vector<Anchor> anchors;

    // Dual signatures (export + tracking)
    Signature export_sig;
    Signature tracking_sig;
    uint8_t prologue_length = 0;

    // byte offset from func start to sig target (0 = normal, >0 = mid-func)
    int32_t sig_offset = 0;

    // instruction types around target (for mid-func refinement)
    std::vector<uint16_t> mid_context;

    // VTable tracking (for offset-based gamedata entries)
    std::string vtable_class;     // e.g., "CBaseEntity" — empty if not vtable-based
    int32_t vtable_offset = -1;   // Original vtable slot index, -1 = not vtable-based

    // Match state (pathfinder fills this)
    MatchResult match;
};

} // namespace tracker

#endif // K4_TRACKER_TYPES_H
