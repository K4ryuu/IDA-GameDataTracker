/*
 * core/config.h - tunables
 */

#ifndef K4_TRACKER_CONFIG_H
#define K4_TRACKER_CONFIG_H

#include <cstdint>
#include <cstring>

namespace tracker {
namespace config {

//=============================================================================
// Module limits
//=============================================================================

static constexpr uint32_t MAX_ITEMS_PER_MODULE = 5;

//=============================================================================
// Signature generation
//=============================================================================

static constexpr uint32_t MIN_SIGNATURE_LENGTH = 8;    // Minimum unique bytes
static constexpr uint32_t MAX_PROLOGUE_SKIP = 24;      // Max prologue bytes to skip
static constexpr uint32_t MIN_FUNC_SIZE_FOR_SKIP = 40; // Don't skip prologue on tiny funcs

//=============================================================================
// String filtering
//=============================================================================

static constexpr uint32_t MIN_STRING_LENGTH = 8;             // Minimum string anchor length
static constexpr uint32_t MIN_PROXIMITY_STRING_LENGTH = 10;  // Proximity needs longer strings
static constexpr uint32_t MAX_RARE_STRING_REFS = 5;          // 2-5 refs = "rare"

//=============================================================================
// Relational filtering
//=============================================================================

static constexpr uint32_t MAX_RELATIONAL_FANOUT = 10;  // Only low-fanout funcs as anchors

//=============================================================================
// Proximity / Neighbor
//=============================================================================

static constexpr uint32_t MAX_NEIGHBOR_DISTANCE = 0x40000;  // ±256KB search radius

//=============================================================================
// stuff that makes terrible anchors
//=============================================================================

inline bool is_anti_anchor_name(const char* name) {
    if (!name || !name[0]) return false;

    static constexpr const char* patterns[] = {
        "memcpy", "memset", "memmove", "memcmp",
        "malloc", "calloc", "realloc", "free",
        "printf", "sprintf", "snprintf", "fprintf",
        "strlen", "strcpy", "strncpy", "strcmp", "strcat",
        "operator new", "operator delete",
        "__cxa_", "__gxx_",
        "_Znw", "_Zdl", "_Zna", "_Zda"  // Mangled new/delete
    };

    for (const char* p : patterns) {
        // Substring match
        const char* found = strstr(name, p);
        if (found) return true;
    }

    return false;
}

//=============================================================================
// Identity gate
//=============================================================================

static constexpr int IDENTITY_PARAM_TOLERANCE = 2;   // ±2 param count difference allowed

//=============================================================================
// Reinforcement scoring
//=============================================================================

static constexpr uint32_t SIZE_TOLERANCE_PCT = 30;    // ±30% function size
static constexpr uint32_t MIN_SIZE_TOLERANCE_ABS = 4;  // Minimum absolute size tolerance (bytes)
static constexpr int BB_COUNT_TOLERANCE = 3;          // ±3 basic blocks
static constexpr int CYCLOMATIC_TOLERANCE = 4;        // ±4 cyclomatic complexity
static constexpr uint32_t CALLER_TOLERANCE_PCT = 50;  // ±50% caller count
static constexpr uint32_t CALLEE_TOLERANCE_PCT = 50;  // ±50% callee count

//=============================================================================
// Voting
//=============================================================================

static constexpr uint32_t MIN_CONSENSUS_VOTES = 2;    // Minimum finders for consensus match
static constexpr uint32_t MIN_ANY_VOTES = 3;          // ≥3 any finders = consensus

//=============================================================================
// Proximity
//=============================================================================

static constexpr uint32_t PROXIMITY_DELTA_TOLERANCE = 0x2000;  // ±8KB delta shift tolerance

//=============================================================================
// VTable finder
//=============================================================================

static constexpr uint32_t VTABLE_SLOT_BASE_TOLERANCE = 10; // Base ± slots when exact slot fails
static constexpr uint32_t MAX_CANDIDATE_TRIES = 5;         // Max candidates to identity-check

//=============================================================================
// Data pointer finder
//=============================================================================

static constexpr uint32_t DATA_PTR_SECTION_TOLERANCE = 0x80000;  // ±512KB section-relative tolerance
static constexpr uint32_t DATA_PTR_CAL_TOLERANCE = 0x40000;      // ±256KB for delta-calibrated search
static constexpr float    DATA_PTR_CAL_MIN_RF = 0.55f;           // Min reinforcement for solo calibrated match
static constexpr uint32_t DATA_PTR_CAL_MAX_CANDIDATES = 30;      // Max candidates to try (closest first)

//=============================================================================
// Tiebreaker
//=============================================================================

static constexpr float RF_TIEBREAKER_MIN_DIFF = 0.3f;  // Min rf score gap to break runner-up tie

//=============================================================================
// Mid-func context
//=============================================================================

static constexpr uint16_t MID_CONTEXT_NONE = 0xFFFF;     // No-instruction sentinel (padding)
static constexpr uint32_t MID_CONTEXT_RADIUS = 5;         // 5 before + target + 5 after = 11
static constexpr uint32_t MID_CONTEXT_MIN_SCORE = 6;      // Minimum matches to accept (out of 11)

//=============================================================================
// Call-chain module
//=============================================================================

static constexpr uint32_t CALLCHAIN_MAX_DEPTH = 6;      // Max BFS depth through call graph
static constexpr uint32_t CALLCHAIN_MAX_ANCHORS = 5;    // Max chain anchors per function
static constexpr uint32_t CALLCHAIN_MAX_VISIT = 500;    // Max functions to visit in BFS

//=============================================================================
// Xref module
//=============================================================================

static constexpr uint32_t XREF_MAX_DEPTH = 4;           // Max BFS depth through data xrefs
static constexpr uint32_t XREF_MAX_ANCHORS = 3;         // Max xref anchors per function
static constexpr uint32_t XREF_MAX_DATA_REFS = 20;      // Max data refs to follow per function

} // namespace config
} // namespace tracker

#endif // K4_TRACKER_CONFIG_H
