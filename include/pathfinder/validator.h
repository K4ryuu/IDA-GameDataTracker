/* pathfinder/validator.h - identity gate + reinforcement scoring */

#ifndef K4_TRACKER_VALIDATOR_H
#define K4_TRACKER_VALIDATOR_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include "crawler/base.h"  // For analyze_identity / analyze_reinforcement

#include <ida.hpp>
#include <funcs.hpp>

#include <cstdlib>

namespace tracker {
namespace pathfinder {

// Identity gate

inline bool identity_matches(const Identity& expected, const Identity& actual,
                             const char** fail_reason = nullptr)
{
    // return type must match
    if (!expected.return_type.empty() && !actual.return_type.empty()) {
        if (expected.return_type != actual.return_type) {
            bool exp_ptr = expected.return_type.back() == '*';
            bool act_ptr = actual.return_type.back() == '*';
            if (!(exp_ptr && act_ptr)) {
                if (fail_reason) *fail_reason = "return_type";
                return false;
            }
        }
    }

    if (expected.param_count > 0 && actual.param_count > 0) {
        int diff = static_cast<int>(expected.param_count) - static_cast<int>(actual.param_count);
        if (diff < 0) diff = -diff;
        if (diff > config::IDENTITY_PARAM_TOLERANCE) {
            if (fail_reason) *fail_reason = "param_count";
            return false;
        }
    }

    // switch is soft now, compilers optimize differently

    return true;
}

// Reinforcement score (0.0-1.0)

inline float reinforcement_score(const Reinforcement& expected, const Reinforcement& actual,
                                 const Identity& expected_id, const Identity& actual_id)
{
    float score = 0.0f;
    float total = 0.0f;

    if (expected.size > 0 && actual.size > 0) {
        uint32_t diff = (expected.size > actual.size)
            ? expected.size - actual.size
            : actual.size - expected.size;
        uint32_t pct_tolerance = expected.size * config::SIZE_TOLERANCE_PCT / 100;
        uint32_t tolerance = (pct_tolerance > config::MIN_SIZE_TOLERANCE_ABS)
            ? pct_tolerance : config::MIN_SIZE_TOLERANCE_ABS;
        if (diff <= tolerance) {
            score += 1.0f - static_cast<float>(diff) / static_cast<float>(tolerance);
        } else {
            float overshoot = static_cast<float>(diff - tolerance) / static_cast<float>(tolerance);
            score -= std::min(overshoot, 1.0f);
        }
        total += 1.0f;
    }

    if (expected.bb_count > 0 && actual.bb_count > 0) {
        int diff = std::abs(static_cast<int>(expected.bb_count) - static_cast<int>(actual.bb_count));
        if (diff <= config::BB_COUNT_TOLERANCE) {
            score += 1.0f - static_cast<float>(diff) / static_cast<float>(config::BB_COUNT_TOLERANCE);
        } else {
            float overshoot = static_cast<float>(diff - config::BB_COUNT_TOLERANCE)
                / static_cast<float>(config::BB_COUNT_TOLERANCE);
            score -= std::min(overshoot, 1.0f);
        }
        total += 1.0f;
    }

    if (expected.cyclomatic > 0 && actual.cyclomatic > 0) {
        int diff = std::abs(static_cast<int>(expected.cyclomatic) - static_cast<int>(actual.cyclomatic));
        if (diff <= config::CYCLOMATIC_TOLERANCE) {
            score += 1.0f - static_cast<float>(diff) / static_cast<float>(config::CYCLOMATIC_TOLERANCE);
        } else {
            float overshoot = static_cast<float>(diff - config::CYCLOMATIC_TOLERANCE)
                / static_cast<float>(config::CYCLOMATIC_TOLERANCE);
            score -= std::min(overshoot, 1.0f);
        }
        total += 1.0f;
    }

    if (expected.caller_count > 0 && actual.caller_count > 0) {
        uint32_t diff = (expected.caller_count > actual.caller_count)
            ? expected.caller_count - actual.caller_count
            : actual.caller_count - expected.caller_count;
        uint32_t tolerance = expected.caller_count * config::CALLER_TOLERANCE_PCT / 100;
        if (tolerance > 0 && diff <= tolerance) {
            score += 1.0f - static_cast<float>(diff) / static_cast<float>(tolerance);
        }
        total += 1.0f;
    }

    if (expected.callee_count > 0 && actual.callee_count > 0) {
        uint32_t diff = (expected.callee_count > actual.callee_count)
            ? expected.callee_count - actual.callee_count
            : actual.callee_count - expected.callee_count;
        uint32_t tolerance = expected.callee_count * config::CALLEE_TOLERANCE_PCT / 100;
        if (tolerance > 0 && diff <= tolerance) {
            score += 1.0f - static_cast<float>(diff) / static_cast<float>(tolerance);
        }
        total += 1.0f;
    }

    {
        uint32_t exp_f = expected_id.struct_flags;
        uint32_t act_f = actual_id.struct_flags;
        uint32_t all_f = exp_f | act_f;
        if (all_f != 0) {
            uint32_t common_f = exp_f & act_f;
            uint32_t common_n = 0, all_n = 0;
            for (uint32_t bit = 1; bit <= all_f; bit <<= 1) {
                if (all_f & bit) all_n++;
                if (common_f & bit) common_n++;
            }
            if (all_n > 0) {
                score += static_cast<float>(common_n) / static_cast<float>(all_n);
            }
            total += 1.0f;
        }
    }

    if (!expected.constants.empty() && !actual.constants.empty()) {
        size_t i = 0, j = 0;
        uint32_t common = 0;
        while (i < expected.constants.size() && j < actual.constants.size()) {
            if (expected.constants[i] == actual.constants[j]) {
                common++;
                i++; j++;
            } else if (expected.constants[i] < actual.constants[j]) {
                i++;
            } else {
                j++;
            }
        }
        size_t total_unique = expected.constants.size() + actual.constants.size() - common;
        if (total_unique > 0) {
            score += static_cast<float>(common) / static_cast<float>(total_unique);
        }
        total += 1.0f;
    }

    {
        if (expected_id.has_switch == actual_id.has_switch) {
            score += 1.0f;
        }
        total += 1.0f;
    }

    return total > 0.0f ? score / total : 0.0f;
}

// Validate candidate

struct ValidationResult {
    bool identity_ok = false;
    float reinforcement = 0.0f;
    const char* identity_fail_reason = nullptr;
};

inline ValidationResult validate_candidate(ea_t candidate_ea,
                                           const Identity& expected_id,
                                           const Reinforcement& expected_rf,
                                           GlobalIndex& index)
{
    // cache hit?
    auto cit = index.validation_cache.find(candidate_ea);
    if (cit != index.validation_cache.end()) {
        ValidationResult vr;
        vr.identity_ok = cit->second.identity_ok;
        vr.reinforcement = cit->second.reinforcement;
        vr.identity_fail_reason = cit->second.fail_reason;
        return vr;
    }

    ValidationResult vr;
    Identity actual_id;
    Reinforcement actual_rf;

    // try pre-fetched metadata
    auto mit = index.func_metadata.find(candidate_ea);
    if (mit != index.func_metadata.end()) {
        actual_id = mit->second.identity;
        actual_rf = mit->second.reinforcement;
    } else {
        // fallback (NOT thread-safe)
        actual_id = base::analyze_identity(candidate_ea);
        actual_rf = base::analyze_reinforcement(candidate_ea, index);
    }

    vr.identity_ok = identity_matches(expected_id, actual_id, &vr.identity_fail_reason);

    // stubs vs real funcs are different beasts
    if (vr.identity_ok && expected_rf.size > 0 && actual_rf.size > 0) {
        bool exp_tiny = expected_rf.size <= 16;
        bool act_tiny = actual_rf.size <= 16;
        if (exp_tiny != act_tiny) {
            vr.identity_ok = false;
            vr.identity_fail_reason = "tiny_size_mismatch";
        } else if (exp_tiny && act_tiny) {
            uint32_t larger = (expected_rf.size > actual_rf.size) ? expected_rf.size : actual_rf.size;
            uint32_t smaller = (expected_rf.size < actual_rf.size) ? expected_rf.size : actual_rf.size;
            if (smaller > 0 && larger > smaller * 2) {
                vr.identity_ok = false;
                vr.identity_fail_reason = "tiny_size_mismatch";
            }
        }
    }

    vr.reinforcement = reinforcement_score(expected_rf, actual_rf, expected_id, actual_id);

    index.validation_cache[candidate_ea] = { vr.identity_ok, vr.reinforcement, vr.identity_fail_reason };

    return vr;
}

} // namespace pathfinder
} // namespace tracker

#endif // K4_TRACKER_VALIDATOR_H
