/* pathfinder/data_ptr_finder.h - .data pointer search */

#ifndef K4_TRACKER_DATA_PTR_FINDER_H
#define K4_TRACKER_DATA_PTR_FINDER_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <ida.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <name.hpp>

namespace tracker {
namespace pathfinder {
namespace finders {

inline std::vector<FinderResult> find_by_data_ptr_all(const Anchor& anchor,
                                                       const GlobalIndex& index)
{
    std::vector<FinderResult> results;

    if (anchor.rva == 0 || anchor.name.empty()) return results;

    ea_t expected_ea = BADADDR;

    for (int i = 0; i < get_segm_qty(); ++i) {
        segment_t* seg = getnseg(i);
        if (!seg) continue;
        qstring sname;
        get_segm_name(&sname, seg);

        bool match = (sname == anchor.name.c_str());
        if (!match) {
            std::string s1 = sname.c_str();
            if (s1.find(".data") != std::string::npos &&
                anchor.name.find(".data") != std::string::npos)
                match = true;
        }
        if (!match) continue;

        ea_t candidate_ea = seg->start_ea + anchor.rva;
        if (candidate_ea >= seg->start_ea && candidate_ea < seg->end_ea) {
            expected_ea = candidate_ea;
            break;
        }
    }

    if (expected_ea == BADADDR) return results;

    uint32_t tolerance = config::DATA_PTR_SECTION_TOLERANCE;
    ea_t search_start = (expected_ea > tolerance)
        ? expected_ea - tolerance : get_imagebase();
    ea_t search_end = expected_ea + tolerance;

    struct CandidateInfo {
        ea_t ptr_ea;
        ea_t func_ea;
        uint64_t dist;
    };
    std::vector<CandidateInfo> candidates;

    for (const auto& [ptr_ea, func_ea] : index.data_func_ptrs) {
        if (ptr_ea < search_start || ptr_ea > search_end) continue;

        func_t* f = get_func(func_ea);
        if (!f) continue;
        if (index.library_funcs.count(f->start_ea)) continue;

        uint64_t dist = (ptr_ea > expected_ea)
            ? ptr_ea - expected_ea : expected_ea - ptr_ea;
        candidates.push_back({ptr_ea, f->start_ea, dist});
    }

    std::sort(candidates.begin(), candidates.end(),
        [](const CandidateInfo& a, const CandidateInfo& b) {
            return a.dist < b.dist;
        });

    std::unordered_set<ea_t> seen_funcs;
    for (const auto& ci : candidates) {
        if (!seen_funcs.insert(ci.func_ea).second) continue;

        FinderResult fr;
        fr.source = ModulePriority::DATA_PTR;
        fr.candidate = ci.func_ea;

        char detail_buf[128];
        qsnprintf(detail_buf, sizeof(detail_buf), "data_ptr: %s+0x%llX (delta=%lld)",
            anchor.name.c_str(),
            (unsigned long long)anchor.rva,
            (long long)(static_cast<int64_t>(ci.ptr_ea) - static_cast<int64_t>(expected_ea)));
        fr.detail = detail_buf;

        results.push_back(std::move(fr));
        if (results.size() >= config::DATA_PTR_CAL_MAX_CANDIDATES) break;
    }

    return results;
}

// Delta calibration from matched funcs

inline int64_t calibrate_data_ptr_delta(const std::vector<TrackedFunc>& funcs,
                                         const GlobalIndex& index)
{
    std::vector<int64_t> deltas;

    for (const auto& tf : funcs) {
        if (tf.match.verdict != MatchVerdict::MATCH) continue;

        for (const auto& anchor : tf.anchors) {
            if (anchor.priority != ModulePriority::DATA_PTR) continue;
            if (anchor.rva == 0 || anchor.name.empty()) continue;

            for (const auto& [ptr_ea, func_ea] : index.data_func_ptrs) {
                if (func_ea != tf.match.matched_ea) continue;

                segment_t* seg = getseg(ptr_ea);
                if (!seg) continue;
                qstring sname;
                get_segm_name(&sname, seg);
                if (sname != anchor.name.c_str()) continue;

                int64_t new_rva = static_cast<int64_t>(ptr_ea - seg->start_ea);
                int64_t old_rva = static_cast<int64_t>(anchor.rva);
                deltas.push_back(new_rva - old_rva);
                break;
            }
        }
    }

    if (deltas.empty()) return 0;

    std::sort(deltas.begin(), deltas.end());
    return deltas[deltas.size() / 2];
}

// Calibrated search with delta offset

inline std::vector<FinderResult> find_by_data_ptr_calibrated_all(
    const Anchor& anchor,
    const GlobalIndex& index,
    int64_t delta)
{
    std::vector<FinderResult> results;

    if (anchor.rva == 0 || anchor.name.empty()) return results;

    ea_t expected_ea = BADADDR;

    for (int i = 0; i < get_segm_qty(); ++i) {
        segment_t* seg = getnseg(i);
        if (!seg) continue;
        qstring sname;
        get_segm_name(&sname, seg);

        bool match = (sname == anchor.name.c_str());
        if (!match) {
            std::string s1 = sname.c_str();
            if (s1.find(".data") != std::string::npos &&
                anchor.name.find(".data") != std::string::npos)
                match = true;
        }
        if (!match) continue;

        int64_t adjusted_rva = static_cast<int64_t>(anchor.rva) + delta;
        if (adjusted_rva >= 0 &&
            static_cast<uint64_t>(adjusted_rva) < (seg->end_ea - seg->start_ea)) {
            expected_ea = seg->start_ea + static_cast<ea_t>(adjusted_rva);
            break;  // Found valid expected position
        }
    }

    if (expected_ea == BADADDR) return results;

    uint32_t tolerance = config::DATA_PTR_CAL_TOLERANCE;
    ea_t search_start = (expected_ea > tolerance)
        ? expected_ea - tolerance : get_imagebase();
    ea_t search_end = expected_ea + tolerance;

    struct CandidateInfo {
        ea_t ptr_ea;
        ea_t func_ea;
        uint64_t dist;
    };
    std::vector<CandidateInfo> candidates;

    for (const auto& [ptr_ea, func_ea] : index.data_func_ptrs) {
        if (ptr_ea < search_start || ptr_ea > search_end) continue;

        func_t* f = get_func(func_ea);
        if (!f) continue;
        if (index.library_funcs.count(f->start_ea)) continue;

        uint64_t dist = (ptr_ea > expected_ea)
            ? ptr_ea - expected_ea : expected_ea - ptr_ea;
        candidates.push_back({ptr_ea, f->start_ea, dist});
    }

    std::sort(candidates.begin(), candidates.end(),
        [](const CandidateInfo& a, const CandidateInfo& b) {
            return a.dist < b.dist;
        });

    std::unordered_set<ea_t> seen_funcs;
    for (const auto& ci : candidates) {
        if (!seen_funcs.insert(ci.func_ea).second) continue;

        FinderResult fr;
        fr.source = ModulePriority::DATA_PTR;
        fr.candidate = ci.func_ea;

        char detail_buf[160];
        qsnprintf(detail_buf, sizeof(detail_buf),
            "data_ptr_cal: %s+0x%llX+delta(%lld) (residual=%lld)",
            anchor.name.c_str(),
            (unsigned long long)anchor.rva,
            (long long)delta,
            (long long)(static_cast<int64_t>(ci.ptr_ea) - static_cast<int64_t>(expected_ea)));
        fr.detail = detail_buf;

        results.push_back(std::move(fr));
    }

    return results;
}

} // namespace finders
} // namespace pathfinder
} // namespace tracker

#endif // K4_TRACKER_DATA_PTR_FINDER_H
