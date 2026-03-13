/* pathfinder/xref_finder.h - shared data xref resolution */

#ifndef K4_TRACKER_XREF_FINDER_H
#define K4_TRACKER_XREF_FINDER_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <ida.hpp>
#include <funcs.hpp>

#include <unordered_set>

namespace tracker {
namespace pathfinder {
namespace finders {

inline std::vector<FinderResult> find_by_xref_all(const Anchor& anchor,
                                                     const GlobalIndex& index)
{
    std::vector<FinderResult> results;

    if (anchor.chain_depth == 0 || anchor.name.empty()) return results;

    ea_t landmark_ea = find_landmark_ea(anchor, index);
    if (landmark_ea == BADADDR) return results;

    std::unordered_set<ea_t> current_funcs = {landmark_ea};
    std::unordered_set<ea_t> all_visited = {landmark_ea};

    for (uint8_t d = 0; d < anchor.chain_depth; ++d) {
        std::unordered_set<ea_t> next_funcs;

        for (ea_t func_ea : current_funcs) {
            auto data_refs = collect_data_xrefs(func_ea);
            uint32_t ref_count = 0;
            for (ea_t data_ea : data_refs) {
                if (++ref_count > config::XREF_MAX_DATA_REFS) break;
                auto sharing = get_functions_referencing_data(data_ea);
                for (ea_t other : sharing) {
                    if (all_visited.insert(other).second) {
                        next_funcs.insert(other);
                    }
                }
            }
        }

        current_funcs = std::move(next_funcs);
        if (current_funcs.empty()) break;
        if (all_visited.size() > 500) break;
    }

    auto size_ok = [&](ea_t candidate_ea) -> bool {
        if (anchor.func_size == 0) return true;
        func_t* cf = get_func(candidate_ea);
        if (!cf) return false;
        uint32_t cand_size = static_cast<uint32_t>(cf->end_ea - cf->start_ea);
        uint32_t orig = anchor.func_size;
        uint32_t factor = (orig < 64) ? 4 : 2;
        uint32_t lo = orig / (factor + 1);
        uint32_t hi = orig * (factor + 1);
        return cand_size >= lo && cand_size <= hi;
    };

    for (ea_t candidate : current_funcs) {
        func_t* f = get_func(candidate);
        if (!f) continue;
        if (index.library_funcs.count(f->start_ea)) continue;
        if (!size_ok(f->start_ea)) continue;

        FinderResult fr;
        fr.source = ModulePriority::XREF;
        fr.candidate = f->start_ea;

        char buf[256];
        const char* lm_type = anchor.chain_landmark_type == 0 ? "str" :
                              anchor.chain_landmark_type == 1 ? "vt" :
                              anchor.chain_landmark_type == 2 ? "cv" : "dp";
        qsnprintf(buf, sizeof(buf), "xref(%s,d=%u): %s",
            lm_type, anchor.chain_depth, anchor.name.c_str());
        fr.detail = buf;
        results.push_back(fr);
    }

    return results;
}

} // namespace finders
} // namespace pathfinder
} // namespace tracker

#endif // K4_TRACKER_XREF_FINDER_H
