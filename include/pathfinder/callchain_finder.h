/* pathfinder/callchain_finder.h - call-chain reversal */

#ifndef K4_TRACKER_CALLCHAIN_FINDER_H
#define K4_TRACKER_CALLCHAIN_FINDER_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <ida.hpp>
#include <funcs.hpp>

#include <unordered_set>

namespace tracker {
namespace pathfinder {
namespace finders {

// Find landmark in new binary
inline ea_t find_landmark_ea(const Anchor& anchor, const GlobalIndex& index) {
    switch (anchor.chain_landmark_type) {
        case 0: {
            auto it = index.string_to_funcs.find(anchor.name);
            if (it != index.string_to_funcs.end() && it->second.size() == 1) {
                return it->second[0];
            }
            if (it != index.string_to_funcs.end() && it->second.size() <= 5) {
                return it->second[0];
            }
            break;
        }
        case 1: {
            size_t bracket = anchor.name.find('[');
            if (bracket == std::string::npos) break;
            std::string class_name = anchor.name.substr(0, bracket);
            uint32_t slot = static_cast<uint32_t>(
                std::strtoul(anchor.name.c_str() + bracket + 1, nullptr, 10));

            for (const auto& [vtname, vt] : index.vtables) {
                std::string norm_dem = !vt.demangled.empty()
                    ? normalize_vtable_name(vt.demangled) : "";
                bool match = (!norm_dem.empty() && norm_dem == class_name)
                          || (vtname == class_name);
                if (!match) continue;

                if (slot < vt.slots.size()) {
                    func_t* f = get_func(vt.slots[slot]);
                    if (f) return f->start_ea;
                }
                break;
            }
            break;
        }
        case 2: {
            ensure_convar_index_for_name(anchor.name);
            auto it = index.convar_name_to_funcs.find(anchor.name);
            if (it != index.convar_name_to_funcs.end() && !it->second.empty()) {
                return it->second[0];
            }
            break;
        }
        case 3: {
            const char* str = anchor.name.c_str();
            char* colon = nullptr;
            uint64_t old_rva = strtoull(str, &colon, 0);
            uint32_t lm_size = 0;
            if (colon && *colon == ':') {
                lm_size = static_cast<uint32_t>(strtoul(colon + 1, nullptr, 10));
            }

            ea_t approx_ea = get_imagebase() + old_rva;
            ea_t best_func = BADADDR;
            int64_t best_dist = INT64_MAX;

            for (const auto& [ptr_ea, func_ea] : index.data_func_ptrs) {
                segment_t* seg = getseg(ptr_ea);
                if (!seg) continue;
                qstring sn;
                get_segm_name(&sn, seg);
                if (sn.find(".data") == qstring::npos) continue;

                if (lm_size > 0) {
                    func_t* cf = get_func(func_ea);
                    if (cf) {
                        uint32_t cs = static_cast<uint32_t>(cf->end_ea - cf->start_ea);
                        if (cs < lm_size / 4 || cs > lm_size * 4) continue;
                    }
                }

                int64_t dist = static_cast<int64_t>(ptr_ea) - static_cast<int64_t>(approx_ea);
                if (dist < 0) dist = -dist;
                if (dist < best_dist) {
                    best_dist = dist;
                    best_func = func_ea;
                }
            }

            if (best_func != BADADDR && best_dist < config::DATA_PTR_SECTION_TOLERANCE) {
                return best_func;
            }
            break;
        }
    }
    return BADADDR;
}

// Reverse-walk chain

inline std::vector<FinderResult> find_by_callchain_all(const Anchor& anchor,
                                                         const GlobalIndex& index)
{
    std::vector<FinderResult> results;

    if (anchor.chain_depth == 0 || anchor.name.empty()) return results;

    ea_t landmark_ea = find_landmark_ea(anchor, index);
    if (landmark_ea == BADADDR) return results;

    std::unordered_set<ea_t> current_set = {landmark_ea};

    for (int hop = anchor.chain_depth - 1; hop >= 0; --hop) {
        if (current_set.empty()) break;

        bool original_was_callee = (anchor.chain_directions >> hop) & 1;

        std::unordered_set<ea_t> next_set;
        for (ea_t ea : current_set) {
            if (original_was_callee) {
                auto it = index.callers.find(ea);
                if (it != index.callers.end()) {
                    for (ea_t caller : it->second) {
                        next_set.insert(caller);
                    }
                }
            } else {
                auto it = index.callees.find(ea);
                if (it != index.callees.end()) {
                    for (ea_t callee : it->second) {
                        next_set.insert(callee);
                    }
                }
            }
        }
        current_set = std::move(next_set);

        if (current_set.size() > 200) break;
    }

    auto size_ok = [&](ea_t candidate_ea) -> bool {
        if (anchor.func_size == 0) return true;  // No size info — accept all
        func_t* cf = get_func(candidate_ea);
        if (!cf) return false;
        uint32_t cand_size = static_cast<uint32_t>(cf->end_ea - cf->start_ea);
        uint32_t orig = anchor.func_size;
        uint32_t factor = (orig < 64) ? 4 : 2;
        uint32_t lo = orig / (factor + 1);
        uint32_t hi = orig * (factor + 1);
        return cand_size >= lo && cand_size <= hi;
    };

    for (ea_t candidate : current_set) {
        func_t* f = get_func(candidate);
        if (!f) continue;
        if (index.library_funcs.count(f->start_ea)) continue;
        if (!size_ok(f->start_ea)) continue;

        FinderResult fr;
        fr.source = ModulePriority::CALLCHAIN;
        fr.candidate = f->start_ea;

        char buf[256];
        const char* lm_type = anchor.chain_landmark_type == 0 ? "str" :
                              anchor.chain_landmark_type == 1 ? "vt" :
                              anchor.chain_landmark_type == 2 ? "cv" : "dp";
        qsnprintf(buf, sizeof(buf), "callchain(%u,%s,d=%u): %s",
            anchor.chain_landmark_type, lm_type,
            anchor.chain_depth,
            anchor.name.c_str());
        fr.detail = buf;
        results.push_back(fr);
    }

    return results;
}

} // namespace finders
} // namespace pathfinder
} // namespace tracker

#endif // K4_TRACKER_CALLCHAIN_FINDER_H
