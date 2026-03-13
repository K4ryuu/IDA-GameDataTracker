/* crawler/xref_module.h - shared data xref anchors */

#ifndef K4_TRACKER_XREF_MODULE_H
#define K4_TRACKER_XREF_MODULE_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <unordered_set>

namespace tracker {
namespace modules {
namespace xref_mod {

// Reuse landmark detection from callchain module
using callchain_mod::LandmarkInfo;
using callchain_mod::detect_landmark;

inline std::vector<Anchor> collect(ea_t fea, const GlobalIndex& index) {
    std::vector<Anchor> anchors;

    uint32_t tracked_size = 0;
    func_t* tracked_f = get_func(fea);
    if (tracked_f) tracked_size = static_cast<uint32_t>(tracked_f->end_ea - tracked_f->start_ea);

    auto data_refs = collect_data_xrefs(fea);
    if (data_refs.empty()) return anchors;

    if (data_refs.size() > config::XREF_MAX_DATA_REFS) {
        data_refs.resize(config::XREF_MAX_DATA_REFS);
    }

    std::unordered_set<ea_t> visited_funcs;
    visited_funcs.insert(fea);

    std::unordered_set<ea_t> current_frontier;

    for (ea_t data_ea : data_refs) {
        auto sharing_funcs = get_functions_referencing_data(data_ea);
        for (ea_t other_fea : sharing_funcs) {
            if (other_fea == fea) continue;
            if (visited_funcs.insert(other_fea).second) {
                current_frontier.insert(other_fea);
            }
        }
    }

    for (uint8_t depth = 1; depth <= config::XREF_MAX_DEPTH; ++depth) {
        if (current_frontier.empty()) break;
        if (anchors.size() >= config::XREF_MAX_ANCHORS) break;

        std::unordered_set<ea_t> next_frontier;

        for (ea_t frontier_ea : current_frontier) {
            if (anchors.size() >= config::XREF_MAX_ANCHORS) break;

            LandmarkInfo lm = detect_landmark(frontier_ea, index);
            if (!lm.name.empty()) {
                Anchor a;
                a.priority = ModulePriority::XREF;
                a.name = lm.name;
                a.chain_depth = depth;
                a.chain_directions = 0;  // Xref chains don't have caller/callee direction
                a.chain_landmark_type = lm.type;
                a.fanout = index.get_fanout(frontier_ea);
                a.func_size = tracked_size;
                a.resolved_ea = frontier_ea;
                anchors.push_back(a);
                continue;  // Don't expand from landmarks
            }

            // Expand to next depth only if not too deep
            if (depth < config::XREF_MAX_DEPTH) {
                auto next_data_refs = collect_data_xrefs(frontier_ea);
                uint32_t ref_count = 0;
                for (ea_t data_ea : next_data_refs) {
                    if (++ref_count > config::XREF_MAX_DATA_REFS) break;
                    auto sharing_funcs = get_functions_referencing_data(data_ea);
                    for (ea_t other_fea : sharing_funcs) {
                        if (visited_funcs.insert(other_fea).second) {
                            next_frontier.insert(other_fea);
                        }
                    }
                }
            }
        }

        current_frontier = std::move(next_frontier);
    }

    std::sort(anchors.begin(), anchors.end(), [](const Anchor& a, const Anchor& b) {
        if (a.chain_depth != b.chain_depth) return a.chain_depth < b.chain_depth;
        return a.chain_landmark_type < b.chain_landmark_type;
    });

    if (anchors.size() > config::XREF_MAX_ANCHORS) {
        anchors.resize(config::XREF_MAX_ANCHORS);
    }

    return anchors;
}

} // namespace xref_mod
} // namespace modules
} // namespace tracker

#endif // K4_TRACKER_XREF_MODULE_H
