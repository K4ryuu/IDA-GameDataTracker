/* pathfinder/proximity_finder.h - neighbor delta matching */

#ifndef K4_TRACKER_PROXIMITY_FINDER_H
#define K4_TRACKER_PROXIMITY_FINDER_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <ida.hpp>
#include <funcs.hpp>

#include <cstdlib>

namespace tracker {
namespace pathfinder {
namespace finders {

inline FinderResult find_by_proximity(const Anchor& anchor, const GlobalIndex& index) {
    FinderResult fr;
    fr.source = ModulePriority::PROXIMITY;

    if (anchor.name.empty()) return fr;

    auto it = index.string_to_funcs.find(anchor.name);
    if (it == index.string_to_funcs.end() || it->second.size() != 1) return fr;

    ea_t neighbor_ea = it->second[0];

    int64_t delta = static_cast<int64_t>(anchor.rva);

    ea_t predicted = static_cast<ea_t>(static_cast<int64_t>(neighbor_ea) + delta);

    func_t* f = get_func(predicted);
    if (f) {
        fr.candidate = f->start_ea;
    } else {
        ea_t search_start = (predicted > config::PROXIMITY_DELTA_TOLERANCE)
            ? predicted - config::PROXIMITY_DELTA_TOLERANCE : 0;
        ea_t search_end = predicted + config::PROXIMITY_DELTA_TOLERANCE;

        ea_t best = BADADDR;
        uint64_t best_dist = UINT64_MAX;

        func_t* fn = get_next_func(search_start);
        while (fn && fn->start_ea < search_end) {
            uint64_t dist = (fn->start_ea > predicted)
                ? fn->start_ea - predicted
                : predicted - fn->start_ea;
            if (dist < best_dist) {
                best_dist = dist;
                best = fn->start_ea;
            }
            fn = get_next_func(fn->start_ea);
        }

        if (best != BADADDR) {
            fr.candidate = best;
        }
    }

    if (fr.candidate != BADADDR) {
        char detail_buf[128];
        qsnprintf(detail_buf, sizeof(detail_buf), "proximity: neighbor=%s delta=%lld",
            anchor.name.c_str(), (long long)delta);
        fr.detail = detail_buf;
    }

    return fr;
}

} // namespace finders
} // namespace pathfinder
} // namespace tracker

#endif // K4_TRACKER_PROXIMITY_FINDER_H
