/* pathfinder/string_finder.h - string lookup */

#ifndef K4_TRACKER_STRING_FINDER_H
#define K4_TRACKER_STRING_FINDER_H

#include "core/types.h"
#include "core/index.h"

#include <ida.hpp>
#include <funcs.hpp>

#include <cstdlib>

namespace tracker {
namespace pathfinder {
namespace finders {

inline FinderResult find_by_string(const Anchor& anchor, const GlobalIndex& index) {
    FinderResult fr;
    fr.source = ModulePriority::UNIQUE_STR;

    if (anchor.name.empty()) return fr;

    auto it = index.string_to_funcs.find(anchor.name);
    if (it == index.string_to_funcs.end() || it->second.empty()) return fr;

    size_t ref_count = it->second.size();

    if (ref_count == 1) {
        fr.candidate = it->second[0];
        fr.detail = "unique_string: " + anchor.name;
        return fr;
    }

    if (ref_count > config::MAX_RARE_STRING_REFS) return fr;

    if (anchor.rva > 0) {
        uint32_t expected_size = static_cast<uint32_t>(anchor.rva);
        ea_t best = BADADDR;
        uint32_t best_diff = UINT32_MAX;
        int count_close = 0;

        for (ea_t fea : it->second) {
            func_t* f = get_func(fea);
            if (!f) continue;
            uint32_t actual_size = static_cast<uint32_t>(f->end_ea - f->start_ea);
            uint32_t diff = (expected_size > actual_size)
                ? expected_size - actual_size
                : actual_size - expected_size;

            if (diff <= expected_size * 30 / 100) {
                count_close++;
                if (diff < best_diff) {
                    best_diff = diff;
                    best = fea;
                }
            }
        }

        if (ref_count <= 3 && best != BADADDR) {
            fr.candidate = best;
            fr.detail = "rare_string(" + std::to_string(ref_count)
                + (count_close == 1 ? ",unique_size" : ",best_size")
                + "): " + anchor.name;
            return fr;
        }

        if (count_close == 1 && best != BADADDR) {
            fr.candidate = best;
            fr.detail = "rare_string(" + std::to_string(ref_count) + "): " + anchor.name;
            return fr;
        }
    }

    return fr;
}

} // namespace finders
} // namespace pathfinder
} // namespace tracker

#endif // K4_TRACKER_STRING_FINDER_H
