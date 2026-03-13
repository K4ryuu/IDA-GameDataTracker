/* crawler/proximity_module.h - neighbor hint anchors */

#ifndef K4_TRACKER_PROXIMITY_MODULE_H
#define K4_TRACKER_PROXIMITY_MODULE_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <ida.hpp>
#include <funcs.hpp>

#include <algorithm>
#include <cstdlib>

namespace tracker {
namespace modules {
namespace proximity_mod {

inline std::vector<Anchor> collect(ea_t fea, const GlobalIndex& index) {
    std::vector<Anchor> anchors;

    ea_t search_start = (fea > config::MAX_NEIGHBOR_DISTANCE)
                        ? fea - config::MAX_NEIGHBOR_DISTANCE : 0;
    ea_t search_end = fea + config::MAX_NEIGHBOR_DISTANCE;

    struct Candidate {
        std::string unique_str;
        int64_t delta;
        uint32_t neighbor_size;
    };
    std::vector<Candidate> candidates;

    for (const auto& [str, funcs] : index.string_to_funcs) {
        if (funcs.size() != 1) continue;  // Only unique strings
        if (str.length() < config::MIN_PROXIMITY_STRING_LENGTH) continue;

        ea_t neighbor_ea = funcs[0];
        if (neighbor_ea == fea) continue;
        if (neighbor_ea < search_start || neighbor_ea > search_end) continue;

        func_t* nf = get_func(neighbor_ea);
        if (!nf) continue;

        candidates.push_back({
            str,
            static_cast<int64_t>(fea) - static_cast<int64_t>(neighbor_ea),
            static_cast<uint32_t>(nf->end_ea - nf->start_ea)
        });
    }

    std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
        return std::abs(a.delta) < std::abs(b.delta);
    });

    size_t limit = std::min(candidates.size(), static_cast<size_t>(config::MAX_ITEMS_PER_MODULE));
    for (size_t i = 0; i < limit; ++i) {
        Anchor a;
        a.priority = ModulePriority::PROXIMITY;
        a.name = candidates[i].unique_str;
        a.rva = static_cast<uint64_t>(candidates[i].delta);  // Store delta as rva
        a.index = candidates[i].neighbor_size;                // Store neighbor size
        a.resolved_ea = fea;
        anchors.push_back(a);
    }

    return anchors;
}

} // namespace proximity_mod
} // namespace modules
} // namespace tracker

#endif // K4_TRACKER_PROXIMITY_MODULE_H
