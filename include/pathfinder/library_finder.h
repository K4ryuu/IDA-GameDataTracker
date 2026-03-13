/* pathfinder/library_finder.h - library func lookup */

#ifndef K4_TRACKER_LIBRARY_FINDER_H
#define K4_TRACKER_LIBRARY_FINDER_H

#include "core/types.h"
#include "core/index.h"

#include <ida.hpp>

namespace tracker {
namespace pathfinder {
namespace finders {

inline FinderResult find_by_library(const Anchor& anchor, const GlobalIndex& index) {
    FinderResult fr;
    fr.source = ModulePriority::LIBRARY;

    if (anchor.name.empty()) return fr;

    ea_t lib_ea = BADADDR;
    for (const auto& [ea, name] : index.library_names) {
        if (name == anchor.name) {
            lib_ea = ea;
            break;
        }
    }
    if (lib_ea == BADADDR) return fr;

    auto cit = index.callers.find(lib_ea);
    if (cit == index.callers.end() || cit->second.empty()) return fr;

    if (cit->second.size() == 1) {
        func_t* f = get_func(cit->second[0]);
        if (f && !index.library_funcs.count(f->start_ea)) {
            fr.candidate = f->start_ea;
            fr.detail = "library_single_caller: " + anchor.name;
        }
    }
    else if (cit->second.size() <= 3) {
        for (ea_t caller : cit->second) {
            if (!index.library_funcs.count(caller)) {
                func_t* f = get_func(caller);
                if (f) {
                    fr.candidate = f->start_ea;
                    fr.detail = "library_few_callers(" +
                        std::to_string(cit->second.size()) + "): " + anchor.name;
                    break;
                }
            }
        }
    }

    return fr;
}

} // namespace finders
} // namespace pathfinder
} // namespace tracker

#endif // K4_TRACKER_LIBRARY_FINDER_H
