/* pathfinder/convar_finder.h - ConVar lookup */

#ifndef K4_TRACKER_CONVAR_FINDER_H
#define K4_TRACKER_CONVAR_FINDER_H

#include "core/types.h"
#include "core/index.h"

#include <ida.hpp>

namespace tracker {
namespace pathfinder {
namespace finders {

inline FinderResult find_by_convar(const Anchor& anchor, const GlobalIndex& index) {
    FinderResult fr;
    fr.source = ModulePriority::CONVAR;

    if (anchor.name.empty()) return fr;

    ensure_convar_index_for_name(anchor.name);

    auto it = index.convar_name_to_funcs.find(anchor.name);
    if (it == index.convar_name_to_funcs.end() || it->second.empty()) return fr;

    if (it->second.size() == 1) {
        fr.candidate = it->second[0];
        fr.detail = "convar: " + anchor.name;
    }

    return fr;
}

} // namespace finders
} // namespace pathfinder
} // namespace tracker

#endif // K4_TRACKER_CONVAR_FINDER_H
