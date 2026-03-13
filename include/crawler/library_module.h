/* crawler/library_module.h - library call anchors */

#ifndef K4_TRACKER_LIBRARY_MODULE_H
#define K4_TRACKER_LIBRARY_MODULE_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <ida.hpp>
#include <name.hpp>

#include <algorithm>
#include <unordered_set>

namespace tracker {
namespace modules {
namespace library_mod {

inline std::vector<Anchor> collect(ea_t fea, const GlobalIndex& index) {
    std::vector<Anchor> anchors;

    auto cit = index.callees.find(fea);
    if (cit == index.callees.end()) return anchors;

    std::unordered_set<std::string> seen;

    for (ea_t callee : cit->second) {
        if (!index.library_funcs.count(callee)) continue;

        auto nit = index.library_names.find(callee);
        if (nit == index.library_names.end()) continue;

        if (!seen.insert(nit->second).second) continue;

        Anchor a;
        a.priority = ModulePriority::LIBRARY;
        a.name = nit->second;
        a.resolved_ea = callee;
        a.fanout = index.get_fanout(callee);
        anchors.push_back(a);
    }

    std::sort(anchors.begin(), anchors.end(), [](const Anchor& a, const Anchor& b) {
        return a.fanout < b.fanout;
    });

    if (anchors.size() > config::MAX_ITEMS_PER_MODULE) {
        anchors.resize(config::MAX_ITEMS_PER_MODULE);
    }

    return anchors;
}

} // namespace library_mod
} // namespace modules
} // namespace tracker

#endif // K4_TRACKER_LIBRARY_MODULE_H
