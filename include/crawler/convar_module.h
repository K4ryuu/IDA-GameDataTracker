/* crawler/convar_module.h - ConVar name anchors */

#ifndef K4_TRACKER_CONVAR_MODULE_H
#define K4_TRACKER_CONVAR_MODULE_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <ida.hpp>
#include <funcs.hpp>

#include <algorithm>
#include <unordered_set>

namespace tracker {
namespace modules {
namespace convar_mod {

inline std::vector<Anchor> collect(ea_t fea, const GlobalIndex& index) {
    std::vector<Anchor> anchors;
    std::unordered_set<std::string> seen_names;

    auto data_refs = collect_data_xrefs(fea);

    for (ea_t data_ea : data_refs) {
        if (!ensure_convar_index_for_qword(data_ea)) continue;

        auto nit = g_index.convar_qword_to_name.find(data_ea);
        if (nit == g_index.convar_qword_to_name.end()) continue;

        auto fit = g_index.convar_name_to_funcs.find(nit->second);
        if (fit == g_index.convar_name_to_funcs.end()) continue;

        if (fit->second.size() == 1 && fit->second[0] == fea) {
            if (!seen_names.insert(nit->second).second) continue;

            Anchor a;
            a.priority = ModulePriority::CONVAR;
            a.name = nit->second;
            a.resolved_ea = fea;
            anchors.push_back(a);
        }
    }

    std::sort(anchors.begin(), anchors.end(), [](const Anchor& a, const Anchor& b) {
        return a.name.length() > b.name.length();
    });

    if (anchors.size() > config::MAX_ITEMS_PER_MODULE) {
        anchors.resize(config::MAX_ITEMS_PER_MODULE);
    }

    return anchors;
}

} // namespace convar_mod
} // namespace modules
} // namespace tracker

#endif // K4_TRACKER_CONVAR_MODULE_H
