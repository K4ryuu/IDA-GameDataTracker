/* crawler/string_module.h - string-based anchors */

#ifndef K4_TRACKER_STRING_MODULE_H
#define K4_TRACKER_STRING_MODULE_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <ida.hpp>
#include <funcs.hpp>

#include <algorithm>
#include <unordered_set>

namespace tracker {
namespace modules {
namespace string_mod {

inline std::vector<Anchor> collect(ea_t fea, const GlobalIndex& index) {
    std::vector<Anchor> anchors;

    auto sit = index.func_to_strings.find(fea);
    if (sit == index.func_to_strings.end()) return anchors;

    std::unordered_set<std::string> seen;

    for (const auto& s : sit->second) {
        if (s.length() < config::MIN_STRING_LENGTH) continue;
        if (!seen.insert(s).second) continue;

        auto fit = index.string_to_funcs.find(s);
        if (fit == index.string_to_funcs.end()) continue;

        size_t ref_count = fit->second.size();

        if (ref_count == 1) {
            Anchor a;
            a.priority = ModulePriority::UNIQUE_STR;
            a.name = s;
            a.index = 1;
            // store func size in case string stops being unique
            func_t* fn = get_func(fea);
            if (fn) {
                a.rva = fn->end_ea - fn->start_ea;
            }
            a.resolved_ea = fea;
            anchors.push_back(a);
        } else if (ref_count >= 2 && ref_count <= config::MAX_RARE_STRING_REFS) {
            Anchor a;
            a.priority = ModulePriority::UNIQUE_STR;  // Same module, pathfinder differentiates by index
            a.name = s;
            a.index = static_cast<uint32_t>(ref_count);

            func_t* fn = get_func(fea);
            if (fn) {
                a.rva = fn->end_ea - fn->start_ea;
            }

            a.resolved_ea = fea;
            anchors.push_back(a);
        }
    }

    std::sort(anchors.begin(), anchors.end(), [](const Anchor& a, const Anchor& b) {
        if (a.index != b.index) return a.index < b.index;  // Fewer refs = better
        return a.name.length() > b.name.length();           // Longer = better
    });

    if (anchors.size() > config::MAX_ITEMS_PER_MODULE) {
        anchors.resize(config::MAX_ITEMS_PER_MODULE);
    }

    return anchors;
}

} // namespace string_mod
} // namespace modules
} // namespace tracker

#endif // K4_TRACKER_STRING_MODULE_H
