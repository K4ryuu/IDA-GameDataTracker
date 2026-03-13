/* crawler/vtable_module.h - vtable slot anchors */

#ifndef K4_TRACKER_VTABLE_MODULE_H
#define K4_TRACKER_VTABLE_MODULE_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <ida.hpp>
#include <bytes.hpp>

#include <algorithm>

namespace tracker {
namespace modules {
namespace vtable_mod {

inline std::string normalize_vtable_name(const std::string& name) {
    static const char* prefixes[] = {
        "`vtable for'", "vtable for ", "`typeinfo for'", "typeinfo for "
    };
    for (const char* prefix : prefixes) {
        size_t plen = strlen(prefix);
        if (name.size() > plen && name.compare(0, plen, prefix) == 0) {
            return name.substr(plen);
        }
    }
    return name;
}

inline std::vector<Anchor> collect(ea_t fea, const GlobalIndex& index) {
    std::vector<Anchor> anchors;

    auto vit = index.func_to_vtables.find(fea);
    if (vit == index.func_to_vtables.end() || vit->second.empty()) return anchors;

    for (const auto& [vtname, slot] : vit->second) {
        auto vt_it = index.vtables.find(vtname);
        if (vt_it == index.vtables.end()) continue;

        const auto& vt_slots = vt_it->second.slots;

        Anchor a;
        a.priority = ModulePriority::VTABLE;
        std::string raw_name = !vt_it->second.demangled.empty()
                               ? vt_it->second.demangled : vtname;
        a.name = normalize_vtable_name(raw_name);
        a.index = slot;
        a.vtable_size = static_cast<uint32_t>(vt_slots.size());
        ea_t vtable_start_ea = vt_it->second.start_ea;
        if (vtable_start_ea != BADADDR) {
            a.rva = vtable_start_ea - get_imagebase();
        }
        a.resolved_ea = fea;

        if (slot > 0 && slot - 1 < vt_slots.size()) {
            func_t* nb = get_func(vt_slots[slot - 1]);
            if (nb) a.vtable_neighbor_before = static_cast<uint32_t>(nb->end_ea - nb->start_ea);
        }
        if (slot + 1 < vt_slots.size()) {
            func_t* nb = get_func(vt_slots[slot + 1]);
            if (nb) a.vtable_neighbor_after = static_cast<uint32_t>(nb->end_ea - nb->start_ea);
        }

        anchors.push_back(a);
    }

    std::sort(anchors.begin(), anchors.end(), [](const Anchor& a, const Anchor& b) {
        if (a.index != b.index) return a.index < b.index;
        return a.vtable_size > b.vtable_size;
    });

    if (anchors.size() > config::MAX_ITEMS_PER_MODULE) {
        anchors.resize(config::MAX_ITEMS_PER_MODULE);
    }

    return anchors;
}

} // namespace vtable_mod
} // namespace modules
} // namespace tracker

#endif // K4_TRACKER_VTABLE_MODULE_H
