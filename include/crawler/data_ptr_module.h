/* crawler/data_ptr_module.h - .data func ptr anchors */

#ifndef K4_TRACKER_DATA_PTR_MODULE_H
#define K4_TRACKER_DATA_PTR_MODULE_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <ida.hpp>
#include <segment.hpp>
#include <name.hpp>

#include <algorithm>

namespace tracker {
namespace modules {
namespace data_ptr_mod {

inline std::vector<Anchor> collect(ea_t fea, const GlobalIndex& index) {
    std::vector<Anchor> anchors;

    for (const auto& [ptr_ea, func_ea] : index.data_func_ptrs) {
        if (func_ea != fea) continue;

        Anchor a;
        a.priority = ModulePriority::DATA_PTR;
        a.resolved_ea = fea;

        segment_t* seg = getseg(ptr_ea);
        if (!seg) continue;  // No segment = unusable anchor

        qstring seg_name;
        get_segm_name(&seg_name, seg);
        a.name = seg_name.c_str();
        a.rva = ptr_ea - seg->start_ea;

        anchors.push_back(a);
    }

    if (anchors.size() > config::MAX_ITEMS_PER_MODULE) {
        anchors.resize(config::MAX_ITEMS_PER_MODULE);
    }

    return anchors;
}

} // namespace data_ptr_mod
} // namespace modules
} // namespace tracker

#endif // K4_TRACKER_DATA_PTR_MODULE_H
