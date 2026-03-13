/* crawler/signature_module.h - byte sig anchors */

#ifndef K4_TRACKER_SIGNATURE_MODULE_H
#define K4_TRACKER_SIGNATURE_MODULE_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"
#include "utils/signature.h"

#include <ida.hpp>
#include <funcs.hpp>

#include <algorithm>

namespace tracker {
namespace modules {
namespace signature_mod {

inline std::vector<Anchor> collect(ea_t fea, const GlobalIndex&) {
    std::vector<Anchor> anchors;

    Signature sig_start = sig::make_signature(fea, BADADDR, fea, 0);
    if (!sig_start.empty()) {
        Anchor a;
        a.priority = ModulePriority::SIGNATURE;
        a.signature = sig_start;
        a.resolved_ea = fea;
        anchors.push_back(a);
    }

    func_t* f = get_func(fea);
    if (f && (f->end_ea - fea) > config::MIN_FUNC_SIZE_FOR_SKIP) {
        uint8_t prologue_len = sig::detect_prologue_length(fea);
        if (prologue_len > 0) {
            ea_t skip_ea = fea + prologue_len;
            Signature sig_skip = sig::make_signature(skip_ea, f->end_ea, skip_ea, prologue_len);
            if (!sig_skip.empty()) {
                bool is_dup = (sig_start.bytes == sig_skip.bytes);
                if (!is_dup) {
                    Anchor a;
                    a.priority = ModulePriority::SIGNATURE;
                    a.signature = sig_skip;
                    a.resolved_ea = fea;
                    anchors.push_back(a);
                }
            }
        }
    }

    std::sort(anchors.begin(), anchors.end(), [](const Anchor& a, const Anchor& b) {
        return a.signature.length() > b.signature.length();
    });

    if (anchors.size() > config::MAX_ITEMS_PER_MODULE) {
        anchors.resize(config::MAX_ITEMS_PER_MODULE);
    }

    return anchors;
}

} // namespace signature_mod
} // namespace modules
} // namespace tracker

#endif // K4_TRACKER_SIGNATURE_MODULE_H
