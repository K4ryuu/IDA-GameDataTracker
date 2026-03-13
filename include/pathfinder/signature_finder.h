/* pathfinder/signature_finder.h - byte sig scan */

#ifndef K4_TRACKER_SIGNATURE_FINDER_H
#define K4_TRACKER_SIGNATURE_FINDER_H

#include "core/types.h"
#include "core/index.h"
#include "utils/signature.h"

#include <ida.hpp>
#include <funcs.hpp>

namespace tracker {
namespace pathfinder {
namespace finders {

inline FinderResult find_by_signature(const Anchor& anchor, const GlobalIndex&) {
    FinderResult fr;
    fr.source = ModulePriority::SIGNATURE;

    if (anchor.signature.empty()) return fr;

    ea_t found = sig::find_first_match(anchor.signature, 0, BADADDR);
    if (found == BADADDR) return fr;

    ea_t second = sig::find_first_match(anchor.signature, found + 1, BADADDR);
    if (second != BADADDR) return fr; // Not unique

    if (found < anchor.signature.offset) return fr;
    ea_t target = found - anchor.signature.offset;
    func_t* f = get_func(target);
    if (!f) return fr;
    if (target < f->start_ea || target >= f->end_ea) return fr;

    fr.candidate = f->start_ea;
    fr.detail = "sig_match (offset=" + std::to_string(anchor.signature.offset) + ")";
    return fr;
}

} // namespace finders
} // namespace pathfinder
} // namespace tracker

#endif // K4_TRACKER_SIGNATURE_FINDER_H
