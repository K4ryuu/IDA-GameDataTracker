/* pathfinder/relational_finder.h - caller/callee sig resolution */

#ifndef K4_TRACKER_RELATIONAL_FINDER_H
#define K4_TRACKER_RELATIONAL_FINDER_H

#include "core/types.h"
#include "core/index.h"
#include "utils/signature.h"

#include <ida.hpp>
#include <funcs.hpp>

namespace tracker {
namespace pathfinder {
namespace finders {

inline std::vector<FinderResult> find_by_relational_all(const Anchor& anchor, const GlobalIndex& index) {
    std::vector<FinderResult> results;

    if (anchor.signature.empty() || anchor.name.empty()) return results;

    bool is_caller = (anchor.name.find("CALLER:") == 0);
    bool is_callee = (anchor.name.find("CALLEE:") == 0);
    if (!is_caller && !is_callee) return results;

    ea_t anchor_ea = sig::find_first_match(anchor.signature, 0, BADADDR);
    if (anchor_ea == BADADDR) return results;

    ea_t second = sig::find_first_match(anchor.signature, anchor_ea + 1, BADADDR);
    if (second != BADADDR) return results;

    if (anchor_ea < anchor.signature.offset) return results;
    anchor_ea -= anchor.signature.offset;
    func_t* anchor_func = get_func(anchor_ea);
    if (!anchor_func) return results;
    anchor_ea = anchor_func->start_ea;

    if (is_caller) {
        auto cit = index.callees.find(anchor_ea);
        if (cit == index.callees.end()) return results;

        if (cit->second.size() <= 10) {
            for (ea_t callee : cit->second) {
                if (!index.library_funcs.count(callee)) {
                    FinderResult fr;
                    fr.source = ModulePriority::RELATIONAL;
                    fr.candidate = callee;
                    fr.detail = "relational_caller→callee: " + anchor.name;
                    results.push_back(fr);
                }
            }
        }
    } else {
        auto cit = index.callers.find(anchor_ea);
        if (cit == index.callers.end()) return results;

        if (cit->second.size() <= 10) {
            for (ea_t caller : cit->second) {
                if (!index.library_funcs.count(caller)) {
                    FinderResult fr;
                    fr.source = ModulePriority::RELATIONAL;
                    fr.candidate = caller;
                    fr.detail = "relational_callee→caller: " + anchor.name;
                    results.push_back(fr);
                }
            }
        }
    }

    return results;
}

// Enhanced: uses already-matched funcs

inline std::vector<FinderResult> find_by_relational_matched_all(
    const Anchor& anchor,
    const GlobalIndex& index,
    const std::unordered_map<ea_t, ea_t>& matched_map)
{
    std::vector<FinderResult> results;

    if (anchor.name.empty()) return results;

    bool is_caller = (anchor.name.find("CALLER:") == 0);
    bool is_callee = (anchor.name.find("CALLEE:") == 0);
    if (!is_caller && !is_callee) return results;

    auto mit = matched_map.find(anchor.resolved_ea);
    if (mit == matched_map.end()) return results;

    ea_t anchor_new_ea = mit->second;

    if (is_caller) {
        auto cit = index.callees.find(anchor_new_ea);
        if (cit == index.callees.end()) return results;
        for (ea_t callee : cit->second) {
            if (!index.library_funcs.count(callee)) {
                FinderResult fr;
                fr.source = ModulePriority::RELATIONAL;
                fr.candidate = callee;
                fr.detail = "relational_matched_caller→callee: " + anchor.name;
                results.push_back(fr);
            }
        }
    } else {
        auto cit = index.callers.find(anchor_new_ea);
        if (cit == index.callers.end()) return results;
        for (ea_t caller : cit->second) {
            if (!index.library_funcs.count(caller)) {
                FinderResult fr;
                fr.source = ModulePriority::RELATIONAL;
                fr.candidate = caller;
                fr.detail = "relational_matched_callee→caller: " + anchor.name;
                results.push_back(fr);
            }
        }
    }

    return results;
}

} // namespace finders
} // namespace pathfinder
} // namespace tracker

#endif // K4_TRACKER_RELATIONAL_FINDER_H
