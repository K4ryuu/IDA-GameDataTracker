/* crawler/relational_module.h - caller/callee sig anchors */

#ifndef K4_TRACKER_RELATIONAL_MODULE_H
#define K4_TRACKER_RELATIONAL_MODULE_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"
#include "utils/signature.h"

#include <ida.hpp>
#include <funcs.hpp>
#include <name.hpp>

#include <algorithm>
#include <unordered_set>

namespace tracker {
namespace modules {
namespace relational_mod {

inline std::vector<Anchor> collect(ea_t fea, const GlobalIndex& index) {
    std::vector<Anchor> anchors;
    std::unordered_set<ea_t> seen;

    auto crit = index.callers.find(fea);
    if (crit != index.callers.end()) {
        for (ea_t caller : crit->second) {
            uint32_t fanout = index.get_fanout(caller);
            if (fanout > config::MAX_RELATIONAL_FANOUT) continue;

            qstring name;
            get_func_name(&name, caller);
            if (config::is_anti_anchor_name(name.c_str())) continue;

            Signature anchor_sig = sig::make_signature(caller, BADADDR, caller, 0);
            if (anchor_sig.empty()) continue;

            if (!seen.insert(caller).second) continue;

            Anchor a;
            a.priority = ModulePriority::RELATIONAL;
            a.name = "CALLER:" + std::string(name.c_str());
            a.signature = anchor_sig;
            a.resolved_ea = caller;
            a.fanout = fanout;
            anchors.push_back(a);
        }
    }

    auto ceit = index.callees.find(fea);
    if (ceit != index.callees.end()) {
        for (ea_t callee : ceit->second) {
            uint32_t fanout = index.get_fanout(callee);
            if (fanout > config::MAX_RELATIONAL_FANOUT) continue;

            qstring name;
            get_func_name(&name, callee);
            if (config::is_anti_anchor_name(name.c_str())) continue;

            Signature anchor_sig = sig::make_signature(callee, BADADDR, callee, 0);
            if (anchor_sig.empty()) continue;

            if (!seen.insert(callee).second) continue;

            Anchor a;
            a.priority = ModulePriority::RELATIONAL;
            a.name = "CALLEE:" + std::string(name.c_str());
            a.signature = anchor_sig;
            a.resolved_ea = callee;
            a.fanout = fanout;
            anchors.push_back(a);
        }
    }

    std::sort(anchors.begin(), anchors.end(), [](const Anchor& a, const Anchor& b) {
        return a.fanout < b.fanout;
    });

    if (anchors.size() > config::MAX_ITEMS_PER_MODULE) {
        anchors.resize(config::MAX_ITEMS_PER_MODULE);
    }

    return anchors;
}

} // namespace relational_mod
} // namespace modules
} // namespace tracker

#endif // K4_TRACKER_RELATIONAL_MODULE_H
