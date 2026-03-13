/* crawler/callchain_module.h - call-graph BFS to landmarks */

#ifndef K4_TRACKER_CALLCHAIN_MODULE_H
#define K4_TRACKER_CALLCHAIN_MODULE_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <queue>
#include <unordered_set>

namespace tracker {
namespace modules {
namespace callchain_mod {

//=============================================================================
// Landmark detection
//=============================================================================

struct LandmarkInfo {
    std::string name;
    uint8_t type = 0;  // 0=string, 1=vtable, 2=convar, 3=data_ptr
};

inline LandmarkInfo detect_landmark(ea_t fea, const GlobalIndex& index) {
    LandmarkInfo info;

    auto str_it = index.func_to_strings.find(fea);
    if (str_it != index.func_to_strings.end()) {
        for (const auto& s : str_it->second) {
            if (s.length() < config::MIN_STRING_LENGTH) continue;
            auto ref_it = index.string_to_funcs.find(s);
            if (ref_it != index.string_to_funcs.end() && ref_it->second.size() == 1) {
                info.name = s;
                info.type = 0;  // unique string
                return info;
            }
        }
    }

    auto vt_it = index.func_to_vtables.find(fea);
    if (vt_it != index.func_to_vtables.end() && !vt_it->second.empty()) {
        // Pick first vtable entry as landmark
        const auto& [vtname, slot] = vt_it->second[0];
        auto vtinfo_it = index.vtables.find(vtname);
        if (vtinfo_it != index.vtables.end()) {
            std::string raw_name = !vtinfo_it->second.demangled.empty()
                                   ? vtinfo_it->second.demangled : vtname;
            // Reuse vtable_module's normalize (inline, safe to duplicate logic)
            static const char* prefixes[] = {
                "`vtable for'", "vtable for ", "`typeinfo for'", "typeinfo for "
            };
            for (const char* prefix : prefixes) {
                size_t plen = strlen(prefix);
                if (raw_name.size() > plen && raw_name.compare(0, plen, prefix) == 0) {
                    raw_name = raw_name.substr(plen);
                    break;
                }
            }
            // Encode as "ClassName[slot]"
            info.name = raw_name + "[" + std::to_string(slot) + "]";
            info.type = 1;  // vtable
            return info;
        }
    }

    if (str_it != index.func_to_strings.end()) {
        for (const auto& s : str_it->second) {
            if (is_convar_string(s)) {
                info.name = s;
                info.type = 2;  // convar
                return info;
            }
        }
    }

    auto dp_it = index.func_to_data_seg_ptrs.find(fea);
    if (dp_it != index.func_to_data_seg_ptrs.end() && !dp_it->second.empty()) {
        ea_t ptr_ea = dp_it->second[0];
        uint64_t rva = ptr_ea - get_imagebase();
        func_t* lm_func = get_func(fea);
        uint32_t lm_size = lm_func
            ? static_cast<uint32_t>(lm_func->end_ea - lm_func->start_ea) : 0;
        char buf[64];
        qsnprintf(buf, sizeof(buf), "0x%llX:%u", (unsigned long long)rva, lm_size);
        info.name = buf;
        info.type = 3;  // data_ptr
        return info;
    }

    return info;  // Not a landmark (empty name)
}

//=============================================================================
// BFS state
//=============================================================================

struct BFSNode {
    ea_t func_ea;
    uint8_t depth;
    uint8_t directions;   // Bitmask: bit i → direction of hop i (0=caller, 1=callee)
};

//=============================================================================
// BFS collect
//=============================================================================

inline std::vector<Anchor> collect(ea_t fea, const GlobalIndex& index) {
    std::vector<Anchor> anchors;

    uint32_t tracked_size = 0;
    func_t* tracked_f = get_func(fea);
    if (tracked_f) tracked_size = static_cast<uint32_t>(tracked_f->end_ea - tracked_f->start_ea);

    std::queue<BFSNode> queue;
    std::unordered_set<ea_t> visited;
    visited.insert(fea);

    auto caller_it = index.callers.find(fea);
    if (caller_it != index.callers.end()) {
        for (ea_t caller : caller_it->second) {
            if (visited.insert(caller).second) {
                queue.push({caller, 1, 0});  // Direction bit 0 = 0 → caller
            }
        }
    }
    auto callee_it = index.callees.find(fea);
    if (callee_it != index.callees.end()) {
        for (ea_t callee : callee_it->second) {
            if (visited.insert(callee).second) {
                queue.push({callee, 1, 1});  // Direction bit 0 = 1 → callee
            }
        }
    }

    while (!queue.empty() && anchors.size() < config::CALLCHAIN_MAX_ANCHORS) {
        if (visited.size() > config::CALLCHAIN_MAX_VISIT) break;

        BFSNode node = queue.front();
        queue.pop();

        LandmarkInfo lm = detect_landmark(node.func_ea, index);
        if (!lm.name.empty()) {
            Anchor a;
            a.priority = ModulePriority::CALLCHAIN;
            a.name = lm.name;
            a.chain_depth = node.depth;
            a.chain_directions = node.directions;
            a.chain_landmark_type = lm.type;
            a.fanout = index.get_fanout(node.func_ea);
            a.func_size = tracked_size;
            a.resolved_ea = node.func_ea;
            anchors.push_back(a);

            continue;
        }

        if (node.depth >= config::CALLCHAIN_MAX_DEPTH) continue;

        uint32_t fanout = index.get_fanout(node.func_ea);
        if (fanout > config::MAX_RELATIONAL_FANOUT * 2) continue;

        auto cit = index.callers.find(node.func_ea);
        if (cit != index.callers.end()) {
            for (ea_t caller : cit->second) {
                if (visited.size() > config::CALLCHAIN_MAX_VISIT) break;
                if (visited.insert(caller).second) {
                    uint8_t new_dirs = node.directions;  // bit already 0 for caller
                    queue.push({caller, static_cast<uint8_t>(node.depth + 1), new_dirs});
                }
            }
        }

        auto ceit = index.callees.find(node.func_ea);
        if (ceit != index.callees.end()) {
            for (ea_t callee : ceit->second) {
                if (visited.size() > config::CALLCHAIN_MAX_VISIT) break;
                if (visited.insert(callee).second) {
                    uint8_t new_dirs = node.directions | (1 << node.depth);
                    queue.push({callee, static_cast<uint8_t>(node.depth + 1), new_dirs});
                }
            }
        }
    }

    std::sort(anchors.begin(), anchors.end(), [](const Anchor& a, const Anchor& b) {
        if (a.chain_depth != b.chain_depth) return a.chain_depth < b.chain_depth;
        return a.chain_landmark_type < b.chain_landmark_type;  // string < vtable < convar
    });

    if (anchors.size() > config::CALLCHAIN_MAX_ANCHORS) {
        anchors.resize(config::CALLCHAIN_MAX_ANCHORS);
    }

    return anchors;
}

} // namespace callchain_mod
} // namespace modules
} // namespace tracker

#endif // K4_TRACKER_CALLCHAIN_MODULE_H
