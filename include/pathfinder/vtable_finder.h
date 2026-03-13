/* pathfinder/vtable_finder.h - vtable slot resolution */

#ifndef K4_TRACKER_VTABLE_FINDER_H
#define K4_TRACKER_VTABLE_FINDER_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"

#include <ida.hpp>
#include <funcs.hpp>

#include <algorithm>

namespace tracker {
namespace pathfinder {
namespace finders {

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

inline std::vector<FinderResult> find_by_vtable_all(const Anchor& anchor,
                                                      const GlobalIndex& index)
{
    std::vector<FinderResult> results;

    if (anchor.name.empty()) return results;

    std::string vtname;
    const GlobalIndex::VTableEntry* vt_ptr = nullptr;

    auto cls_it = index.class_to_vtname.find(anchor.name);
    if (cls_it != index.class_to_vtname.end()) {
        auto vt_it = index.vtables.find(cls_it->second);
        if (vt_it != index.vtables.end()) {
            vtname = cls_it->second;
            vt_ptr = &vt_it->second;
        }
    }
    if (!vt_ptr) {
        auto vt_it = index.vtables.find(anchor.name);
        if (vt_it != index.vtables.end()) {
            vtname = anchor.name;
            vt_ptr = &vt_it->second;
        }
    }
    if (!vt_ptr) {
        for (const auto& [vtn, vt] : index.vtables) {
            std::string norm_demangled = !vt.demangled.empty()
                ? normalize_vtable_name(vt.demangled) : "";
            if ((!norm_demangled.empty() && norm_demangled == anchor.name) ||
                vtn == anchor.name) {
                vtname = vtn;
                vt_ptr = &vt;
                break;
            }
        }
    }

    if (vt_ptr) {
        const auto& vt = *vt_ptr;

        uint32_t new_vtable_size = static_cast<uint32_t>(vt.slots.size());
        uint32_t size_diff = (anchor.vtable_size > new_vtable_size)
            ? anchor.vtable_size - new_vtable_size
            : new_vtable_size - anchor.vtable_size;
        int32_t tolerance = static_cast<int32_t>(
            config::VTABLE_SLOT_BASE_TOLERANCE + size_diff);

        int32_t start = std::max<int32_t>(0,
            static_cast<int32_t>(anchor.index) - tolerance);
        int32_t end = std::min<int32_t>(
            static_cast<int32_t>(vt.slots.size()),
            static_cast<int32_t>(anchor.index) + tolerance + 1);

        bool has_neighbor_info = (anchor.vtable_neighbor_before > 0 ||
                                  anchor.vtable_neighbor_after > 0);

        struct SlotCandidate {
            int32_t slot;
            ea_t func_ea;
            int neighbor_score;  // Total score (nb levels + proximity)
        };
        std::vector<SlotCandidate> slot_candidates;

        auto get_real_func_size = [](ea_t ea) -> uint32_t {
            func_t* f = get_func(ea);
            if (!f) return 0;
            // If it's a small jmp wrapper (thunk), follow it
            if ((f->end_ea - f->start_ea) < 32) {
                insn_t insn;
                if (decode_insn(&insn, f->start_ea) > 0) {
                    if (insn.itype == NN_jmp || insn.itype == NN_jmpfi || insn.itype == NN_jmpni) {
                        if (insn.Op1.type == o_near || insn.Op1.type == o_far) {
                            func_t* target = get_func(insn.Op1.addr);
                            if (target) return static_cast<uint32_t>(target->end_ea - target->start_ea);
                        }
                    }
                }
            }
            return static_cast<uint32_t>(f->end_ea - f->start_ea);
        };

        auto get_nb_level = [](uint32_t actual, uint32_t expected) -> int {
            if (expected == 0 || actual == 0) return 0;
            uint32_t diff = (actual > expected) ? actual - expected : expected - actual;
            if (diff <= 2) return 10;                       // Level 3: Near-exact (+10)
            if (diff <= expected * 10 / 100 + 2) return 5;  // Level 2: Close (10%) (+5)
            if (diff <= expected * 30 / 100 + 4) return 2;  // Level 1: Rough (30%) (+2)
            return 0;
        };

        for (int32_t s = start; s < end; ++s) {
            ea_t func_ea = vt.slots[s];
            func_t* f = get_func(func_ea);
            if (!f) continue;
            if (index.library_funcs.count(f->start_ea)) continue;

            int score = 0;
            if (has_neighbor_info) {
                // nb before
                if (anchor.vtable_neighbor_before > 0 && s > 0 &&
                    static_cast<uint32_t>(s - 1) < vt.slots.size()) {
                    score += get_nb_level(get_real_func_size(vt.slots[s - 1]), 
                                           anchor.vtable_neighbor_before);
                }
                // nb after
                if (anchor.vtable_neighbor_after > 0 &&
                    static_cast<uint32_t>(s + 1) < vt.slots.size()) {
                    score += get_nb_level(get_real_func_size(vt.slots[s + 1]), 
                                           anchor.vtable_neighbor_after);
                }
            }
            
            int32_t dist = (s > (int32_t)anchor.index) ? s - (int32_t)anchor.index : (int32_t)anchor.index - s;
            if (dist == 0) score += 2;
            else if (dist <= 2) score += 1;

            slot_candidates.push_back({s, f->start_ea, score});
        }

        for (const auto& sc : slot_candidates) {
            char buf[160];
            const char* name = anchor.name.c_str();

            // Base vote
            results.push_back({ sc.func_ea, ModulePriority::VTABLE, 
                (sc.slot == (int32_t)anchor.index) 
                    ? (qsnprintf(buf, sizeof(buf), "vtable: %s[%u]", name, anchor.index), buf)
                    : (qsnprintf(buf, sizeof(buf), "vtable~: %s[%u->%d]", name, anchor.index, sc.slot), buf)
            });

            for (int i = 0; i < sc.neighbor_score; ++i) {
                qsnprintf(buf, sizeof(buf), "vtable_score: %s[%d](rank=%d)", name, sc.slot, i + 1);
                results.push_back({ sc.func_ea, ModulePriority::VTABLE, buf });
            }
        }

        return results;
    }

    return results;
}

} // namespace finders
} // namespace pathfinder
} // namespace tracker

#endif // K4_TRACKER_VTABLE_FINDER_H
