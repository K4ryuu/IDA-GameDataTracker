/*
 * core/index.h - global binary index, built once per session
 */

#ifndef K4_TRACKER_INDEX_H
#define K4_TRACKER_INDEX_H

#include "core/types.h"
#include "core/config.h"
#include "utils/logger.h"
#include "rtti_parser.h"

#include <ida.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <strlist.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <demangle.hpp>
#include <ua.hpp>
#ifndef K4T_ALLINS_INCLUDED
#define K4T_ALLINS_INCLUDED
#include <allins.hpp>
#endif

#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <chrono>
#include <cctype>

namespace tracker {

struct GlobalIndex {
    // String <-> function mappings
    std::unordered_map<std::string, std::vector<ea_t>> string_to_funcs;
    std::unordered_map<ea_t, std::vector<std::string>> func_to_strings;

    // Call graph
    std::unordered_map<ea_t, std::vector<ea_t>> callers;
    std::unordered_map<ea_t, std::vector<ea_t>> callees;

    // VTable info
    struct VTableEntry {
        std::string name;
        std::string demangled;
        ea_t start_ea;
        std::vector<ea_t> slots;
    };
    std::unordered_map<std::string, VTableEntry> vtables;
    std::unordered_map<ea_t, std::vector<std::pair<std::string, uint32_t>>> func_to_vtables;

    // Data segment function pointers: (pointer_ea, target_func_ea)
    std::vector<std::pair<ea_t, ea_t>> data_func_ptrs;

    // reverse: func → .data ptrs (for landmark detection)
    std::unordered_map<ea_t, std::vector<ea_t>> func_to_data_seg_ptrs;

    // thunk → real target
    std::unordered_map<ea_t, ea_t> thunk_map;

    // copied code bytes for parallel sig scan
    struct CodeSection {
        ea_t start_ea;
        std::vector<uint8_t> bytes;
    };
    std::vector<CodeSection> code_sections;

    // Known library/imported functions
    std::unordered_set<ea_t> library_funcs;
    std::unordered_map<ea_t, std::string> library_names;

    // class name → vtable key
    std::unordered_map<std::string, std::string> class_to_vtname;

    // ConVar indexing (on-demand)
    std::unordered_map<ea_t, std::string> convar_qword_to_name;
    std::unordered_map<std::string, std::vector<ea_t>> convar_name_to_funcs;
    std::unordered_set<ea_t> convar_qword_scanned;
    std::unordered_set<std::string> convar_name_scanned;

    // pre-built metadata for all funcs (thread-safe)
    struct FuncMetadata {
        Identity identity;
        Reinforcement reinforcement;
    };
    std::unordered_map<ea_t, FuncMetadata> func_metadata;

    // validation cache
    struct CachedValidation {
        bool identity_ok;
        float reinforcement;
        const char* fail_reason;
    };
    std::unordered_map<ea_t, CachedValidation> validation_cache;

    bool ready = false;

    void build(TreeLogger& logger);

    void clear() {
        string_to_funcs.clear();
        func_to_strings.clear();
        callers.clear();
        callees.clear();
        vtables.clear();
        func_to_vtables.clear();
        class_to_vtname.clear();
        data_func_ptrs.clear();
        func_to_data_seg_ptrs.clear();
        library_funcs.clear();
        library_names.clear();
        convar_qword_to_name.clear();
        convar_name_to_funcs.clear();
        convar_qword_scanned.clear();
        convar_name_scanned.clear();
        func_metadata.clear();
        validation_cache.clear();
        thunk_map.clear();
        code_sections.clear();
        ready = false;
    }

    uint32_t get_fanout(ea_t fea) const {
        uint32_t count = 0;
        auto cit = callers.find(fea);
        if (cit != callers.end()) count += static_cast<uint32_t>(cit->second.size());
        auto ceit = callees.find(fea);
        if (ceit != callees.end()) count += static_cast<uint32_t>(ceit->second.size());
        return count;
    }

    uint32_t get_caller_count(ea_t fea) const {
        auto it = callers.find(fea);
        return it != callers.end() ? static_cast<uint32_t>(it->second.size()) : 0;
    }

    uint32_t get_callee_count(ea_t fea) const {
        auto it = callees.find(fea);
        return it != callees.end() ? static_cast<uint32_t>(it->second.size()) : 0;
    }
};

// Global instance
inline GlobalIndex g_index;

//=============================================================================
// String index
//=============================================================================

inline void build_string_index(TreeLogger& logger) {
    auto start = std::chrono::high_resolution_clock::now();

    size_t count = get_strlist_qty();
    for (size_t i = 0; i < count; ++i) {
        string_info_t si;
        if (!get_strlist_item(&si, i)) continue;
        if (si.length < 6) continue;

        qstring str;
        if (get_strlit_contents(&str, si.ea, si.length, si.type) <= 0) continue;

        std::string s = str.c_str();

        if (s == "true" || s == "false" || s == "null") continue;

        xrefblk_t xb;
        for (bool ok = xb.first_to(si.ea, XREF_DATA); ok; ok = xb.next_to()) {
            func_t* f = get_func(xb.from);
            if (!f) continue;

            ea_t fea = f->start_ea;
            g_index.string_to_funcs[s].push_back(fea);
            g_index.func_to_strings[fea].push_back(s);
        }
    }

    for (auto& [str, funcs] : g_index.string_to_funcs) {
        std::sort(funcs.begin(), funcs.end());
        funcs.erase(std::unique(funcs.begin(), funcs.end()), funcs.end());
    }
    for (auto& [fea, strs] : g_index.func_to_strings) {
        std::sort(strs.begin(), strs.end());
        strs.erase(std::unique(strs.begin(), strs.end()), strs.end());
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    logger.item(false, "Strings: %zu unique, %zu func mappings (%lldms)",
        g_index.string_to_funcs.size(), g_index.func_to_strings.size(), ms);
}

//=============================================================================
// Call graph
//=============================================================================

inline void build_callgraph_index(TreeLogger& logger) {
    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < get_func_qty(); ++i) {
        func_t* f = getn_func(i);
        if (!f) continue;

        ea_t fea = f->start_ea;
        ea_t ea = f->start_ea;
        while (ea < f->end_ea) {
            xrefblk_t xb;
            for (bool ok = xb.first_from(ea, XREF_FAR); ok; ok = xb.next_from()) {
                if (!xb.iscode) continue;
                func_t* target = get_func(xb.to);
                if (target && target->start_ea != fea) {
                    g_index.callees[fea].push_back(target->start_ea);
                    g_index.callers[target->start_ea].push_back(fea);
                }
            }
            ea = next_head(ea, f->end_ea);
        }
    }

    for (auto& [fea, list] : g_index.callees) {
        std::sort(list.begin(), list.end());
        list.erase(std::unique(list.begin(), list.end()), list.end());
    }
    for (auto& [fea, list] : g_index.callers) {
        std::sort(list.begin(), list.end());
        list.erase(std::unique(list.begin(), list.end()), list.end());
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    logger.item(false, "CallGraph: %zu with callers, %zu with callees (%lldms)",
        g_index.callers.size(), g_index.callees.size(), ms);
}

//=============================================================================
// VTable index
//=============================================================================

inline void build_vtable_index(TreeLogger& logger) {
    auto start = std::chrono::high_resolution_clock::now();

    size_t ptr_size = inf_is_64bit() ? 8 : 4;

    for (int i = 0; i < get_segm_qty(); ++i) {
        segment_t* seg = getnseg(i);
        if (!seg) continue;

        qstring seg_name;
        get_segm_name(&seg_name, seg);

        bool is_data_seg = (seg->type == SEG_DATA) ||
                           (seg_name.find(".data") != qstring::npos) ||
                           (seg_name.find(".rodata") != qstring::npos) ||
                           (seg_name.find(".rdata") != qstring::npos) ||
                           (seg_name.find("__const") != qstring::npos) ||
                           (seg_name.find("__data") != qstring::npos);

        if (!is_data_seg) continue;

        ea_t ea = seg->start_ea;
        while (ea < seg->end_ea && ea != BADADDR) {
            qstring name;
            if (get_name(&name, ea) > 0 && !name.empty()) {
                bool is_vtable = false;
                std::string vtable_name;

                if (name.find("_ZTV") == 0) {
                    is_vtable = true;
                    vtable_name = name.c_str();
                } else if (name.find("??_7") == 0) {
                    is_vtable = true;
                    vtable_name = name.c_str();
                } else if (name.find("vtable for") != qstring::npos ||
                           name.find("`vftable'") != qstring::npos ||
                           name.find("_vftable") != qstring::npos) {
                    is_vtable = true;
                    vtable_name = name.c_str();
                }

                if (is_vtable) {
                    GlobalIndex::VTableEntry vt;
                    vt.name = vtable_name;
                    vt.start_ea = ea;
                    vt.demangled = rtti_parser::gcc_rtti::extract_class_from_mangled(vtable_name);

                    ea_t ptr_ea = ea;
                    if (vtable_name.find("_ZTV") == 0) {
                        ptr_ea += ptr_size * 2;  // Skip offset-to-top + RTTI
                    }

                    while (ptr_ea < seg->end_ea) {
                        ea_t func_ea = inf_is_64bit() ? get_qword(ptr_ea) : get_dword(ptr_ea);

                        if (func_ea == 0 || func_ea == BADADDR) break;

                        // Stop at next real named symbol
                        qstring next_name;
                        if (ptr_ea != ea && get_name(&next_name, ptr_ea) > 0 && !next_name.empty()) {
                            if (next_name.find("off_") != 0 &&
                                next_name.find("qword_") != 0 &&
                                next_name.find("unk_") != 0 &&
                                next_name.find("byte_") != 0 &&
                                next_name.find("word_") != 0 &&
                                next_name.find("dword_") != 0) {
                                break;
                            }
                        }

                        if (!is_func(get_flags(func_ea))) {
                            ptr_ea += ptr_size;
                            continue;
                        }

                        // resolve thunks
                        {
                            func_t* thunk_f = get_func(func_ea);
                            if (thunk_f && (thunk_f->end_ea - thunk_f->start_ea) < 64) {
                                insn_t thunk_insn;
                                for (ea_t sca = thunk_f->start_ea; sca < thunk_f->end_ea; ) {
                                    if (decode_insn(&thunk_insn, sca) == 0) break;
                                    if (thunk_insn.itype == NN_jmp ||
                                        thunk_insn.itype == NN_jmpfi ||
                                        thunk_insn.itype == NN_jmpni) {
                                        if (thunk_insn.Op1.type == o_near ||
                                            thunk_insn.Op1.type == o_far) {
                                            ea_t jt = thunk_insn.Op1.addr;
                                            func_t* tf = get_func(jt);
                                            if (tf && tf->start_ea == jt) {
                                                func_ea = jt;
                                                break;
                                            }
                                        }
                                    }
                                    sca = thunk_insn.ea + thunk_insn.size;
                                }
                            }
                        }

                        uint32_t slot = static_cast<uint32_t>(vt.slots.size());
                        vt.slots.push_back(func_ea);
                        g_index.func_to_vtables[func_ea].push_back({vtable_name, slot});

                        ptr_ea += ptr_size;
                        if (vt.slots.size() > 500) break;
                    }

                    if (!vt.slots.empty()) {
                        g_index.vtables[vtable_name] = std::move(vt);
                    }
                }
            }
            ea = next_head(ea, seg->end_ea);
        }
    }

    for (const auto& [vtname, vt] : g_index.vtables) {
        if (!vt.demangled.empty()) {
            g_index.class_to_vtname[vt.demangled] = vtname;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    logger.item(false, "VTables: %zu tables, %zu func mappings, %zu class index (%lldms)",
        g_index.vtables.size(), g_index.func_to_vtables.size(),
        g_index.class_to_vtname.size(), ms);
}

//=============================================================================
// Data ptr index
//=============================================================================

inline void build_data_ptr_index(TreeLogger& logger) {
    auto start = std::chrono::high_resolution_clock::now();

    size_t ptr_size = inf_is_64bit() ? 8 : 4;

    // sorted vtable ranges for overlap check
    std::vector<std::pair<ea_t, ea_t>> vtable_ranges;
    vtable_ranges.reserve(g_index.vtables.size());
    for (const auto& [vtname, vtinfo] : g_index.vtables) {
        ea_t vt_start = vtinfo.start_ea + (2 * ptr_size);
        ea_t vt_end = vt_start + (vtinfo.slots.size() * ptr_size);
        vtable_ranges.push_back({vt_start, vt_end});
    }
    std::sort(vtable_ranges.begin(), vtable_ranges.end());

    for (int i = 0; i < get_segm_qty(); ++i) {
        segment_t* seg = getnseg(i);
        if (!seg) continue;

        qstring seg_name;
        get_segm_name(&seg_name, seg);

        if (seg->type != SEG_DATA &&
            seg_name.find(".data") == qstring::npos &&
            seg_name.find(".rodata") == qstring::npos &&
            seg_name.find(".rdata") == qstring::npos) continue;

        for (ea_t ea = seg->start_ea; ea + ptr_size <= seg->end_ea; ea += ptr_size) {
            ea_t ptr_val = inf_is_64bit() ? get_qword(ea) : get_dword(ea);
            if (ptr_val == 0 || ptr_val == BADADDR) continue;
            if (!is_func(get_flags(ptr_val))) continue;

            // skip vtable pointers
            auto it = std::upper_bound(vtable_ranges.begin(), vtable_ranges.end(),
                std::make_pair(ea, (ea_t)BADADDR));
            bool in_vtable = false;
            if (it != vtable_ranges.begin()) {
                --it;
                if (ea >= it->first && ea < it->second) in_vtable = true;
            }
            if (in_vtable) continue;

            // resolve wrappers
            ea_t final_target = ptr_val;
            func_t* f = get_func(ptr_val);
            if (f && (f->end_ea - f->start_ea) < 64) {
                insn_t insn;
                for (ea_t scan_ea = f->start_ea; scan_ea < f->end_ea; ) {
                    if (decode_insn(&insn, scan_ea) == 0) break;
                    if (insn.itype == NN_jmp || insn.itype == NN_jmpfi || insn.itype == NN_jmpni) {
                        if (insn.Op1.type == o_near || insn.Op1.type == o_far) {
                            ea_t jmp_target = insn.Op1.addr;
                            func_t* target_func = get_func(jmp_target);
                            if (target_func && target_func->start_ea == jmp_target) {
                                final_target = jmp_target;
                                break;
                            }
                        }
                    }
                    scan_ea = insn.ea + insn.size;
                }
            }

            g_index.data_func_ptrs.push_back({ea, final_target});

            // reverse index for landmark detection
            if (seg_name.find(".data") != qstring::npos) {
                g_index.func_to_data_seg_ptrs[final_target].push_back(ea);
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    logger.item(false, "Data pointers: %zu (.data reverse: %zu) (%lldms)",
        g_index.data_func_ptrs.size(), g_index.func_to_data_seg_ptrs.size(), ms);
}

//=============================================================================
// Library funcs
//=============================================================================

inline void build_library_index(TreeLogger& logger) {
    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < get_import_module_qty(); ++i) {
        qstring modname;
        if (get_import_module_name(&modname, i) <= 0) continue;

        struct enum_ctx { GlobalIndex* idx; };
        enum_ctx ctx{&g_index};

        enum_import_names(i, [](ea_t ea, const char* name, uval_t, void* param) -> int {
            auto* ctx = static_cast<enum_ctx*>(param);
            if (ea != BADADDR && name && name[0]) {
                ctx->idx->library_funcs.insert(ea);
                ctx->idx->library_names[ea] = name;
            }
            return 1;
        }, &ctx);
    }

    for (size_t i = 0; i < get_func_qty(); ++i) {
        func_t* f = getn_func(i);
        if (!f) continue;

        qstring name;
        if (get_func_name(&name, f->start_ea) <= 0) continue;

        std::string sname = name.c_str();
        bool is_lib = false;

        if (sname.find("@plt") != std::string::npos ||
            sname.find(".plt") != std::string::npos) {
            is_lib = true;
        } else if (sname.find("j_") == 0 || sname.find("_imp_") == 0) {
            is_lib = true;
        } else if (sname.find("std::") == 0 ||
                   sname.find("__cxa_") == 0 ||
                   sname.find("__gxx_") == 0) {
            is_lib = true;
        }

        if (is_lib) {
            g_index.library_funcs.insert(f->start_ea);
            if (g_index.library_names.find(f->start_ea) == g_index.library_names.end()) {
                g_index.library_names[f->start_ea] = sname;
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    logger.item(true, "Library funcs: %zu (%lldms)", g_index.library_funcs.size(), ms);
}

//=============================================================================
// ConVar helpers (lazy indexed)
//=============================================================================

inline bool is_convar_string(const std::string& s) {
    if (s.length() < 4 || s.length() > 64) return false;

    static constexpr const char* prefixes[] = {
        "sv_", "mp_", "cl_", "tv_", "net_", "r_", "mat_",
        "snd_", "demo_", "con_"
    };

    bool has_prefix = false;
    for (const char* p : prefixes) {
        if (s.rfind(p, 0) == 0) { has_prefix = true; break; }
    }
    if (!has_prefix) return false;

    for (char c : s) {
        if (c == '_') continue;
        if (!std::isalnum(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

inline std::string pick_best_convar_string(const std::vector<std::string>& strings) {
    std::string best;
    for (const auto& s : strings) {
        if (!is_convar_string(s)) continue;
        if (s.length() > best.length()) best = s;
    }
    return best;
}

inline std::vector<ea_t> collect_data_xrefs(ea_t fea) {
    std::vector<ea_t> data_refs;
    func_t* f = get_func(fea);
    if (!f) return data_refs;

    std::unordered_set<ea_t> seen;
    for (ea_t ea = f->start_ea; ea < f->end_ea; ) {
        xrefblk_t xb;
        for (bool ok = xb.first_from(ea, XREF_DATA); ok; ok = xb.next_from()) {
            ea_t data_ea = xb.to;
            segment_t* seg = getseg(data_ea);
            if (!seg) continue;
            if (seg->type != SEG_DATA &&
                seg->perm != (SEGPERM_READ | SEGPERM_WRITE) &&
                seg->perm != SEGPERM_READ) continue;

            flags_t flags = get_flags(data_ea);
            if (!is_data(flags) || is_strlit(flags)) continue;

            size_t item_size = get_item_size(data_ea);
            size_t ptr_size = inf_is_64bit() ? 8 : 4;
            if (item_size < ptr_size) continue;

            if (seen.insert(data_ea).second) {
                data_refs.push_back(data_ea);
            }
        }
        ea = next_head(ea, f->end_ea);
        if (ea == BADADDR) break;
    }

    return data_refs;
}

inline std::vector<ea_t> get_functions_referencing_data(ea_t data_ea) {
    std::vector<ea_t> funcs;
    std::unordered_set<ea_t> seen;

    xrefblk_t xb;
    for (bool ok = xb.first_to(data_ea, XREF_DATA); ok; ok = xb.next_to()) {
        func_t* f = get_func(xb.from);
        if (!f) continue;
        if (seen.insert(f->start_ea).second) {
            funcs.push_back(f->start_ea);
        }
    }
    return funcs;
}

inline bool ensure_convar_index_for_qword(ea_t qword_ea) {
    if (g_index.convar_qword_scanned.count(qword_ea)) {
        return g_index.convar_qword_to_name.find(qword_ea) != g_index.convar_qword_to_name.end();
    }
    g_index.convar_qword_scanned.insert(qword_ea);

    auto funcs = get_functions_referencing_data(qword_ea);
    if (funcs.empty()) return false;

    std::string convar_name;
    std::unordered_set<ea_t> reg_funcs;

    for (ea_t fea : funcs) {
        auto it = g_index.func_to_strings.find(fea);
        if (it == g_index.func_to_strings.end()) continue;

        std::string candidate = pick_best_convar_string(it->second);
        if (candidate.empty()) continue;

        if (convar_name.empty()) {
            convar_name = candidate;
        } else if (candidate != convar_name) {
            return false;
        }
        reg_funcs.insert(fea);
    }

    if (convar_name.empty()) return false;

    g_index.convar_qword_to_name[qword_ea] = convar_name;

    std::vector<ea_t> use_funcs;
    bool has_non_reg = (funcs.size() > reg_funcs.size());
    for (ea_t fea : funcs) {
        if (has_non_reg && reg_funcs.count(fea)) continue;
        use_funcs.push_back(fea);
    }

    auto& existing = g_index.convar_name_to_funcs[convar_name];
    std::unordered_set<ea_t> merged(existing.begin(), existing.end());
    for (ea_t fea : use_funcs) {
        if (merged.insert(fea).second) {
            existing.push_back(fea);
        }
    }

    return true;
}

inline bool ensure_convar_index_for_name(const std::string& name) {
    if (g_index.convar_name_scanned.count(name)) {
        return g_index.convar_name_to_funcs.find(name) != g_index.convar_name_to_funcs.end();
    }
    g_index.convar_name_scanned.insert(name);

    auto sit = g_index.string_to_funcs.find(name);
    if (sit == g_index.string_to_funcs.end() || sit->second.empty()) return false;

    for (ea_t fea : sit->second) {
        auto data_refs = collect_data_xrefs(fea);
        for (ea_t data_ea : data_refs) {
            ensure_convar_index_for_qword(data_ea);
        }
    }

    return g_index.convar_name_to_funcs.find(name) != g_index.convar_name_to_funcs.end();
}

//=============================================================================
// Code image (parallel sig scan)
//=============================================================================

inline void build_code_index(TreeLogger& logger) {
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < get_segm_qty(); ++i) {
        segment_t* seg = getnseg(i);
        if (!seg || seg->type != SEG_CODE) continue;

        GlobalIndex::CodeSection cs;
        cs.start_ea = seg->start_ea;
        size_t size = static_cast<size_t>(seg->end_ea - seg->start_ea);
        cs.bytes.resize(size);
        
        if (get_bytes(cs.bytes.data(), size, seg->start_ea) > 0) {
            g_index.code_sections.push_back(std::move(cs));
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    logger.item(false, "CodeImage: %zu sections indexed (%lldms)", g_index.code_sections.size(), ms);
}

//=============================================================================
// Build everything
//=============================================================================

inline void GlobalIndex::build(TreeLogger& logger) {
    logger.section("Building Global Index");
    logger.open_branch(false, "Indexing binary");
    auto start = std::chrono::high_resolution_clock::now();

    clear();

    build_string_index(logger);
    build_vtable_index(logger);
    build_callgraph_index(logger);
    build_data_ptr_index(logger);
    build_library_index(logger);
    build_code_index(logger);

    ready = true;

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    logger.close_branch();
    logger.item(false, "Index ready (total: %lldms)", ms);
}

} // namespace tracker

#endif // K4_TRACKER_INDEX_H
