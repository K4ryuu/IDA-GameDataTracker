/*
 * crawler/base.h - identity + reinforcement analysis
 */

#ifndef K4_TRACKER_CRAWLER_BASE_H
#define K4_TRACKER_CRAWLER_BASE_H

#include "core/types.h"
#include "core/index.h"

#include <ida.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#ifndef K4T_ALLINS_INCLUDED
#define K4T_ALLINS_INCLUDED
#include <allins.hpp>
#endif

#include <set>

namespace tracker {
namespace base {

//=============================================================================
// Identity analysis
//=============================================================================

inline Identity analyze_identity(ea_t fea) {
    Identity id;

    func_t* f = get_func(fea);
    if (!f) return id;

    tinfo_t ti;
    if (get_tinfo(&ti, fea)) {
        func_type_data_t ftd;
        if (ti.get_func_details(&ftd)) {
            id.param_count = static_cast<uint8_t>(ftd.size());
            id.has_return = !ftd.rettype.is_void();

            qstring ret_str;
            if (ftd.rettype.print(&ret_str)) {
                id.return_type = ret_str.c_str();
            }

            for (size_t i = 0; i < ftd.size(); ++i) {
                qstring param_str;
                if (ftd[i].type.print(&param_str)) {
                    id.param_types.push_back(param_str.c_str());
                }
            }
        }
    }

    ea_t ea = f->start_ea;
    while (ea < f->end_ea) {
        insn_t insn;
        if (decode_insn(&insn, ea) > 0) {
            if (insn.itype == NN_call || insn.itype == NN_callfi || insn.itype == NN_callni) {
                if (insn.ops[0].type == o_reg || insn.ops[0].type == o_phrase ||
                    insn.ops[0].type == o_displ) {
                    id.has_indirect_call = true;
                }
            }
            if (insn.itype == NN_jmp || insn.itype == NN_jmpfi || insn.itype == NN_jmpni) {
                if (insn.ops[0].type == o_reg || insn.ops[0].type == o_phrase) {
                    id.has_switch = true;
                }
            }

            // bitflags
            if (insn.itype >= NN_ja && insn.itype <= NN_jz) {
                if (insn.ops[0].type == o_near && insn.ops[0].addr < ea) {
                    id.struct_flags |= identity_flags::HAS_LOOP;
                }
            }
            if (insn.itype == NN_loop || insn.itype == NN_loope || insn.itype == NN_loopne) {
                id.struct_flags |= identity_flags::HAS_LOOP;
            }

            if (insn.itype == NN_movss || insn.itype == NN_movsd ||
                insn.itype == NN_addss || insn.itype == NN_addsd ||
                insn.itype == NN_subss || insn.itype == NN_subsd ||
                insn.itype == NN_mulss || insn.itype == NN_mulsd ||
                insn.itype == NN_divss || insn.itype == NN_divsd ||
                insn.itype == NN_comiss || insn.itype == NN_comisd ||
                insn.itype == NN_ucomiss || insn.itype == NN_ucomisd ||
                insn.itype == NN_cvtss2sd || insn.itype == NN_cvtsd2ss) {
                id.struct_flags |= identity_flags::HAS_FLOAT_OPS;
            }

            if (insn.itype == NN_movaps || insn.itype == NN_movups ||
                insn.itype == NN_movapd || insn.itype == NN_movupd ||
                insn.itype == NN_addps || insn.itype == NN_addpd ||
                insn.itype == NN_mulps || insn.itype == NN_mulpd) {
                id.struct_flags |= identity_flags::HAS_SIMD;
            }

            if (insn.itype == NN_div || insn.itype == NN_idiv) {
                id.struct_flags |= identity_flags::HAS_DIV;
            }

            if (insn.itype == NN_imul) {
                id.struct_flags |= identity_flags::HAS_MUL;
            }

            if (insn.itype == NN_sub && insn.ops[0].type == o_reg &&
                insn.ops[0].reg == 0x04 /* RSP */ && insn.ops[1].type == o_imm &&
                insn.ops[1].value > 256) {
                id.struct_flags |= identity_flags::HAS_LARGE_STACK;
            }

            if (insn.itype == NN_rep || insn.itype == NN_repe || insn.itype == NN_repne) {
                id.struct_flags |= identity_flags::HAS_REP_OPS;
            }

            if (insn.itype >= NN_cmova && insn.itype <= NN_cmovz) {
                id.struct_flags |= identity_flags::HAS_CMOV;
            }
        }
        ea = next_head(ea, f->end_ea);
    }

    return id;
}

//=============================================================================
// Reinforcement analysis
//=============================================================================

inline Reinforcement analyze_reinforcement(ea_t fea, const GlobalIndex& index) {
    Reinforcement rf;

    func_t* f = get_func(fea);
    if (!f) return rf;

    rf.size = static_cast<uint32_t>(f->end_ea - f->start_ea);

    qflow_chart_t fc("", f, f->start_ea, f->end_ea, 0);
    rf.bb_count = static_cast<uint16_t>(fc.size());

    int edges = 0;
    for (int i = 0; i < fc.size(); ++i) {
        edges += fc.nsucc(i);
    }
    rf.cyclomatic = static_cast<uint16_t>(edges - fc.size() + 2);

    rf.caller_count = index.get_caller_count(fea);
    rf.callee_count = index.get_callee_count(fea);

    auto it = index.func_to_strings.find(fea);
    if (it != index.func_to_strings.end()) {
        for (const auto& s : it->second) {
            if (s.length() >= config::MIN_STRING_LENGTH) {
                rf.strings.push_back(s);
            }
        }
    }

    {
        std::set<uint64_t> const_set;
        ea_t cea = f->start_ea;
        while (cea < f->end_ea) {
            insn_t insn;
            if (decode_insn(&insn, cea) > 0) {
                for (int opn = 0; opn < UA_MAXOP; ++opn) {
                    if (insn.ops[opn].type == o_void) break;
                    if (insn.ops[opn].type == o_imm) {
                        uint64_t val = insn.ops[opn].value;
                        if (val > 0xFF && val != 0xFFFFFFFF && val != 0xFFFFFFFFFFFFFFFF
                            && val != 0x100 && val != 0x200 && val != 0x400 && val != 0x800) {
                            const_set.insert(val);
                        }
                    }
                    if ((insn.itype == NN_movss || insn.itype == NN_movsd) &&
                        insn.ops[opn].type == o_mem) {
                        ea_t addr = insn.ops[opn].addr;
                        if (addr != BADADDR) {
                            uint32_t raw = get_dword(addr);
                            if (raw != 0 && raw != 0x3F800000 /* 1.0f */) {
                                const_set.insert(raw);
                            }
                        }
                    }
                }
            }
            cea = next_head(cea, f->end_ea);
        }
        rf.constants.assign(const_set.begin(), const_set.end());
    }

    return rf;
}

} // namespace base
} // namespace tracker

#endif // K4_TRACKER_CRAWLER_BASE_H
