/* utils/signature.h - sig gen + prologue detection */

#ifndef K4_TRACKER_SIGNATURE_H
#define K4_TRACKER_SIGNATURE_H

#include "core/types.h"
#include "core/config.h"

#include <ida.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <ua.hpp>
#include <segment.hpp>
#ifndef K4T_ALLINS_INCLUDED
#define K4T_ALLINS_INCLUDED
#include <allins.hpp>
#endif

namespace tracker {
namespace sig {

inline int get_imm_offset(const insn_t& insn) {
    for (int i = 0; i < UA_MAXOP; ++i) {
        const op_t& op = insn.ops[i];
        if (op.type == o_void) return 0;
        if (op.offb > 0) return op.offb;
    }
    return 0;
}

inline void trim(Signature& sig) {
    while (!sig.mask.empty() && !sig.mask.back()) {
        sig.bytes.pop_back();
        sig.mask.pop_back();
    }

    size_t leading = 0;
    while (leading < sig.mask.size() && !sig.mask[leading]) {
        leading++;
    }
    if (leading > 0) {
        sig.bytes.erase(sig.bytes.begin(), sig.bytes.begin() + leading);
        sig.mask.erase(sig.mask.begin(), sig.mask.begin() + leading);
        sig.offset += static_cast<uint32_t>(leading);
    }
}

// pattern search (uses memory image if available)
inline ea_t find_first_match(const Signature& sig, ea_t start_at, ea_t ignore_ea) {
    if (sig.empty()) return BADADDR;

    if (g_index.ready && !g_index.code_sections.empty()) {
        size_t sig_len = sig.bytes.size();
        
        for (const auto& sec : g_index.code_sections) {
            if (start_at >= (sec.start_ea + sec.bytes.size())) continue;
            
            size_t start_offset = (start_at > sec.start_ea) ? (start_at - sec.start_ea) : 0;
            const uint8_t* data = sec.bytes.data();
            size_t data_len = sec.bytes.size();

            for (size_t i = start_offset; i + sig_len <= data_len; ++i) {
                ea_t current_ea = sec.start_ea + i;
                if (current_ea == ignore_ea) continue;

                bool match = true;
                for (size_t j = 0; j < sig_len; ++j) {
                    if (sig.mask[j] && data[i + j] != sig.bytes[j]) {
                        match = false;
                        break;
                    }
                }

                if (match) return current_ea;
            }
        }
        return BADADDR;
    }

    // fallback: bin_search (slow, not thread-safe)
    size_t len = sig.bytes.size();
    bytevec_t image, mask;
    image.resize(len);
    mask.resize(len);
    for (size_t i = 0; i < len; ++i) {
        image[i] = sig.bytes[i];
        mask[i] = sig.mask[i] ? 0xFF : 0x00;
    }

    ea_t ea_max = inf_get_max_ea();
    ea_t addr = (start_at > 0 ? start_at : inf_get_min_ea()) - 1;
    while (true) {
        addr = bin_search(addr + 1, ea_max,
            image.begin(), mask.begin(), len,
            BIN_SEARCH_FORWARD | BIN_SEARCH_CASE);
        if (addr == BADADDR) return BADADDR;
        if (addr == ignore_ea) continue;
        return addr;
    }
}

inline int process_instruction(ea_t addr, Signature& sig, func_item_iterator_t& iterator, ea_t ea_max) {
    insn_t insn;
    if (!decode_insn(&insn, addr)) return 0;

    func_t* func = get_func(addr);
    if (func != nullptr && addr >= func->end_ea) return 0;

    int imm_offset = get_imm_offset(insn);

    for (ea_t op_addr = addr; op_addr < (addr + insn.size); ++op_addr) {
        bool is_imm = imm_offset > 0 && (op_addr - addr) >= imm_offset;
        sig.bytes.push_back(get_byte(op_addr));
        sig.mask.push_back(!is_imm);
    }

    if (get_byte(addr) == 0xCC || get_byte(addr) == 0x90) {
        return 0; // int3 or nop = end of meaningful code
    }

    if (!iterator.next_not_tail()) return 0;
    return 1;
}

inline Signature make_signature(ea_t start_ea, ea_t end_ea, ea_t ignore_ea, uint32_t offset) {
    Signature sig;
    sig.offset = offset;

    if (start_ea == BADADDR) return {};

    ea_t ea_max = inf_get_max_ea();

    if (end_ea == BADADDR || end_ea <= start_ea) {
        func_t* f = get_func(start_ea);
        if (f) {
            end_ea = f->end_ea;
        } else {
            segment_t* seg = getseg(start_ea);
            if (!seg) return {};
            end_ea = seg->end_ea;
        }
    }

    ea_t last_found = inf_get_min_ea();

    func_item_iterator_t iterator;
    iterator.set_range(start_ea, end_ea);
    for (ea_t addr = iterator.current(); true; addr = iterator.current()) {
        int result = process_instruction(addr, sig, iterator, ea_max);
        if (result == 0) break;

        if (sig.bytes.size() >= config::MIN_SIGNATURE_LENGTH) {
            ea_t found = find_first_match(sig, last_found, ignore_ea);
            if (found == BADADDR) break;  // Unique!
            last_found = found;
        }
    }

    trim(sig);

    if (sig.bytes.size() < config::MIN_SIGNATURE_LENGTH) return {};

    return sig;
}

// detect prologue length
inline uint8_t detect_prologue_length(ea_t fea) {
    func_t* f = get_func(fea);
    if (!f) return 0;

    uint8_t prologue_len = 0;
    ea_t cur = fea;
    ea_t max_check = std::min(fea + 32, f->end_ea);

    while (cur < max_check) {
        insn_t insn;
        int insn_len = decode_insn(&insn, cur);
        if (insn_len <= 0) break;

        bool is_prologue = false;

        if (insn.itype == NN_push && insn.ops[0].type == o_reg) {
            int reg = insn.ops[0].reg;
            if (reg == 5 || reg == 3 || (reg >= 12 && reg <= 15)) {
                is_prologue = true;
            }
        }
        else if (insn.itype == NN_mov &&
                 insn.ops[0].type == o_reg && insn.ops[1].type == o_reg &&
                 insn.ops[0].reg == 5 && insn.ops[1].reg == 4) {
            is_prologue = true;
        }
        else if (insn.itype == NN_sub &&
                 insn.ops[0].type == o_reg && insn.ops[0].reg == 4) {
            is_prologue = true;
        }
        else if (insn.itype == NN_lea &&
                 insn.ops[0].type == o_reg && insn.ops[0].reg == 5) {
            is_prologue = true;
        }
        else if (insn.itype == NN_and &&
                 insn.ops[0].type == o_reg && insn.ops[0].reg == 4) {
            is_prologue = true;
        }

        if (!is_prologue) break;

        prologue_len += insn_len;
        cur += insn_len;

        if (prologue_len >= config::MAX_PROLOGUE_SKIP) break;
    }

    return prologue_len;
}

// mid-func context collection

inline std::vector<uint16_t> collect_mid_context(ea_t func_start, ea_t func_end,
                                                  ea_t target_ea, uint32_t radius)
{
    struct InsnInfo { ea_t ea; uint16_t itype; };
    std::vector<InsnInfo> insns;
    insns.reserve(256);

    ea_t cur = func_start;
    while (cur < func_end) {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0) break;
        insns.push_back({cur, insn.itype});
        cur += len;
    }

    if (insns.empty()) return {};
    int target_idx = -1;
    for (size_t i = 0; i < insns.size(); ++i) {
        ea_t insn_end = (i + 1 < insns.size()) ? insns[i + 1].ea : func_end;
        if (target_ea >= insns[i].ea && target_ea < insn_end) {
            target_idx = static_cast<int>(i);
            break;
        }
    }

    if (target_idx < 0) return {};

    uint32_t window = 2 * radius + 1;
    std::vector<uint16_t> ctx(window, config::MID_CONTEXT_NONE);

    for (uint32_t i = 0; i < window; ++i) {
        int idx = target_idx - static_cast<int>(radius) + static_cast<int>(i);
        if (idx >= 0 && idx < static_cast<int>(insns.size())) {
            ctx[i] = insns[idx].itype;
        }
    }

    return ctx;
}

// find best mid-func match

inline ea_t find_mid_context_match(ea_t func_start, ea_t func_end,
                                    const std::vector<uint16_t>& context,
                                    uint32_t radius, uint32_t min_score)
{
    if (context.empty()) return BADADDR;

    struct InsnInfo { ea_t ea; uint16_t itype; };
    std::vector<InsnInfo> insns;
    insns.reserve(256);

    ea_t cur = func_start;
    while (cur < func_end) {
        insn_t insn;
        int len = decode_insn(&insn, cur);
        if (len <= 0) break;
        insns.push_back({cur, insn.itype});
        cur += len;
    }

    if (insns.empty()) return BADADDR;

    uint32_t window = static_cast<uint32_t>(context.size());
    uint32_t ctx_valid = 0;
    for (uint16_t v : context) {
        if (v != config::MID_CONTEXT_NONE) ctx_valid++;
    }
    if (ctx_valid < min_score) return BADADDR;  // Not enough context to match

    ea_t best_ea = BADADDR;
    uint32_t best_score = 0;

    for (size_t center = 0; center < insns.size(); ++center) {
        uint32_t score = 0;
        for (uint32_t i = 0; i < window; ++i) {
            if (context[i] == config::MID_CONTEXT_NONE) continue;  // Skip padding
            int idx = static_cast<int>(center) - static_cast<int>(radius) + static_cast<int>(i);
            if (idx >= 0 && idx < static_cast<int>(insns.size())) {
                if (insns[idx].itype == context[i]) score++;
            }
        }

        if (score > best_score) {
            best_score = score;
            best_ea = insns[center].ea;
        }
    }

    if (best_score < min_score) return BADADDR;

    return best_ea;
}

} // namespace sig
} // namespace tracker

#endif // K4_TRACKER_SIGNATURE_H
