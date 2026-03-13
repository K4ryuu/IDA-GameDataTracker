/* pathfinder/pathfinder.h - match orchestrator */

#ifndef K4_TRACKER_PATHFINDER_H
#define K4_TRACKER_PATHFINDER_H

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"
#include "utils/logger.h"

// Validator
#include "pathfinder/validator.h"

// Finder modules
#include "pathfinder/signature_finder.h"
#include "pathfinder/string_finder.h"
#include "pathfinder/convar_finder.h"
#include "pathfinder/vtable_finder.h"
#include "pathfinder/library_finder.h"
#include "pathfinder/relational_finder.h"
#include "pathfinder/data_ptr_finder.h"
#include "pathfinder/proximity_finder.h"
#include "pathfinder/callchain_finder.h"
#include "pathfinder/xref_finder.h"

#include <ida.hpp>
#include <funcs.hpp>

#include <unordered_map>
#include <algorithm>
#include <thread>
#include <vector>
#include <mutex>
#include <future>

namespace tracker {
namespace pathfinder {

inline FinderResult dispatch_finder(const Anchor& anchor, const GlobalIndex& index) {
    switch (anchor.priority) {
        case ModulePriority::SIGNATURE:
            return finders::find_by_signature(anchor, index);
        case ModulePriority::UNIQUE_STR:
            return finders::find_by_string(anchor, index);
        case ModulePriority::CONVAR:
            return finders::find_by_convar(anchor, index);
        case ModulePriority::VTABLE:
            return {};
        case ModulePriority::LIBRARY:
            return finders::find_by_library(anchor, index);
        case ModulePriority::RELATIONAL:
            return {};
        case ModulePriority::DATA_PTR:
            return {};
        case ModulePriority::PROXIMITY:
            return finders::find_by_proximity(anchor, index);
        case ModulePriority::CALLCHAIN:
            return {};
        case ModulePriority::XREF:
            return {};
        default:
            return {};
    }
}

inline bool is_authoritative(ModulePriority p) {
    return p == ModulePriority::SIGNATURE
        || p == ModulePriority::UNIQUE_STR
        || p == ModulePriority::CONVAR;
}

struct StructuralCheck {
    uint32_t confirmed = 0;
    std::string detail;
};

inline StructuralCheck verify_structural(ea_t candidate,
                                          const std::vector<Anchor>& anchors,
                                          const std::vector<const FinderResult*>* voted_hits,
                                          const GlobalIndex& index)
{
    StructuralCheck sc;
    std::unordered_set<uint8_t> voted_types;
    if (voted_hits) {
        for (const auto* fr : *voted_hits) {
            voted_types.insert(static_cast<uint8_t>(fr->source));
        }
    }

    if (!voted_types.count(static_cast<uint8_t>(ModulePriority::VTABLE))) {
        auto ft_it = index.func_to_vtables.find(candidate);
        if (ft_it != index.func_to_vtables.end()) {
            for (const auto& anchor : anchors) {
                if (anchor.priority != ModulePriority::VTABLE) continue;
                if (anchor.name.empty()) continue;

                for (const auto& [vtname, slot] : ft_it->second) {
                    auto vt_it = index.vtables.find(vtname);
                    if (vt_it == index.vtables.end()) continue;

                    std::string norm_dem = !vt_it->second.demangled.empty()
                        ? finders::normalize_vtable_name(vt_it->second.demangled) : "";
                    bool name_match = (!norm_dem.empty() && norm_dem == anchor.name)
                                    || (vtname == anchor.name);
                    if (name_match) {
                        sc.confirmed++;
                        char buf[128];
                        qsnprintf(buf, sizeof(buf), "VTABLE_OK[%s:%u->%u]",
                            anchor.name.c_str(), anchor.index, slot);
                        if (!sc.detail.empty()) sc.detail += "+";
                        sc.detail += buf;
                        break;
                    }
                }
            }
        }
    }

    if (!voted_types.count(static_cast<uint8_t>(ModulePriority::DATA_PTR))) {
        bool has_dataptr_anchor = false;
        for (const auto& anchor : anchors) {
            if (anchor.priority == ModulePriority::DATA_PTR) {
                has_dataptr_anchor = true;
                break;
            }
        }
        if (has_dataptr_anchor) {
            for (const auto& [ptr_ea, func_ea] : index.data_func_ptrs) {
                if (func_ea == candidate) {
                    sc.confirmed++;
                    if (!sc.detail.empty()) sc.detail += "+";
                    sc.detail += "DATAPTR_OK";
                    break;
                }
            }
        }
    }

    if (!voted_types.count(static_cast<uint8_t>(ModulePriority::UNIQUE_STR))) {
        auto str_it = index.func_to_strings.find(candidate);
        if (str_it != index.func_to_strings.end()) {
            bool found_string = false;
            for (const auto& anchor : anchors) {
                if (anchor.priority != ModulePriority::UNIQUE_STR) continue;
                if (anchor.name.empty()) continue;

                for (const auto& s : str_it->second) {
                    if (s == anchor.name) {
                        found_string = true;
                        break;
                    }
                }
                if (found_string) {
                    sc.confirmed++;
                    if (!sc.detail.empty()) sc.detail += "+";
                    sc.detail += "STRING_OK";
                    break;
                }
            }
        }
    }

    return sc;
}

inline MatchResult match_function(const TrackedFunc& tf, GlobalIndex& index,
                                  const std::vector<FinderResult>& extra_hits = {}) {
    MatchResult result;
    std::vector<FinderResult> hits;
    for (const auto& anchor : tf.anchors) {
        if (anchor.priority == ModulePriority::RELATIONAL) {
            auto rels = finders::find_by_relational_all(anchor, index);
            for (auto& fr : rels) if (fr.candidate != BADADDR) hits.push_back(std::move(fr));
        } else if (anchor.priority == ModulePriority::VTABLE) {
            auto vts = finders::find_by_vtable_all(anchor, index);
            for (auto& fr : vts) if (fr.candidate != BADADDR) hits.push_back(std::move(fr));
        } else if (anchor.priority == ModulePriority::CALLCHAIN) {
            auto ccs = finders::find_by_callchain_all(anchor, index);
            for (auto& fr : ccs) if (fr.candidate != BADADDR) hits.push_back(std::move(fr));
        } else if (anchor.priority == ModulePriority::XREF) {
            auto xrs = finders::find_by_xref_all(anchor, index);
            for (auto& fr : xrs) if (fr.candidate != BADADDR) hits.push_back(std::move(fr));
        } else if (anchor.priority == ModulePriority::DATA_PTR) {
            auto dps = finders::find_by_data_ptr_all(anchor, index);
            for (auto& fr : dps) if (fr.candidate != BADADDR) hits.push_back(std::move(fr));
        } else {
            FinderResult fr = dispatch_finder(anchor, index);
            if (fr.candidate != BADADDR) hits.push_back(fr);
        }
    }

    for (const auto& eh : extra_hits) if (eh.candidate != BADADDR) hits.push_back(eh);
    if (hits.empty()) return result;

    for (auto& h : hits) {
        auto tit = index.thunk_map.find(h.candidate);
        if (tit != index.thunk_map.end()) h.candidate = tit->second;
    }

    std::unordered_map<ea_t, std::vector<const FinderResult*>> vote_map;
    for (const auto& h : hits) vote_map[h.candidate].push_back(&h);

    std::vector<ea_t> sorted_candidates;
    for (auto& [ea, frs] : vote_map) sorted_candidates.push_back(ea);
    std::sort(sorted_candidates.begin(), sorted_candidates.end(),
        [&vote_map](ea_t a, ea_t b) { return vote_map[a].size() > vote_map[b].size(); });

    std::vector<std::string> expected_vtable_classes;
    for (const auto& anchor : tf.anchors) {
        if (anchor.priority == ModulePriority::VTABLE && !anchor.name.empty())
            expected_vtable_classes.push_back(anchor.name);
    }

    struct CandidateScore { ea_t ea; uint32_t votes; ValidationResult vr; float weighted; };
    ea_t best_candidate = BADADDR;
    uint32_t best_votes = 0;
    const std::vector<const FinderResult*>* best_hits = nullptr;
    ValidationResult best_vr;
    const char* first_fail_reason = nullptr;

    std::vector<CandidateScore> scored_candidates;
    for (size_t i = 0; i < std::min<size_t>(sorted_candidates.size(), 5); ++i) {
        ea_t ea = sorted_candidates[i];
        ValidationResult vr = validate_candidate(ea, tf.identity, tf.reinforcement, index);
        if (vr.identity_ok && !expected_vtable_classes.empty()) {
            auto ft_it = index.func_to_vtables.find(ea);
            if (ft_it != index.func_to_vtables.end()) {
                bool class_match = false;
                for (const auto& [vtname, slot] : ft_it->second) {
                    std::string norm;
                    auto vt_it = index.vtables.find(vtname);
                    if (vt_it != index.vtables.end() && !vt_it->second.demangled.empty())
                        norm = finders::normalize_vtable_name(vt_it->second.demangled);
                    for (const auto& exp_cls : expected_vtable_classes)
                        if ((!norm.empty() && norm == exp_cls) || vtname == exp_cls) { class_match = true; break; }
                    if (class_match) break;
                }
                if (!class_match) { vr.identity_ok = false; vr.identity_fail_reason = "wrong_vtable_class"; }
            }
        }
        if (i == 0 && !vr.identity_ok) first_fail_reason = vr.identity_fail_reason;
        if (!vr.identity_ok) continue;

        if (vr.reinforcement < -0.3f) {
            bool has_auth = false;
            for (const auto* fr : vote_map[ea]) if (is_authoritative(fr->source)) { has_auth = true; break; }
            if (!has_auth) { if (i == 0) first_fail_reason = "structural_misfit"; continue; }
        }

        float multiplier = (vr.reinforcement < 0) ? (1.0f + vr.reinforcement) * (1.0f + vr.reinforcement)
                                                  : 1.0f + (vr.reinforcement * vr.reinforcement * 50.0f);
        scored_candidates.push_back({ea, (uint32_t)vote_map[ea].size(), vr, (float)vote_map[ea].size() * multiplier});
    }

    std::sort(scored_candidates.begin(), scored_candidates.end(), [](const CandidateScore& a, const CandidateScore& b) { return a.weighted > b.weighted; });
    if (!scored_candidates.empty()) {
        const auto& best = scored_candidates[0];
        best_candidate = best.ea; best_votes = best.votes; best_hits = &vote_map[best.ea]; best_vr = best.vr;
    }

    if (best_candidate == BADADDR || !best_hits) {
        ea_t top = sorted_candidates[0];
        result.verdict = MatchVerdict::NONE; result.matched_ea = top; result.votes = (uint32_t)vote_map[top].size();
        result.method = "IDENTITY_FAIL"; if (first_fail_reason) { result.method += "("; result.method += first_fail_reason; result.method += ")"; }
        return result;
    }

    result.identity_passed = true; result.reinforcement_score = best_vr.reinforcement;
    result.matched_ea = best_candidate; result.votes = best_votes;

    bool has_authoritative = false;
    std::vector<std::pair<const char*, uint32_t>> method_counts;
    for (const auto* fr : *best_hits) {
        const char* name = priority_name(fr->source);
        bool found = false;
        for (auto& [n, c] : method_counts) if (strcmp(n, name) == 0) { c++; found = true; break; }
        if (!found) method_counts.push_back({name, 1});
        if (is_authoritative(fr->source)) has_authoritative = true;
    }
    for (const auto& [name, count] : method_counts) {
        if (!result.method.empty()) result.method += "+";
        result.method += name; if (count > 1) result.method += "x" + std::to_string(count);
    }

    if (has_authoritative || best_votes >= config::MIN_ANY_VOTES) result.verdict = MatchVerdict::MATCH;
    else if (best_votes >= config::MIN_CONSENSUS_VOTES) {
        bool strong = false;
        for (const auto* fr : *best_hits) if (fr->source != ModulePriority::LIBRARY && fr->source != ModulePriority::PROXIMITY) { strong = true; break; }
        result.verdict = strong ? MatchVerdict::MATCH : MatchVerdict::AMBIGUOUS;
    } else result.verdict = MatchVerdict::AMBIGUOUS;

    if (result.verdict == MatchVerdict::MATCH && !has_authoritative && scored_candidates.size() > 1) {
        if (scored_candidates[1].weighted >= scored_candidates[0].weighted * 0.85f) {
            result.verdict = MatchVerdict::AMBIGUOUS; result.method += "(WEIGHT_TIE)";
        }
    }

    StructuralCheck sc = verify_structural(best_candidate, tf.anchors, best_hits, index);
    result.structural = sc.confirmed;
    if (sc.confirmed > 0) {
        result.method += "+" + sc.detail;
        if (result.verdict == MatchVerdict::AMBIGUOUS) result.verdict = MatchVerdict::MATCH;
    }
    return result;
}

struct MatchStats { uint32_t total = 0, survived = 0, matched = 0, ambiguous = 0, none = 0, pass2_rescued = 0; };

inline MatchStats match_all(std::vector<TrackedFunc>& funcs, GlobalIndex& index, TreeLogger& logger) {
    MatchStats stats; stats.total = (uint32_t)funcs.size();
    uint32_t need_matching = 0;
    std::vector<size_t> match_indices;
    for (size_t i = 0; i < funcs.size(); ++i) {
        if (funcs[i].match.verdict == MatchVerdict::MATCH) { stats.survived++; stats.matched++; }
        else { need_matching++; match_indices.push_back(i); }
    }
    if (need_matching == 0) { logger.item(true, "All survived"); return stats; }

    logger.open_branch(false, "Pass 1: Parallel Matching (%u functions, %u threads)", need_matching, std::thread::hardware_concurrency());
    
    std::mutex stats_mutex;
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;

    auto worker = [&](size_t start_idx, size_t end_idx) {
        for (size_t k = start_idx; k < end_idx; ++k) {
            size_t idx = match_indices[k];
            MatchResult mr = match_function(funcs[idx], index);
            std::lock_guard<std::mutex> lock(stats_mutex);
            funcs[idx].match = mr;
            if (mr.verdict == MatchVerdict::MATCH) stats.matched++;
            else if (mr.verdict == MatchVerdict::AMBIGUOUS) stats.ambiguous++;
            else stats.none++;
        }
    };

    std::vector<std::thread> threads;
    size_t grain_size = (match_indices.size() + num_threads - 1) / num_threads;
    for (unsigned int t = 0; t < num_threads; ++t) {
        size_t start = t * grain_size;
        size_t end = std::min(start + grain_size, match_indices.size());
        if (start < end) threads.emplace_back(worker, start, end);
    }
    for (auto& t : threads) t.join();

    for (size_t idx : match_indices) {
        const auto& tf = funcs[idx];
        if (tf.match.verdict == MatchVerdict::MATCH) logger.item(false, "✓ %-52s → 0x%llX", tf.name.c_str(), (unsigned long long)tf.match.matched_ea);
        else if (tf.match.verdict == MatchVerdict::AMBIGUOUS) logger.item(false, "? %-52s AMBIGUOUS", tf.name.c_str());
        else logger.item(false, "✗ %-52s NO MATCH", tf.name.c_str());
    }
    logger.close_branch();

    if (stats.matched >= 3 && (stats.none > 0 || stats.ambiguous > 0)) {
        int64_t dp_delta = finders::calibrate_data_ptr_delta(funcs, index);
        std::unordered_map<ea_t, ea_t> matched_map;
        for (const auto& tf : funcs) if (tf.match.verdict == MatchVerdict::MATCH) matched_map[tf.original_ea] = tf.match.matched_ea;

        logger.open_branch(true, "Pass 2: Parallel Retry (%u functions)", stats.none + stats.ambiguous);
        std::vector<size_t> p2_indices;
        for (size_t i = 0; i < funcs.size(); ++i) if (funcs[i].match.verdict != MatchVerdict::MATCH) p2_indices.push_back(i);

        threads.clear();
        grain_size = (p2_indices.size() + num_threads - 1) / num_threads;
        
        auto p2_worker = [&](size_t start_idx, size_t end_idx) {
            for (size_t k = start_idx; k < end_idx; ++k) {
                size_t idx = p2_indices[k];
                std::vector<FinderResult> extra;
                if (dp_delta != 0) {
                    for (const auto& a : funcs[idx].anchors) if (a.priority == ModulePriority::DATA_PTR) {
                        auto cals = finders::find_by_data_ptr_calibrated_all(a, index, dp_delta);
                        uint32_t added = 0;
                        for (auto& fr : cals) { if (++added > config::DATA_PTR_CAL_MAX_CANDIDATES) break; extra.push_back(std::move(fr)); }
                    }
                }
                for (const auto& a : funcs[idx].anchors) if (a.priority == ModulePriority::RELATIONAL) {
                    auto rels = finders::find_by_relational_matched_all(a, index, matched_map);
                    for (auto& fr : rels) extra.push_back(std::move(fr));
                }
                MatchResult mr = match_function(funcs[idx], index, extra);
                std::lock_guard<std::mutex> lock(stats_mutex);
                if (mr.verdict == MatchVerdict::MATCH) {
                    funcs[idx].match = mr; funcs[idx].match.method = "PASS2+" + mr.method;
                    stats.matched++; stats.pass2_rescued++;
                }
            }
        };

        for (unsigned int t = 0; t < num_threads; ++t) {
            size_t start = t * grain_size;
            size_t end = std::min(start + grain_size, p2_indices.size());
            if (start < end) threads.emplace_back(p2_worker, start, end);
        }
        for (auto& t : threads) t.join();

        for (size_t idx : p2_indices) {
            if (funcs[idx].match.verdict == MatchVerdict::MATCH) logger.item(false, "✓ %-52s RESCUED", funcs[idx].name.c_str());
        }
        logger.close_branch();
    }
    return stats;
}

} // namespace pathfinder
} // namespace tracker

#endif // K4_TRACKER_PATHFINDER_H