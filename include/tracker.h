/*
 * tracker.h - Main plugin entry point (actions, menus, context menus)
 *
 * Menu structure (Edit > Plugins >):
 *   GDT: Track Function         — Add cursor function to tracking
 *   GDT: Backtrack              — Import old tracking data + match in new binary
 *   GDT: Import Gamedata        — Import community gamedata → track + crawl
 *   GDT: Tracked Functions      — Open browser table
 *   GDT: Generate Signature     — Quick sig + clipboard
 *   GDT: Export Gamedata        — Export matched → CSS/Swiftly
 */

#ifndef K4_TRACKER_MAIN_H
#define K4_TRACKER_MAIN_H

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <expr.hpp>
#include <name.hpp>

#include "core/types.h"
#include "core/config.h"
#include "core/index.h"
#include "crawler/crawler.h"
#include "io/serialize.h"
#include "io/deserialize.h"
#include "io/gamedata.h"
#include "pathfinder/pathfinder.h"
#include "chooser.h"
#include "utils/logger.h"
#include "utils/signature.h"

namespace tracker {

//=============================================================================
// Plugin info
//=============================================================================

#define K4T_NAME    "GameDataTracker"
#define K4T_VERSION "1.0.0"

//=============================================================================
// Action IDs
//=============================================================================

#define K4T_ACTION_TRACK       "gamedata_tracker:track"
#define K4T_ACTION_BACKTRACK   "gamedata_tracker:backtrack"
#define K4T_ACTION_IMPORT_GD   "gamedata_tracker:import_gamedata"
#define K4T_ACTION_BROWSER     "gamedata_tracker:browser"
#define K4T_ACTION_GENSIG      "gamedata_tracker:gensig"
#define K4T_ACTION_EXPORT_GD   "gamedata_tracker:export_gamedata"

//=============================================================================
// Helpers
//=============================================================================

inline std::string get_binary_filename() {
    char buf[MAXSTR];
    get_root_filename(buf, sizeof(buf));
    return buf;
}

inline std::string get_library_name() {
    std::string name = get_binary_filename();
    
    size_t dot = name.rfind('.');
    if (dot != std::string::npos) name = name.substr(0, dot);

    if (name.size() > 3 && name.compare(0, 3, "lib") == 0) {
        name = name.substr(3);
    }
    
    return name;
}

inline std::string get_default_save_path() {
    char buf[MAXSTR];
    get_input_file_path(buf, sizeof(buf));
    std::string path = buf;
    size_t dot = path.rfind('.');
    if (dot != std::string::npos) path = path.substr(0, dot);
    path += ".gamedata_tracker.json";
    return path;
}

inline void auto_load() {
    std::string path = get_default_save_path();
    if (qfileexist(path.c_str())) {
        std::vector<TrackedFunc> funcs;
        std::string json_binary;
        if (io::deserialize(path.c_str(), funcs, json_binary)) {
            std::string current_binary = get_binary_filename();
            
            // same binary = trust addresses
            bool same_binary = (json_binary == current_binary);
            
            for (auto& tf : funcs) {
                if (same_binary) {
                    tf.match.verdict = MatchVerdict::MATCH;
                    tf.match.matched_ea = tf.original_ea;
                    tf.match.method = "LOADED";
                    tf.match.votes = 1;
                    tf.match.identity_passed = true;
                    tf.match.reinforcement_score = 1.0f;
                } else {
                    // different binary, needs backtrack
                    tf.match.verdict = MatchVerdict::NONE;
                }
            }

            ui::g_cache.functions = std::move(funcs);
            ui::g_cache.binary_name = current_binary;
            ui::g_cache.loaded_from = path;
            ui::g_cache.modified = false;
            
            msg("GDT: Auto-loaded %zu functions from %s%s\n", 
                ui::g_cache.functions.size(), path.c_str(),
                same_binary ? " (Verified)" : " (New version - Backtrack required)");

            ui::refresh_tracked_chooser();
        }
    }
}

//=============================================================================
// Action: Track Function at cursor
//=============================================================================

struct action_track_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t*) override {
        ea_t ea = get_screen_ea();
        func_t* f = get_func(ea);
        if (!f) {
            warning("GDT: Cursor is not in a function");
            return 0;
        }

        for (const auto& tf : ui::g_cache.functions) {
            if (tf.original_ea == f->start_ea) {
                warning("GDT: Function already tracked");
                return 0;
            }
        }

        TreeLogger logger;
        crawler::ensure_index(logger);

        CrawlResult cr = crawler::crawl_verbose(f->start_ea, logger);

        TrackedFunc tf;
        qstring fname;
        get_func_name(&fname, f->start_ea);
        tf.name = fname.c_str();
        tf.original_ea = f->start_ea;
        tf.identity = std::move(cr.identity);
        tf.reinforcement = std::move(cr.reinforcement);
        tf.anchors = std::move(cr.anchors);

        tf.export_sig = sig::make_signature(f->start_ea, BADADDR, f->start_ea, 0);
        tf.prologue_length = sig::detect_prologue_length(f->start_ea);
        if (tf.prologue_length > 0 && (f->end_ea - f->start_ea) > config::MIN_FUNC_SIZE_FOR_SKIP) {
            ea_t skip_ea = f->start_ea + tf.prologue_length;
            tf.tracking_sig = sig::make_signature(skip_ea, f->end_ea, skip_ea, tf.prologue_length);
        }
        if (tf.tracking_sig.empty()) {
            tf.tracking_sig = tf.export_sig;
        }

        ui::g_cache.functions.push_back(std::move(tf));
        ui::g_cache.modified = true;

        msg("GDT: Now tracking '%s' (0x%llX) — %zu anchors\n",
            fname.c_str(), (unsigned long long)f->start_ea,
            ui::g_cache.functions.back().anchors.size());

        std::string path = get_default_save_path();
        io::serialize(ui::g_cache.functions, get_binary_filename(), path.c_str());
        ui::g_cache.modified = false;

        ui::refresh_tracked_chooser();
        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return get_func(get_screen_ea()) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE;
    }
};

//=============================================================================
// Action: Backtrack
//=============================================================================

struct action_backtrack_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t*) override {
        const char* path = ask_file(false, "*.gamedata_tracker.json;*.json",
            "Select previous version tracking file");
        if (!path) return 0;

        std::vector<TrackedFunc> funcs;
        std::string old_binary;
        if (!io::deserialize(path, funcs, old_binary)) {
            warning("GDT: Failed to load tracking file");
            return 0;
        }

        msg("\nGDT: Loaded %zu functions from %s (binary: %s)\n",
            funcs.size(), path, old_binary.c_str());

        TreeLogger logger;
        logger.header("Backtrack");
        crawler::ensure_index(logger);

        // pre-validate: unique sig match = SURVIVED, skip pathfinder
        // vtable entries always need full check

        show_wait_box("GDT: Pre-validating signatures...");

        uint32_t survived = 0, broken = 0, vtable_need_check = 0;
        logger.open_branch(false, "Pre-validation: Signature scan (%zu functions)", funcs.size());

        for (size_t i = 0; i < funcs.size(); ++i) {
            auto& tf = funcs[i];
            bool is_last = (i + 1 == funcs.size());

            replace_wait_box("GDT: [PRE-CHECK] %zu/%zu — %s",
                i + 1, funcs.size(), tf.name.c_str());

            if (tf.vtable_offset >= 0) {
                vtable_need_check++;
                continue; // leave match as NONE → pathfinder will handle
            }

            if (tf.tracking_sig.empty()) {
                broken++;
                logger.item(is_last, "%-52s  BROKEN (no tracking sig)",
                    tf.name.c_str());
                continue;
            }

            ea_t match_ea = sig::find_first_match(tf.tracking_sig, 0, BADADDR);
            if (match_ea == BADADDR) {
                broken++;
                logger.item(is_last, "%-52s  BROKEN (sig not found)",
                    tf.name.c_str());
                continue;
            }

            ea_t second = sig::find_first_match(tf.tracking_sig, match_ea + 1, BADADDR);
            if (second != BADADDR) {
                broken++;
                logger.item(is_last, "%-52s  BROKEN (sig not unique)",
                    tf.name.c_str());
                continue;
            }

            func_t* f = get_func(match_ea);
            if (!f) {
                broken++;
                logger.item(is_last, "%-52s  BROKEN (not in function)",
                    tf.name.c_str());
                continue;
            }

            tf.match.verdict = MatchVerdict::MATCH;
            tf.match.matched_ea = f->start_ea;
            tf.match.method = "SURVIVED";
            tf.match.votes = 1;
            tf.match.identity_passed = true;
            tf.match.reinforcement_score = 1.0f;
            survived++;

            logger.item(is_last, "✓ %-52s  SURVIVED → 0x%llX",
                tf.name.c_str(), (unsigned long long)f->start_ea);
        }
        logger.close_branch();

        logger.item(false, "Pre-validation: %u survived, %u broken, %u vtable",
            survived, broken, vtable_need_check);

        pathfinder::MatchStats stats = pathfinder::match_all(funcs, g_index, logger);

        // regen sigs for broken matches only, survived keep theirs

        replace_wait_box("GDT: Regenerating signatures...");

        std::vector<size_t> regen_indices;
        regen_indices.reserve(funcs.size() / 2);
        for (size_t i = 0; i < funcs.size(); ++i) {
            const auto& tf = funcs[i];
            if (tf.match.verdict != MatchVerdict::MATCH || tf.match.matched_ea == BADADDR)
                continue;
            if (tf.match.method == "SURVIVED") continue;
            regen_indices.push_back(i);
        }
        uint32_t regen_total = static_cast<uint32_t>(regen_indices.size());

        logger.open_branch(false, "Signature regeneration (%u broken matched)", regen_total);

        uint32_t regen_count = 0;
        for (uint32_t regen_idx = 0; regen_idx < regen_total; ++regen_idx) {
            auto& tf = funcs[regen_indices[regen_idx]];
            bool regen_last = (regen_idx + 1 == regen_total);

            replace_wait_box("GDT: [SIG REGEN] %u/%u — %s",
                regen_idx + 1, regen_total, tf.name.c_str());

            func_t* f = get_func(tf.match.matched_ea);
            if (!f) {
                logger.item(regen_last, "%-52s  SKIP (func lost)", tf.name.c_str());
                continue;
            }

            if (tf.sig_offset > 0) {
                ea_t target_ea = f->start_ea + tf.sig_offset;

                // try to refine offset via instruction-type fingerprint
                bool refined = false;
                if (!tf.mid_context.empty()) {
                    ea_t ctx_ea = sig::find_mid_context_match(
                        f->start_ea, f->end_ea, tf.mid_context,
                        config::MID_CONTEXT_RADIUS, config::MID_CONTEXT_MIN_SCORE);
                    if (ctx_ea != BADADDR && ctx_ea != target_ea) {
                        target_ea = ctx_ea;
                        tf.sig_offset = static_cast<int32_t>(ctx_ea - f->start_ea);
                        refined = true;
                    }
                }

                if (target_ea < f->end_ea) {
                    tf.export_sig = sig::make_signature(target_ea, f->end_ea, target_ea, 0);

                    tf.mid_context = sig::collect_mid_context(
                        f->start_ea, f->end_ea, target_ea, config::MID_CONTEXT_RADIUS);

                    regen_count++;
                    if (refined) {
                        logger.item(regen_last, "%-52s  export=%zu bytes (mid-func +%d, context-refined)",
                            tf.name.c_str(), tf.export_sig.length(), tf.sig_offset);
                    } else {
                        logger.item(regen_last, "%-52s  export=%zu bytes (mid-func +%d)",
                            tf.name.c_str(), tf.export_sig.length(), tf.sig_offset);
                    }
                } else {
                    // offset OOB, reset to func start
                    tf.export_sig = sig::make_signature(f->start_ea, BADADDR, f->start_ea, 0);
                    tf.sig_offset = 0;
                    regen_count++;
                    logger.item(regen_last, "%-52s  export=%zu bytes (offset OOB, reset)",
                        tf.name.c_str(), tf.export_sig.length());
                }

                tf.prologue_length = sig::detect_prologue_length(f->start_ea);
                if (tf.prologue_length > 0 &&
                    (f->end_ea - f->start_ea) > config::MIN_FUNC_SIZE_FOR_SKIP) {
                    ea_t skip_ea = f->start_ea + tf.prologue_length;
                    tf.tracking_sig = sig::make_signature(skip_ea, f->end_ea, skip_ea, tf.prologue_length);
                }
                if (tf.tracking_sig.empty()) {
                    tf.tracking_sig = sig::make_signature(f->start_ea, BADADDR, f->start_ea, 0);
                }
                continue;
            }

            tf.export_sig = sig::make_signature(f->start_ea, BADADDR, f->start_ea, 0);
            tf.prologue_length = sig::detect_prologue_length(f->start_ea);
            if (tf.prologue_length > 0 &&
                (f->end_ea - f->start_ea) > config::MIN_FUNC_SIZE_FOR_SKIP) {
                ea_t skip_ea = f->start_ea + tf.prologue_length;
                tf.tracking_sig = sig::make_signature(skip_ea, f->end_ea, skip_ea, tf.prologue_length);
            }
            if (tf.tracking_sig.empty()) tf.tracking_sig = tf.export_sig;
            regen_count++;

            logger.item(regen_last, "%-52s  export=%zu bytes, tracking=%zu bytes (prologue=%u)",
                tf.name.c_str(),
                tf.export_sig.length(), tf.tracking_sig.length(),
                tf.prologue_length);
        }
        logger.close_branch();

        // update vtable offsets for matched funcs

        uint32_t vtable_checked = 0, vtable_updated = 0;
        for (const auto& tf : funcs) {
            if (tf.match.verdict != MatchVerdict::MATCH) continue;
            if (tf.vtable_offset < 0 || tf.vtable_class.empty()) continue;
            if (tf.match.matched_ea == BADADDR) continue;
            vtable_checked++;
        }

        if (vtable_checked > 0) {
            replace_wait_box("GDT: Updating vtable offsets...");
            logger.open_branch(true, "VTable offset update (%u entries)", vtable_checked);

            uint32_t vtable_idx = 0;
            for (auto& tf : funcs) {
                if (tf.match.verdict != MatchVerdict::MATCH) continue;
                if (tf.vtable_offset < 0 || tf.vtable_class.empty()) continue;
                if (tf.match.matched_ea == BADADDR) continue;

                vtable_idx++;
                bool is_last = (vtable_idx == vtable_checked);

                auto cls_it = g_index.class_to_vtname.find(tf.vtable_class);
                if (cls_it == g_index.class_to_vtname.end()) {
                    logger.item(is_last, "%-52s  %s — class not found in new binary",
                        tf.name.c_str(), tf.vtable_class.c_str());
                    continue;
                }
                auto vt_it = g_index.vtables.find(cls_it->second);
                if (vt_it == g_index.vtables.end()) {
                    logger.item(is_last, "%-52s  %s — class not found in new binary",
                        tf.name.c_str(), tf.vtable_class.c_str());
                    continue;
                }
                const auto& vt = vt_it->second;

                // small funcs: if size mismatch, skip EA strategies, let size-match handle it
                bool skip_ea_strategies = false;
                bool found = false;
                if (tf.reinforcement.size > 0 && tf.reinforcement.size <= 16) {
                    func_t* mf = get_func(tf.match.matched_ea);
                    if (mf) {
                        uint32_t msize = static_cast<uint32_t>(mf->end_ea - mf->start_ea);
                        uint32_t tsize = tf.reinforcement.size;
                        uint32_t lo = (tsize > 2) ? tsize - 2 : 1;
                        uint32_t hi = tsize + 2;
                        if (msize < lo || msize > hi) {
                            skip_ea_strategies = true;
                        }
                    }
                }

                // strat 1: reverse lookup
                if (!skip_ea_strategies) {
                    auto ft_it = g_index.func_to_vtables.find(tf.match.matched_ea);
                    if (ft_it != g_index.func_to_vtables.end()) {
                        for (const auto& [vtname, slot] : ft_it->second) {
                            if (vtname != cls_it->second) continue;

                            found = true;
                            int32_t new_offset = static_cast<int32_t>(slot);
                            if (new_offset != tf.vtable_offset) {
                                logger.item(is_last, "%-52s  %s[%d → %d] CHANGED",
                                    tf.name.c_str(), tf.vtable_class.c_str(),
                                    tf.vtable_offset, new_offset);
                                tf.vtable_offset = new_offset;
                                vtable_updated++;
                            } else {
                                logger.item(is_last, "%-52s  %s[%d] OK",
                                    tf.name.c_str(), tf.vtable_class.c_str(), tf.vtable_offset);
                            }
                            break;
                        }
                    }
                }

                // strat 2: direct slot check + full scan
                if (!found && !skip_ea_strategies) {
                    // original slot still valid?
                    if (tf.vtable_offset >= 0 &&
                        static_cast<size_t>(tf.vtable_offset) < vt.slots.size()) {
                        func_t* sf = get_func(vt.slots[tf.vtable_offset]);
                        if (sf && sf->start_ea == tf.match.matched_ea) {
                            logger.item(is_last, "%-52s  %s[%d] OK (direct)",
                                tf.name.c_str(), tf.vtable_class.c_str(),
                                tf.vtable_offset);
                            found = true;
                        }
                    }

                    // slot moved, scan all
                    if (!found) {
                        for (size_t s = 0; s < vt.slots.size(); ++s) {
                            func_t* sf = get_func(vt.slots[s]);
                            if (sf && sf->start_ea == tf.match.matched_ea) {
                                int32_t new_offset = static_cast<int32_t>(s);
                                if (new_offset != tf.vtable_offset) {
                                    logger.item(is_last, "%-52s  %s[%d → %d] CHANGED (direct)",
                                        tf.name.c_str(), tf.vtable_class.c_str(),
                                        tf.vtable_offset, new_offset);
                                    tf.vtable_offset = new_offset;
                                    vtable_updated++;
                                } else {
                                    logger.item(is_last, "%-52s  %s[%d] OK (direct)",
                                        tf.name.c_str(), tf.vtable_class.c_str(),
                                        tf.vtable_offset);
                                }
                                found = true;
                                break;
                            }
                        }
                    }
                }

                // strat 3: wrapper check (slot calls matched func)
                if (!found && !skip_ea_strategies) {
                    for (size_t s = 0; s < vt.slots.size(); ++s) {
                        ea_t slot_ea = vt.slots[s];
                        auto callee_it = g_index.callees.find(slot_ea);
                        if (callee_it == g_index.callees.end()) continue;

                        for (ea_t callee : callee_it->second) {
                            if (callee == tf.match.matched_ea) {
                                int32_t new_offset = static_cast<int32_t>(s);
                                if (new_offset != tf.vtable_offset) {
                                    logger.item(is_last, "%-52s  %s[%d → %d] CHANGED (wrapper)",
                                        tf.name.c_str(), tf.vtable_class.c_str(),
                                        tf.vtable_offset, new_offset);
                                    tf.vtable_offset = new_offset;
                                    vtable_updated++;
                                } else {
                                    logger.item(is_last, "%-52s  %s[%d] OK (wrapper)",
                                        tf.name.c_str(), tf.vtable_class.c_str(),
                                        tf.vtable_offset);
                                }
                                found = true;
                                break;
                            }
                        }
                        if (found) break;
                    }
                }

                // strat 4: nearest slot by size
                if (!found) {
                    int32_t tol = static_cast<int32_t>(config::VTABLE_SLOT_BASE_TOLERANCE);
                    int32_t old_slot = tf.vtable_offset;
                    int32_t best_slot = -1;
                    int32_t best_dist = INT32_MAX;

                    int32_t lo = std::max<int32_t>(0, old_slot - tol);
                    int32_t hi = std::min<int32_t>(
                        static_cast<int32_t>(vt.slots.size()), old_slot + tol + 1);

                    uint32_t orig_size = tf.reinforcement.size;

                    for (int32_t s = lo; s < hi; ++s) {
                        func_t* sf = get_func(vt.slots[s]);
                        if (!sf) continue;

                        if (orig_size > 0) {
                            uint32_t cand_size = static_cast<uint32_t>(sf->end_ea - sf->start_ea);
                            uint32_t size_lo, size_hi;
                            if (orig_size <= 8) {
                                size_lo = (orig_size > 1) ? orig_size - 1 : 1;
                                size_hi = orig_size + 1;
                            } else {
                                size_lo = orig_size / 3;
                                size_hi = orig_size * 3;
                            }
                            if (cand_size < size_lo || cand_size > size_hi) continue;
                        }

                        int32_t d = (s > old_slot) ? s - old_slot : old_slot - s;
                        if (d < best_dist) {
                            best_dist = d;
                            best_slot = s;
                        }
                    }

                    if (best_slot >= 0) {
                        ea_t slot_func = vt.slots[best_slot];
                        func_t* sf = get_func(slot_func);
                        if (sf) {
                            tf.match.matched_ea = sf->start_ea;
                            int32_t new_offset = best_slot;
                            logger.item(is_last, "%-52s  %s[%d → %d] OVERRIDE (slot)",
                                tf.name.c_str(), tf.vtable_class.c_str(),
                                tf.vtable_offset, new_offset);
                            tf.vtable_offset = new_offset;
                            vtable_updated++;
                            found = true;
                        }
                    }
                }

                if (!found) {
                    logger.item(is_last, "%-52s  %s — matched func not in vtable slots",
                        tf.name.c_str(), tf.vtable_class.c_str());
                }
            }
            logger.close_branch();
        }

        hide_wait_box();

        ui::g_cache.functions = std::move(funcs);
        ui::g_cache.binary_name = get_binary_filename();
        ui::g_cache.loaded_from = path;
        ui::g_cache.modified = true;

        logger.section("Summary");
        float pct = stats.total > 0 ? (float)stats.matched / stats.total * 100 : 0.0f;
        logger.item(false, "Total:       %u functions", stats.total);
        logger.item(false, "Survived:    %u (tracking sig intact)", stats.survived);
        logger.item(false, "Matched:     %u/%u (%.0f%%)", stats.matched, stats.total, pct);
        if (stats.ambiguous > 0)
            logger.item(false, "Ambiguous:   %u", stats.ambiguous);
        if (stats.none > 0)
            logger.item(false, "Not found:   %u", stats.none);
        if (stats.pass2_rescued > 0)
            logger.item(false, "Pass 2 rescued: %u", stats.pass2_rescued);
        logger.item(false, "Sigs regenerated: %u", regen_count);
        if (vtable_updated > 0)
            logger.item(true, "VTable offsets updated: %u", vtable_updated);
        else
            logger.item(true, "VTable offsets: %u checked, all OK", vtable_checked);

        qstring summary;
        summary.sprnt(
            "Backtrack Complete\n\n"
            "Source: %s\nTarget: %s\n\n"
            "Survived: %u (tracking sig intact)\n"
            "Matched: %u/%u (%.0f%%)\n"
            "Ambiguous: %u\nNot found: %u\n"
            "Pass 2 rescued: %u\n"
            "Signatures regenerated: %u\n"
            "VTable offsets updated: %u\n\n"
            "Open tracked functions browser?",
            old_binary.c_str(), get_binary_filename().c_str(),
            stats.survived,
            stats.matched, stats.total,
            stats.total > 0 ? (float)stats.matched / stats.total * 100 : 0.0f,
            stats.ambiguous, stats.none, stats.pass2_rescued,
            regen_count, vtable_updated);

        int open_browser = ask_yn(ASKBTN_YES, "%s", summary.c_str());

        if (open_browser == ASKBTN_YES) {
            int save_choice = ask_buttons("Save Now", "Skip", "Cancel",
                ASKBTN_BTN1,
                "Save updated tracking data now?\n\n"
                "This will write new signatures and vtable offsets\n"
                "to the default save path.");

            if (save_choice == ASKBTN_BTN1) {
                std::string save_path = get_default_save_path();
                if (io::serialize(ui::g_cache.functions, get_binary_filename(), save_path.c_str())) {
                    ui::g_cache.modified = false;
                    msg("GDT: Saved %zu functions to %s\n",
                        ui::g_cache.functions.size(), save_path.c_str());
                } else {
                    warning("GDT: Failed to save to %s", save_path.c_str());
                }
            } else if (save_choice == ASKBTN_CANCEL) {
                return 1;  // Don't open browser
            }
            ui::open_tracked_chooser();
        }

        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

//=============================================================================
// Action: Import Gamedata
//=============================================================================

struct action_import_gamedata_t : public action_handler_t {

    struct GamedataEntry {
        std::string name;
        std::string sig_str;      // IDA-style "55 48 89" or \x-style "\x55\x48"
        std::string library;
        int32_t offset = -1;      // vtable slot index, -1 = no offset
    };

    static std::string strip_jsonc(const char* data, size_t len) {
        std::string result;
        result.reserve(len);

        bool in_string = false;
        for (size_t i = 0; i < len; ++i) {
            char c = data[i];
            char next = (i + 1 < len) ? data[i + 1] : '\0';

            if (in_string) {
                result += c;
                if (c == '\\' && next != '\0') {
                    result += next;
                    ++i;
                } else if (c == '"') {
                    in_string = false;
                }
                continue;
            }

            if (c == '"') {
                in_string = true;
                result += c;
            } else if (c == '/' && next == '/') {
                i += 2;
                while (i < len && data[i] != '\n') ++i;
                if (i < len) result += '\n';
            } else if (c == '/' && next == '*') {
                i += 2;
                while (i + 1 < len && !(data[i] == '*' && data[i + 1] == '/')) ++i;
                if (i + 1 < len) ++i; // skip closing /
            } else {
                result += c;
            }
        }
        return result;
    }

    // parse IDA-style "55 48 89" or \x-style "\x55\x48"
    static Signature parse_sig_str(const std::string& str) {
        Signature sig;
        if (str.empty()) return sig;

        if (str.find("\\x") != std::string::npos) {
            const char* p = str.c_str();
            while (*p) {
                if (p[0] == '\\' && p[1] == 'x' && p[2] && p[3]) {
                    char hex[3] = {p[2], p[3], 0};
                    uint8_t byte = (uint8_t)strtoul(hex, nullptr, 16);
                    if (byte == 0x2A) {
                        sig.bytes.push_back(0);
                        sig.mask.push_back(false);
                    } else {
                        sig.bytes.push_back(byte);
                        sig.mask.push_back(true);
                    }
                    p += 4;
                } else {
                    p++;
                }
            }
        } else {
            size_t i = 0;
            while (i < str.size()) {
                while (i < str.size() && str[i] == ' ') ++i;
                if (i >= str.size()) break;

                if (str[i] == '?') {
                    sig.bytes.push_back(0);
                    sig.mask.push_back(false);
                    ++i;
                    if (i < str.size() && str[i] == '?') ++i;
                } else if (isxdigit((unsigned char)str[i])) {
                    char hex[3] = {0};
                    hex[0] = str[i++];
                    if (i < str.size() && isxdigit((unsigned char)str[i]))
                        hex[1] = str[i++];
                    sig.bytes.push_back((uint8_t)strtoul(hex, nullptr, 16));
                    sig.mask.push_back(true);
                } else {
                    ++i;
                }
            }
        }
        return sig;
    }

    struct GdParser {
        const char* d;
        size_t pos;
        size_t len;
        bool linux_platform;

        void skip_ws() {
            while (pos < len && (d[pos]==' '||d[pos]=='\t'||d[pos]=='\n'||d[pos]=='\r'))
                ++pos;
        }

        char peek() { skip_ws(); return pos < len ? d[pos] : 0; }

        bool expect(char c) {
            skip_ws();
            if (pos < len && d[pos] == c) { ++pos; return true; }
            return false;
        }

        std::string read_string() {
            std::string s;
            if (!expect('"')) return s;
            while (pos < len && d[pos] != '"') {
                if (d[pos] == '\\' && pos + 1 < len) {
                    ++pos;
                    switch (d[pos]) {
                        case '"': s += '"'; break;
                        case '\\': s += '\\'; break;
                        case 'n': s += '\n'; break;
                        case 'x':
                            s += '\\'; s += 'x';
                            break;
                        default: s += d[pos]; break;
                    }
                } else {
                    s += d[pos];
                }
                ++pos;
            }
            if (pos < len) ++pos; // closing "
            return s;
        }

        int64_t read_number() {
            skip_ws();
            bool neg = false;
            if (pos < len && d[pos] == '-') { neg = true; ++pos; }
            int64_t val = 0;
            while (pos < len && d[pos] >= '0' && d[pos] <= '9') {
                val = val * 10 + (d[pos] - '0');
                ++pos;
            }
            if (pos < len && d[pos] == '.') {
                ++pos;
                while (pos < len && d[pos] >= '0' && d[pos] <= '9') ++pos;
            }
            return neg ? -val : val;
        }

        void skip_value() {
            skip_ws();
            if (pos >= len) return;
            if (d[pos] == '"') { read_string(); }
            else if (d[pos] == '{') { skip_object(); }
            else if (d[pos] == '[') { skip_array(); }
            else if (d[pos] == 't') { pos += 4; }
            else if (d[pos] == 'f') { pos += 5; }
            else if (d[pos] == 'n') { pos += 4; }
            else { read_number(); }
        }

        void skip_object() {
            expect('{');
            if (peek() == '}') { expect('}'); return; }
            do {
                read_string();
                expect(':');
                skip_value();
            } while (expect(','));
            expect('}');
        }

        void skip_array() {
            expect('[');
            if (peek() == ']') { expect(']'); return; }
            do { skip_value(); } while (expect(','));
            expect(']');
        }

        std::vector<GamedataEntry> parse() {
            std::vector<GamedataEntry> entries;

            const char* plat_key = linux_platform ? "linux" : "windows";

            if (!expect('{')) return entries;

            while (peek() != '}' && pos < len) {
                std::string func_name = read_string();
                if (func_name.empty()) break;
                if (!expect(':')) break;

                GamedataEntry entry;
                entry.name = func_name;

                if (!expect('{')) { skip_value(); expect(','); continue; }

                while (peek() != '}' && pos < len) {
                    std::string key = read_string();
                    if (!expect(':')) break;

                    if (key == "signatures") {
                        if (!expect('{')) { skip_value(); expect(','); continue; }
                        while (peek() != '}' && pos < len) {
                            std::string sig_key = read_string();
                            if (!expect(':')) break;
                            if (sig_key == "library" || sig_key == "lib") {
                                entry.library = read_string();
                            } else if (sig_key == plat_key) {
                                entry.sig_str = read_string();
                            } else {
                                skip_value();
                            }
                            expect(',');
                        }
                        expect('}');
                    } else if (key == "signature") {
                        entry.sig_str = read_string();
                    } else if (key == "offsets") {
                        if (!expect('{')) { skip_value(); expect(','); continue; }
                        while (peek() != '}' && pos < len) {
                            std::string off_key = read_string();
                            if (!expect(':')) break;
                            if (off_key == plat_key) {
                                entry.offset = static_cast<int32_t>(read_number());
                            } else {
                                skip_value();
                            }
                            expect(',');
                        }
                        expect('}');
                    } else if (key == "library" || key == "lib") {
                        entry.library = read_string();
                    } else {
                        skip_value();
                    }
                    expect(',');
                }
                expect('}');

                if (!entry.sig_str.empty() || entry.offset >= 0) {
                    entries.push_back(std::move(entry));
                }

                expect(',');
            }
            expect('}');

            return entries;
        }
    };

    // walk backwards through _ separators to find vtable class
    // e.g. CCSPlayer_ItemServices_GiveNamedItem -> try CCSPlayer_ItemServices, then CCSPlayer
    static std::string resolve_vtable_class(const std::string& func_name,
                                            const GlobalIndex& index)
    {
        size_t sep = func_name.find("::");
        if (sep != std::string::npos) {
            std::string candidate = func_name.substr(0, sep);
            if (index.class_to_vtname.count(candidate)) return candidate;
        }

        size_t upos = func_name.rfind('_');
        while (upos != std::string::npos && upos > 0) {
            std::string candidate = func_name.substr(0, upos);
            if (index.class_to_vtname.count(candidate)) return candidate;
            upos = func_name.rfind('_', upos - 1);
        }

        return "";
    }

    static ea_t resolve_vtable_func(const std::string& vtable_class,
                                    int32_t slot_index,
                                    const GlobalIndex& index)
    {
        auto it = index.class_to_vtname.find(vtable_class);
        if (it == index.class_to_vtname.end()) return BADADDR;

        auto vt_it = index.vtables.find(it->second);
        if (vt_it == index.vtables.end()) return BADADDR;

        const auto& vt = vt_it->second;
        if (slot_index < 0 || static_cast<size_t>(slot_index) >= vt.slots.size())
            return BADADDR;

        ea_t func_ea = vt.slots[slot_index];
        func_t* f = get_func(func_ea);
        if (f) return f->start_ea;
        return BADADDR;
    }

    struct PairHash {
        size_t operator()(const std::pair<std::string, int32_t>& p) const {
            size_t h1 = std::hash<std::string>{}(p.first);
            size_t h2 = std::hash<int32_t>{}(p.second);
            return h1 ^ (h2 << 32 | h2 >> 32);
        }
    };

    struct DuplicateCache {
        std::unordered_set<std::string> names;
        std::unordered_set<ea_t> sig_eas;
        std::unordered_set<std::pair<std::string, int32_t>, PairHash> vtable_entries;

        void rebuild() {
            names.clear(); sig_eas.clear(); vtable_entries.clear();
            for (const auto& tf : ui::g_cache.functions) {
                names.insert(tf.name);
                // key on sig target, several mid-func patches can share one func
                if (tf.original_ea != BADADDR) sig_eas.insert(tf.original_ea + tf.sig_offset);
                if (tf.vtable_offset >= 0 && !tf.vtable_class.empty())
                    vtable_entries.insert({tf.vtable_class, tf.vtable_offset});
            }
        }

        bool check(const std::string& name, ea_t sig_ea = BADADDR,
                    const std::string& vt_class = "", int32_t vt_offset = -1) const {
            if (names.count(name)) return true;
            if (sig_ea != BADADDR && sig_eas.count(sig_ea)) return true;
            if (vt_offset >= 0 && !vt_class.empty() &&
                vtable_entries.count({vt_class, vt_offset})) return true;
            return false;
        }

        void add(const std::string& name, ea_t sig_ea = BADADDR,
                 const std::string& vt_class = "", int32_t vt_offset = -1) {
            names.insert(name);
            if (sig_ea != BADADDR) sig_eas.insert(sig_ea);
            if (vt_offset >= 0 && !vt_class.empty())
                vtable_entries.insert({vt_class, vt_offset});
        }
    };

    static TrackedFunc make_tracked(func_t* f, const std::string& name,
                                    const std::string& method)
    {
        CrawlResult cr = crawler::crawl(f->start_ea);

        TrackedFunc tf;
        tf.name = name;
        tf.original_ea = f->start_ea;
        tf.identity = std::move(cr.identity);
        tf.reinforcement = std::move(cr.reinforcement);
        tf.anchors = std::move(cr.anchors);

        tf.export_sig = sig::make_signature(f->start_ea, BADADDR, f->start_ea, 0);
        tf.prologue_length = sig::detect_prologue_length(f->start_ea);
        if (tf.prologue_length > 0 &&
            (f->end_ea - f->start_ea) > config::MIN_FUNC_SIZE_FOR_SKIP) {
            ea_t skip_ea = f->start_ea + tf.prologue_length;
            tf.tracking_sig = sig::make_signature(skip_ea, f->end_ea, skip_ea, tf.prologue_length);
        }
        if (tf.tracking_sig.empty()) tf.tracking_sig = tf.export_sig;

        tf.match.verdict = MatchVerdict::MATCH;
        tf.match.matched_ea = f->start_ea;
        tf.match.method = method;
        tf.match.votes = 1;
        tf.match.identity_passed = true;
        tf.match.reinforcement_score = 1.0f;

        return tf;
    }

    virtual int idaapi activate(action_activation_ctx_t*) override {
        const char* path = ask_file(false, "*.json;*.jsonc",
            "Select gamedata file (gamedata.json or signatures.jsonc)");
        if (!path) return 0;

        FILE* fp = fopen(path, "r");
        if (!fp) { warning("GDT: Cannot open file"); return 0; }

        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        std::vector<char> buf(fsize + 1);
        (void)fread(buf.data(), 1, fsize, fp);
        fclose(fp);
        buf[fsize] = '\0';

        std::string json = strip_jsonc(buf.data(), static_cast<size_t>(fsize));
        bool linux = io::is_linux_binary();

        GdParser parser;
        parser.d = json.c_str();
        parser.pos = 0;
        parser.len = json.size();
        parser.linux_platform = linux;

        std::vector<GamedataEntry> entries = parser.parse();

        if (entries.empty()) {
            warning("GDT: No valid entries found in gamedata");
            return 0;
        }

        TreeLogger logger;
        logger.header("Import Gamedata");
        crawler::ensure_index(logger);

        uint32_t sig_count = 0, offset_count = 0;
        for (const auto& e : entries) {
            if (e.offset >= 0) offset_count++;
            else sig_count++;
        }
        logger.item(false, "Entries: %u signature, %u offset",
            sig_count, offset_count);

        show_wait_box("GDT: Importing 0/%zu functions...", entries.size());

        uint32_t tracked_sig = 0, tracked_offset = 0, skipped = 0;

        DuplicateCache dup_cache;
        dup_cache.rebuild();

        uint32_t sig_processed = 0;
        logger.open_branch(false, "Signature entries (%u)", sig_count);
        for (size_t i = 0; i < entries.size(); ++i) {
            const auto& entry = entries[i];
            if (entry.offset >= 0) continue; // vtable entries handled below
            sig_processed++;
            bool is_last_sig = (sig_processed == sig_count);

            replace_wait_box("GDT: [SIG] %u/%u — %s",
                sig_processed, sig_count, entry.name.c_str());

            Signature gsig = parse_sig_str(entry.sig_str);
            if (gsig.empty()) {
                logger.item(is_last_sig, "%-52s  SKIP (bad signature)", entry.name.c_str());
                skipped++;
                continue;
            }

            ea_t match_ea = sig::find_first_match(gsig, 0, BADADDR);
            if (match_ea == BADADDR) {
                logger.item(is_last_sig, "%-52s  SKIP (no match)", entry.name.c_str());
                skipped++;
                continue;
            }

            ea_t second = sig::find_first_match(gsig, match_ea + 1, BADADDR);
            func_t* f = get_func(match_ea);
            bool is_midfunc = (f && match_ea != f->start_ea);

            if (second != BADADDR) {
                // multi-match ok if all in same func
                func_t* f2 = get_func(second);
                bool same_func = (f && f2 && f->start_ea == f2->start_ea);

                if (same_func) {
                    // verify no matches in other funcs
                    ea_t scan = second + 1;
                    while (scan != BADADDR) {
                        ea_t next = sig::find_first_match(gsig, scan, BADADDR);
                        if (next == BADADDR) break;
                        func_t* fn = get_func(next);
                        if (!fn || fn->start_ea != f->start_ea) {
                            same_func = false;
                            break;
                        }
                        scan = next + 1;
                    }
                }

                if (!same_func) {
                    // 2 matches = warn + accept, 3+ = bail
                    ea_t third = sig::find_first_match(gsig, second + 1, BADADDR);
                    if (third != BADADDR) {
                        logger.item(is_last_sig, "%-52s  SKIP (not unique: 3+ matches)",
                            entry.name.c_str());
                        skipped++;
                        continue;
                    }

                    // 2 matches, anchors will disambiguate on backtrack
                    qstring na, nb;
                    if (f)  get_func_name(&na, f->start_ea);
                    if (f2) get_func_name(&nb, f2->start_ea);
                    logger.item(is_last_sig, "%-52s  WARN (2 matches: %s vs %s — using first)",
                        entry.name.c_str(),
                        na.empty() ? "?" : na.c_str(),
                        nb.empty() ? "?" : nb.c_str());
                }
            }
            if (!f) {
                logger.item(is_last_sig, "%-52s  SKIP (not in func)", entry.name.c_str());
                skipped++;
                continue;
            }

            if (dup_cache.check(entry.name, match_ea)) {
                logger.item(is_last_sig, "%-52s  SKIP (duplicate)", entry.name.c_str());
                skipped++;
                continue;
            }

            TrackedFunc tf = make_tracked(f, entry.name, "GAMEDATA_IMPORT");

            // mid-func sig: store offset for hook target
            if (match_ea != f->start_ea) {
                tf.sig_offset = static_cast<int32_t>(match_ea - f->start_ea);
                tf.export_sig = sig::make_signature(match_ea, f->end_ea, match_ea, 0);
                tf.mid_context = sig::collect_mid_context(
                    f->start_ea, f->end_ea, match_ea, config::MID_CONTEXT_RADIUS);
            }

            dup_cache.add(entry.name, match_ea);
            ui::g_cache.functions.push_back(std::move(tf));
            tracked_sig++;

            // don't clobber a func already named by another tracked entry
            qstring cur_name;
            get_func_name(&cur_name, f->start_ea);
            if (!dup_cache.names.count(cur_name.c_str()))
                set_name(f->start_ea, entry.name.c_str(), SN_NOWARN | SN_FORCE);

            if (match_ea != f->start_ea) {
                logger.item(is_last_sig, "%-52s  OK → 0x%llX +%d (mid-func, %zu bytes sig)",
                    entry.name.c_str(),
                    (unsigned long long)f->start_ea,
                    static_cast<int>(match_ea - f->start_ea),
                    gsig.length());
            } else {
                logger.item(is_last_sig, "%-52s  OK → 0x%llX (%zu bytes sig)",
                    entry.name.c_str(),
                    (unsigned long long)f->start_ea,
                    gsig.length());
            }
        }
        logger.close_branch();

        logger.open_branch(true, "VTable entries (%u)", offset_count);
        uint32_t offset_idx = 0;
        for (size_t i = 0; i < entries.size(); ++i) {
            const auto& entry = entries[i];
            if (entry.offset < 0) continue; // sig entries handled above

            offset_idx++;
            bool offset_last = (offset_idx == offset_count);

            replace_wait_box("GDT: [VTABLE] %u/%u — %s",
                offset_idx, offset_count, entry.name.c_str());

            std::string vt_class = resolve_vtable_class(entry.name, g_index);
            if (vt_class.empty()) {
                logger.item(offset_last, "%-52s  SKIP (no vtable class)", entry.name.c_str());
                skipped++;
                continue;
            }

            ea_t func_ea = resolve_vtable_func(vt_class, entry.offset, g_index);
            if (func_ea == BADADDR) {
                logger.item(offset_last, "%-52s  SKIP (%s[%d] not found)",
                    entry.name.c_str(), vt_class.c_str(), entry.offset);
                skipped++;
                continue;
            }

            if (dup_cache.check(entry.name, BADADDR, vt_class, entry.offset)) {
                logger.item(offset_last, "%-52s  SKIP (duplicate)", entry.name.c_str());
                skipped++;
                continue;
            }

            func_t* f = get_func(func_ea);
            if (!f) {
                logger.item(offset_last, "%-52s  SKIP (not in func)", entry.name.c_str());
                skipped++;
                continue;
            }

            TrackedFunc tf = make_tracked(f, entry.name, "GAMEDATA_VTABLE");
            tf.vtable_class = vt_class;
            tf.vtable_offset = entry.offset;
            dup_cache.add(entry.name, BADADDR, vt_class, entry.offset);
            ui::g_cache.functions.push_back(std::move(tf));
            tracked_offset++;

            set_name(func_ea, entry.name.c_str(), SN_NOWARN | SN_FORCE);

            logger.item(offset_last, "%-52s  OK → 0x%llX (%s[%d])",
                entry.name.c_str(),
                (unsigned long long)func_ea,
                vt_class.c_str(), entry.offset);
        }
        logger.close_branch();

        hide_wait_box();

        ui::g_cache.modified = true;

        std::string save_path = get_default_save_path();
        replace_wait_box("GDT: Saving tracking data...");
        show_wait_box("GDT: Saving tracking data...");
        io::serialize(ui::g_cache.functions, get_binary_filename(), save_path.c_str());
        ui::g_cache.modified = false;
        hide_wait_box();

        uint32_t total_tracked = tracked_sig + tracked_offset;

        logger.section("Summary");
        logger.item(false, "Signature:  %u/%u matched", tracked_sig, sig_count);
        logger.item(false, "VTable:     %u/%u matched", tracked_offset, offset_count);
        logger.item(false, "Skipped:    %u", skipped);
        logger.item(true, "Total:      %u/%zu tracked", total_tracked, entries.size());
        logger.success("Import complete: %u tracked (%u sig + %u vtable)",
            total_tracked, tracked_sig, tracked_offset);

        if (total_tracked > 0) {
            ui::open_tracked_chooser();
        }

        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

//=============================================================================
// Action: Open Browser
//=============================================================================

struct action_browser_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t*) override {
        ui::open_tracked_chooser();
        return 1;
    }
    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

//=============================================================================
// Action: Generate Signature (quick sig + clipboard)
//=============================================================================

struct action_gensig_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t*) override {
        ea_t ea = get_screen_ea();
        func_t* f = get_func(ea);
        if (!f) { warning("GDT: Cursor not in a function"); return 0; }

        Signature s = sig::make_signature(f->start_ea, BADADDR, f->start_ea, 0);
        if (s.empty()) { warning("GDT: Failed to generate signature"); return 0; }

        std::string ida_str = s.to_ida();

        ea_t second = sig::find_first_match(s, f->start_ea + 1, f->start_ea);
        bool unique = (second == BADADDR);

        msg("GDT: %s signature (%zu bytes): %s\n",
            unique ? "Unique" : "Non-unique", s.length(), ida_str.c_str());

        qstring idc_cmd;
        idc_cmd.sprnt("set_clipboard_text(\"%s\");", ida_str.c_str());
        idc_value_t result;
        qstring errbuf;
        eval_idc_snippet(&result, idc_cmd.c_str(), &errbuf);

        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return get_func(get_screen_ea()) ? AST_ENABLE_FOR_WIDGET : AST_DISABLE;
    }
};

//=============================================================================
// Action: Export Gamedata
//=============================================================================

struct action_export_gamedata_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t*) override {
        if (ui::g_cache.empty()) {
            warning("GDT: No functions to export");
            return 0;
        }

        uint32_t matched = 0;
        for (const auto& tf : ui::g_cache.functions) {
            if (tf.match.verdict != MatchVerdict::MATCH) continue;
            if (!tf.export_sig.empty() || tf.vtable_offset >= 0)
                matched++;
        }

        if (matched == 0) {
            warning("GDT: No matched functions to export");
            return 0;
        }

        int choice = ask_buttons("CSS", "SwiftlyS2", "Both",
            ASKBTN_BTN3, "Export %u functions as:", matched);

        if (choice == ASKBTN_BTN1 || choice == ASKBTN_BTN3) {
            const char* p = ask_file(true, "*.json", "Export CounterStrikeSharp gamedata.json");
            if (p) {
                io::export_css(ui::g_cache.functions, p);
                msg("GDT: Exported CSS gamedata → %s\n", p);
            }
        }
        if (choice == ASKBTN_BTN2 || choice == ASKBTN_BTN3) {
            const char* p = ask_file(true, "*.json", "Export SwiftlyS2 gamedata.json");
            if (p) {
                io::export_swiftly(ui::g_cache.functions, p);
                msg("GDT: Exported SwiftlyS2 gamedata → %s\n", p);
            }
        }

        return 1;
    }

    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return ui::g_cache.empty() ? AST_DISABLE : AST_ENABLE_ALWAYS;
    }
};

//=============================================================================
// Action instances
//=============================================================================

static action_track_t           g_action_track;
static action_backtrack_t       g_action_backtrack;
static action_import_gamedata_t g_action_import_gd;
static action_browser_t         g_action_browser;
static action_gensig_t          g_action_gensig;
static action_export_gamedata_t g_action_export_gd;

//=============================================================================
// Register all actions
//=============================================================================

inline bool register_actions() {
    struct ActionDef {
        const char* id;
        const char* label;
        action_handler_t* handler;
    };

    ActionDef defs[] = {
        { K4T_ACTION_TRACK,     "GDT: Track Function",      &g_action_track },
        { K4T_ACTION_BACKTRACK, "GDT: Backtrack",            &g_action_backtrack },
        { K4T_ACTION_IMPORT_GD, "GDT: Import Gamedata",      &g_action_import_gd },
        { K4T_ACTION_BROWSER,   "GDT: Tracked Functions",    &g_action_browser },
        { K4T_ACTION_GENSIG,    "GDT: Generate Signature",   &g_action_gensig },
        { K4T_ACTION_EXPORT_GD, "GDT: Export Gamedata",      &g_action_export_gd },
    };

    for (const auto& d : defs) {
        action_desc_t desc = ACTION_DESC_LITERAL(
            d.id, d.label, d.handler, nullptr, nullptr, -1);
        if (!register_action(desc)) return false;
    }
    return true;
}

inline void unregister_actions() {
    unregister_action(K4T_ACTION_TRACK);
    unregister_action(K4T_ACTION_BACKTRACK);
    unregister_action(K4T_ACTION_IMPORT_GD);
    unregister_action(K4T_ACTION_BROWSER);
    unregister_action(K4T_ACTION_GENSIG);
    unregister_action(K4T_ACTION_EXPORT_GD);
    ui::unregister_chooser_actions();
}

//=============================================================================
// Attach to menus
//=============================================================================

inline void attach_to_menus() {
    struct MenuDef {
        const char* id;
        const char* label;
    };
    MenuDef items[] = {
        { K4T_ACTION_TRACK,     "Track Function" },
        { K4T_ACTION_BACKTRACK, "Backtrack" },
        { K4T_ACTION_IMPORT_GD, "Import Gamedata" },
        { K4T_ACTION_BROWSER,   "Tracked Functions" },
        { K4T_ACTION_GENSIG,    "Generate Signature" },
        { K4T_ACTION_EXPORT_GD, "Export Gamedata" },
    };
    for (const auto& m : items) {
        bool ok = attach_action_to_menu("Edit/GameDataTracker/", m.id, SETMENU_APP);
        if (!ok) {
            msg("GDT: Menu attach FAILED for %s\n", m.label);
        }
    }
}

//=============================================================================
// Context menu listener (right-click in disasm/pseudocode)
//=============================================================================

struct ui_event_listener_t : public event_listener_t {
    virtual ssize_t idaapi on_event(ssize_t, va_list) override {
        return 0;
    }
};

static ui_event_listener_t g_ui_listener;

} // namespace tracker

#endif // K4_TRACKER_MAIN_H
