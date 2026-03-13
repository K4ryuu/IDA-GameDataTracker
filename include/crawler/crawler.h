/*
 * crawler/crawler.h - orchestrator, runs all modules and merges results
 */

#ifndef K4_TRACKER_CRAWLER_H
#define K4_TRACKER_CRAWLER_H

#include "core/types.h"
#include "core/index.h"
#include "utils/logger.h"

#include "crawler/base.h"
#include "crawler/signature_module.h"
#include "crawler/string_module.h"
#include "crawler/convar_module.h"
#include "crawler/vtable_module.h"
#include "crawler/library_module.h"
#include "crawler/relational_module.h"
#include "crawler/data_ptr_module.h"
#include "crawler/proximity_module.h"
#include "crawler/callchain_module.h"
#include "crawler/xref_module.h"

namespace tracker {
namespace crawler {

//=============================================================================
// Pre-build identity + reinforcement for every func
//=============================================================================

inline void build_metadata_index(TreeLogger& logger) {
    auto start = std::chrono::high_resolution_clock::now();

    size_t total = get_func_qty();
    g_index.func_metadata.reserve(total);

    for (size_t i = 0; i < total; ++i) {
        func_t* f = getn_func(i);
        if (!f) continue;

        ea_t fea = f->start_ea;
        g_index.func_metadata[fea] = {
            base::analyze_identity(fea),
            base::analyze_reinforcement(fea, g_index)
        };

        if (i % 1000 == 0) {
            replace_wait_box("GDT: Indexing metadata %zu/%zu...", i, total);
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    logger.item(true, "Metadata: %zu functions analyzed (%lldms)", g_index.func_metadata.size(), ms);
}

inline void ensure_index(TreeLogger& logger) {
    if (!g_index.ready) {
        g_index.build(logger);
        build_metadata_index(logger);
    }
}

inline void rebuild_index(TreeLogger& logger) {
    g_index.build(logger);
    build_metadata_index(logger);
}

//=============================================================================
// Crawl one func
//=============================================================================

inline CrawlResult crawl(ea_t fea) {
    if (!g_index.ready) {
        TreeLogger dummy;
        g_index.build(dummy);
    }

    Identity identity = base::analyze_identity(fea);
    Reinforcement reinforcement = base::analyze_reinforcement(fea, g_index);

    std::vector<Anchor> all;

    auto append = [&](std::vector<Anchor>&& v) {
        all.insert(all.end(),
            std::make_move_iterator(v.begin()),
            std::make_move_iterator(v.end()));
    };

    append(modules::signature_mod::collect(fea, g_index));
    append(modules::string_mod::collect(fea, g_index));
    append(modules::convar_mod::collect(fea, g_index));
    append(modules::vtable_mod::collect(fea, g_index));
    append(modules::library_mod::collect(fea, g_index));
    append(modules::relational_mod::collect(fea, g_index));
    append(modules::data_ptr_mod::collect(fea, g_index));
    append(modules::proximity_mod::collect(fea, g_index));
    append(modules::callchain_mod::collect(fea, g_index));
    append(modules::xref_mod::collect(fea, g_index));

    return { std::move(identity), std::move(reinforcement), std::move(all) };
}

//=============================================================================
// Verbose crawl (with logging)
//=============================================================================

inline CrawlResult crawl_verbose(ea_t fea, TreeLogger& logger) {
    ensure_index(logger);

    qstring func_name;
    get_func_name(&func_name, fea);
    logger.open_branch(false, "Crawling: %s (0x%llX)", func_name.c_str(), (uint64_t)fea);

    CrawlResult result = crawl(fea);

    size_t per_module[10] = {};
    for (const auto& a : result.anchors) {
        uint8_t idx = static_cast<uint8_t>(a.priority);
        if (idx < 10) per_module[idx]++;
    }

    logger.item(false, "Identity: %s(%d params)%s",
        result.identity.return_type.empty() ? "?" : result.identity.return_type.c_str(),
        result.identity.param_count,
        result.identity.has_indirect_call ? " [indirect]" : "");

    logger.item(false, "Reinforcement: %u bytes, %u BBs, %u callers, %u callees",
        result.reinforcement.size, result.reinforcement.bb_count,
        result.reinforcement.caller_count, result.reinforcement.callee_count);

    logger.item(true, "Anchors: %zu total [sig:%zu str:%zu cv:%zu vt:%zu lib:%zu rel:%zu dp:%zu prx:%zu cc:%zu xr:%zu]",
        result.anchors.size(),
        per_module[0], per_module[1], per_module[2], per_module[3],
        per_module[4], per_module[5], per_module[6], per_module[7],
        per_module[8], per_module[9]);

    logger.close_branch();
    return result;
}

} // namespace crawler
} // namespace tracker

#endif // K4_TRACKER_CRAWLER_H
