/* chooser.h - tracked functions chooser UI */

#ifndef K4_TRACKER_CHOOSER_H
#define K4_TRACKER_CHOOSER_H

#include <ida.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <name.hpp>

#include "core/types.h"
#include "io/gamedata.h"

#include <cmath>
#include <vector>

namespace tracker {
namespace ui {

namespace icons {

inline uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320u : 0u);
    }
    return ~crc;
}

inline uint32_t adler32(const uint8_t* data, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

inline void push_be32(std::vector<uint8_t>& v, uint32_t val) {
    v.push_back((uint8_t)(val >> 24));
    v.push_back((uint8_t)(val >> 16));
    v.push_back((uint8_t)(val >> 8));
    v.push_back((uint8_t)(val));
}

inline void push_chunk(std::vector<uint8_t>& png,
                       const char* type,
                       const uint8_t* data, uint32_t len)
{
    push_be32(png, len);
    size_t crc_start = png.size();
    png.insert(png.end(), type, type + 4);
    if (data && len > 0)
        png.insert(png.end(), data, data + len);
    uint32_t c = crc32(&png[crc_start], 4 + len);
    push_be32(png, c);
}

// gen 16x16 circle icon
inline int load_circle_icon(uint8_t r, uint8_t g, uint8_t b) {
    const int W = 16, H = 16;

    std::vector<uint8_t> raw;
    raw.reserve(H * (1 + W * 4));
    const float cx = 7.5f, cy = 7.5f, rad = 6.0f;

    for (int y = 0; y < H; y++) {
        raw.push_back(0x00); // filter: none
        for (int x = 0; x < W; x++) {
            float dx = (float)x - cx, dy = (float)y - cy;
            float d2 = dx * dx + dy * dy;
            if (d2 <= rad * rad) {
                raw.push_back(r); raw.push_back(g);
                raw.push_back(b); raw.push_back(0xFF);
            } else if (d2 <= (rad + 1.0f) * (rad + 1.0f)) {
                uint8_t a = (uint8_t)((rad + 1.0f - sqrtf(d2)) * 255.0f);
                raw.push_back(r); raw.push_back(g);
                raw.push_back(b); raw.push_back(a);
            } else {
                raw.push_back(0); raw.push_back(0);
                raw.push_back(0); raw.push_back(0);
            }
        }
    }

    // zlib stored (tiny data, no compression)
    std::vector<uint8_t> zlib;
    zlib.push_back(0x78); // CMF: deflate, window=32k
    zlib.push_back(0x01); // FLG: FCHECK=1

    uint16_t rlen = (uint16_t)raw.size();
    uint16_t nlen = (uint16_t)~rlen;
    zlib.push_back(0x01); // BFINAL=1, BTYPE=00 (stored)
    zlib.push_back((uint8_t)(rlen & 0xFF));
    zlib.push_back((uint8_t)(rlen >> 8));
    zlib.push_back((uint8_t)(nlen & 0xFF));
    zlib.push_back((uint8_t)(nlen >> 8));
    zlib.insert(zlib.end(), raw.begin(), raw.end());
    push_be32(zlib, adler32(raw.data(), raw.size()));

    std::vector<uint8_t> png = {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A};

    uint8_t ihdr[13] = {};
    ihdr[3] = W; ihdr[7] = H; // width/height as BE32 (high bytes are 0)
    ihdr[8] = 8;  // bit depth
    ihdr[9] = 6;  // color type: RGBA
    push_chunk(png, "IHDR", ihdr, 13);

    // IDAT
    push_chunk(png, "IDAT", zlib.data(), (uint32_t)zlib.size());

    // IEND
    push_chunk(png, "IEND", nullptr, 0);

    return load_custom_icon(png.data(), (unsigned int)png.size(), "png");
}

struct ChooserIcons {
    int green  = -1;  // MATCH + SURVIVED
    int blue   = -1;  // MATCH + relocated
    int cyan   = -1;  // MATCH + sig regenerated
    int orange = -1;  // AMBIGUOUS
    int red    = -1;  // NONE
    bool loaded = false;

    void init() {
        if (loaded) return;
        green  = load_circle_icon(0x22, 0xBB, 0x33);
        blue   = load_circle_icon(0x33, 0x88, 0xFF);
        cyan   = load_circle_icon(0x00, 0xBB, 0xDD);
        orange = load_circle_icon(0xFF, 0x99, 0x00);
        red    = load_circle_icon(0xFF, 0x33, 0x33);
        loaded = true;
    }

    void term() {
        if (!loaded) return;
        if (green  >= 0) free_custom_icon(green);
        if (blue   >= 0) free_custom_icon(blue);
        if (cyan   >= 0) free_custom_icon(cyan);
        if (orange >= 0) free_custom_icon(orange);
        if (red    >= 0) free_custom_icon(red);
        green = blue = cyan = orange = red = -1;
        loaded = false;
    }
};

inline ChooserIcons g_icons;

} // namespace icons

// Global state

struct TrackerCache {
    std::vector<TrackedFunc> functions;
    std::string binary_name;
    std::string loaded_from;
    bool modified = false;

    bool empty() const { return functions.empty(); }
    void clear() {
        functions.clear();
        binary_name.clear();
        loaded_from.clear();
        modified = false;
    }
};

inline TrackerCache g_cache;

#define K4T_ACTION_JUMP        "gamedata_tracker:jump"
#define K4T_ACTION_EXPORT_CSS  "gamedata_tracker:export_css"
#define K4T_ACTION_EXPORT_SW   "gamedata_tracker:export_swiftly"

inline const char* verdict_icon(MatchVerdict v) {
    switch (v) {
        case MatchVerdict::MATCH:     return "[OK]";
        case MatchVerdict::AMBIGUOUS: return "[??]";
        case MatchVerdict::NONE:      return "[--]";
        default: return "[  ]";
    }
}

struct tracked_chooser_t : public chooser_t {
    static const int COLUMNS = 5;
    static const char* const headers[COLUMNS];
    static const int widths[COLUMNS];

    tracked_chooser_t()
        : chooser_t(CH_KEEP | CH_CAN_DEL | CH_CAN_REFRESH,
                     COLUMNS, widths, headers,
                     "GDT - Tracked Functions")
    {}

    virtual size_t idaapi get_count() const override {
        return g_cache.functions.size();
    }

    virtual void idaapi get_row(
        qstrvec_t* cols,
        int* icon,
        chooser_item_attrs_t* attrs,
        size_t n) const override
    {
        if (n >= g_cache.functions.size()) return;
        const TrackedFunc& tf = g_cache.functions[n];

        (*cols)[0] = tf.name.c_str();

        (*cols)[1].sprnt("0x%llX", (unsigned long long)tf.original_ea);

        if (tf.match.matched_ea != BADADDR) {
            (*cols)[2].sprnt("0x%llX", (unsigned long long)tf.match.matched_ea);
        } else {
            (*cols)[2] = "\xe2\x80\x94"; // em-dash
        }

        (*cols)[3] = verdict_icon(tf.match.verdict);
        (*cols)[3].cat_sprnt(" %s", verdict_name(tf.match.verdict));

        if (tf.match.votes > 0) {
            (*cols)[4].sprnt("%s (v=%u, rf=%.0f%%)",
                tf.match.method.c_str(),
                tf.match.votes,
                tf.match.reinforcement_score * 100);
        } else {
            (*cols)[4] = "";
        }

        switch (tf.match.verdict) {
            case MatchVerdict::MATCH: {
                bool survived = (tf.match.method == "SURVIVED");
                bool addr_moved = (tf.original_ea != tf.match.matched_ea
                                   && tf.match.matched_ea != BADADDR);

                if (survived) {
                    *icon = icons::g_icons.green;
                } else if (addr_moved) {
                    *icon = icons::g_icons.blue;
                } else {
                    *icon = icons::g_icons.cyan;
                }
                break;
            }
            case MatchVerdict::AMBIGUOUS:
                *icon = icons::g_icons.orange;
                if (attrs) attrs->color = 0x00A5FF;
                break;
            case MatchVerdict::NONE:
                *icon = icons::g_icons.red;
                if (attrs) attrs->color = 0x0000FF;
                break;
        }
    }

    // enter -> jump
    virtual cbret_t idaapi enter(size_t n) override {
        if (n >= g_cache.functions.size()) return cbret_t();
        const TrackedFunc& tf = g_cache.functions[n];

        ea_t target = (tf.match.matched_ea != BADADDR)
            ? tf.match.matched_ea : tf.original_ea;

        if (tf.sig_offset > 0 && target != BADADDR)
            target += tf.sig_offset;

        if (target != BADADDR && is_mapped(target)) {
            jumpto(target);
        }
        return cbret_t();
    }

    // del -> remove
    virtual cbret_t idaapi del(size_t n) override {
        if (n >= g_cache.functions.size()) return cbret_t();

        int answer = ask_yn(ASKBTN_NO, "Remove tracking for '%s'?",
            g_cache.functions[n].name.c_str());
        if (answer == ASKBTN_YES) {
            g_cache.functions.erase(g_cache.functions.begin() + n);
            g_cache.modified = true;
            return cbret_t(chooser_base_t::ALL_CHANGED);
        }
        return cbret_t();
    }

    virtual cbret_t idaapi refresh(ssize_t) override {
        return cbret_t(chooser_base_t::ALL_CHANGED);
    }

    virtual bool idaapi init() override { return true; }
};

const char* const tracked_chooser_t::headers[COLUMNS] = {
    "Function", "Original", "Matched", "Verdict", "Method"
};
const int tracked_chooser_t::widths[COLUMNS] = {
    45, 14, 14, 12, 30
};

struct action_jump_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t* ctx) override {
        if (!ctx || ctx->chooser_selection.empty()) return 0;
        size_t n = ctx->chooser_selection[0];
        if (n >= g_cache.functions.size()) return 0;

        const TrackedFunc& tf = g_cache.functions[n];
        ea_t target = (tf.match.matched_ea != BADADDR)
            ? tf.match.matched_ea : tf.original_ea;
        if (tf.sig_offset > 0 && target != BADADDR)
            target += tf.sig_offset;
        if (target != BADADDR && is_mapped(target)) jumpto(target);
        return 1;
    }
    virtual action_state_t idaapi update(action_update_ctx_t* ctx) override {
        return (ctx && !ctx->chooser_selection.empty()) ? AST_ENABLE : AST_DISABLE;
    }
};

struct action_export_css_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t*) override {
        if (g_cache.empty()) return 0;
        const char* path = ask_file(true, "*.json", "Export CounterStrikeSharp gamedata.json");
        if (!path) return 0;
        if (io::export_css(g_cache.functions, path)) {
            msg("GDT: Exported CSS gamedata to %s\n", path);
        }
        return 1;
    }
    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return g_cache.empty() ? AST_DISABLE : AST_ENABLE;
    }
};

struct action_export_swiftly_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t*) override {
        if (g_cache.empty()) return 0;
        const char* path = ask_file(true, "*.json", "Export SwiftlyS2 gamedata.json");
        if (!path) return 0;
        if (io::export_swiftly(g_cache.functions, path)) {
            msg("GDT: Exported SwiftlyS2 gamedata to %s\n", path);
        }
        return 1;
    }
    virtual action_state_t idaapi update(action_update_ctx_t*) override {
        return g_cache.empty() ? AST_DISABLE : AST_ENABLE;
    }
};

static action_jump_t g_action_jump;
static action_export_css_t g_action_export_css;
static action_export_swiftly_t g_action_export_swiftly;

inline void register_chooser_actions() {
    static bool done = false;
    if (done) return;

    register_action(ACTION_DESC_LITERAL(K4T_ACTION_JUMP,
        "Jump to Function", &g_action_jump, nullptr, nullptr, -1));
    register_action(ACTION_DESC_LITERAL(K4T_ACTION_EXPORT_CSS,
        "Export CounterStrikeSharp", &g_action_export_css, nullptr, nullptr, -1));
    register_action(ACTION_DESC_LITERAL(K4T_ACTION_EXPORT_SW,
        "Export SwiftlyS2", &g_action_export_swiftly, nullptr, nullptr, -1));
    done = true;
}

inline void unregister_chooser_actions() {
    unregister_action(K4T_ACTION_JUMP);
    unregister_action(K4T_ACTION_EXPORT_CSS);
    unregister_action(K4T_ACTION_EXPORT_SW);
    icons::g_icons.term();
}

static TWidget* g_chooser_widget = nullptr;

inline void open_tracked_chooser() {
    icons::g_icons.init();
    register_chooser_actions();
    tracked_chooser_t* ch = new tracked_chooser_t();
    ssize_t result = ch->choose();
    if (result >= 0) {
        TWidget* w = find_widget("GDT - Tracked Functions");
        if (w) {
            g_chooser_widget = w;
            attach_action_to_popup(w, nullptr, K4T_ACTION_JUMP, "GDT/");
            attach_action_to_popup(w, nullptr, K4T_ACTION_EXPORT_CSS, "GDT/Export/");
            attach_action_to_popup(w, nullptr, K4T_ACTION_EXPORT_SW, "GDT/Export/");
        }
    }
}

inline void refresh_tracked_chooser() {
    TWidget* w = find_widget("GDT - Tracked Functions");
    if (w) refresh_chooser("GDT - Tracked Functions");
}

} // namespace ui
} // namespace tracker

#endif // K4_TRACKER_CHOOSER_H
