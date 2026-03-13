/* io/gamedata.h - export gamedata (SwiftlyS2 / CSS) */

#ifndef K4_TRACKER_GAMEDATA_H
#define K4_TRACKER_GAMEDATA_H

#include "core/types.h"

#include <cstdio>
#include <string>
#include <vector>

namespace tracker {
namespace io {

inline bool is_linux_binary() {
    char input_file[MAXSTR];
    get_input_file_path(input_file, sizeof(input_file));
    std::string name = input_file;
    return name.find(".so") != std::string::npos
        || name.find(".dylib") != std::string::npos;
}

inline std::string get_library_name() {
    char buf[MAXSTR];
    get_root_filename(buf, sizeof(buf));
    std::string name = buf;
    
    size_t dot = name.rfind('.');
    if (dot != std::string::npos) name = name.substr(0, dot);
    
    if (name.size() > 3 && name.compare(0, 3, "lib") == 0) {
        name = name.substr(3);
    }
    
    return name;
}

inline bool export_swiftly(const std::vector<TrackedFunc>& funcs,
                           const char* path)
{
    FILE* fp = fopen(path, "w");
    if (!fp) return false;

    bool linux = is_linux_binary();
    const char* platform = linux ? "linux" : "windows";
    std::string lib_name = get_library_name();

    fputs("{\n", fp);

    bool first = true;
    for (const auto& tf : funcs) {
        if (tf.match.verdict != MatchVerdict::MATCH) continue;

        if (tf.vtable_offset >= 0) {
            if (!first) fputs(",\n", fp);
            first = false;

            fprintf(fp, "  \"%s\": {\n", tf.name.c_str());
            fprintf(fp, "    \"offsets\": {\n");
            fprintf(fp, "      \"%s\": %d\n", platform, tf.vtable_offset);
            fprintf(fp, "    }\n");
            fprintf(fp, "  }");
            continue;
        }

        if (tf.export_sig.empty()) continue;

        if (!first) fputs(",\n", fp);
        first = false;

        fprintf(fp, "  \"%s\": {\n", tf.name.c_str());
        fprintf(fp, "    \"signatures\": {\n");
        fprintf(fp, "      \"library\": \"%s\",\n", lib_name.c_str());
        fprintf(fp, "      \"%s\": \"%s\"\n", platform, tf.export_sig.to_ida().c_str());
        fprintf(fp, "    }\n");
        fprintf(fp, "  }");
    }

    fputs("\n}\n", fp);
    fclose(fp);
    return true;
}

inline bool export_css(const std::vector<TrackedFunc>& funcs,
                       const char* path)
{
    FILE* fp = fopen(path, "w");
    if (!fp) return false;

    bool linux = is_linux_binary();
    const char* platform = linux ? "linux" : "windows";
    std::string lib_name = get_library_name();

    fputs("{\n", fp);

    bool first = true;
    for (const auto& tf : funcs) {
        if (tf.match.verdict != MatchVerdict::MATCH) continue;

        if (tf.vtable_offset >= 0) {
            if (!first) fputs(",\n", fp);
            first = false;

            fprintf(fp, "  \"%s\": {\n", tf.name.c_str());
            fprintf(fp, "    \"offsets\": {\n");
            fprintf(fp, "      \"%s\": %d\n", platform, tf.vtable_offset);
            fprintf(fp, "    }\n");
            fprintf(fp, "  }");
            continue;
        }

        if (tf.export_sig.empty()) continue;

        if (!first) fputs(",\n", fp);
        first = false;

        fprintf(fp, "  \"%s\": {\n", tf.name.c_str());
        fprintf(fp, "    \"signature\": \"%s\",\n", tf.export_sig.to_ida().c_str());
        fprintf(fp, "    \"library\": \"%s\"\n", lib_name.c_str());
        fprintf(fp, "  }");
    }

    fputs("\n}\n", fp);
    fclose(fp);
    return true;
}

struct ExportStats {
    uint32_t total = 0;
    uint32_t matched = 0;
    uint32_t exported_sig = 0;
    uint32_t exported_offset = 0;
};

inline ExportStats export_gamedata(const std::vector<TrackedFunc>& funcs,
                                   const char* swiftly_path,
                                   const char* css_path)
{
    ExportStats stats;
    stats.total = static_cast<uint32_t>(funcs.size());

    for (const auto& tf : funcs) {
        if (tf.match.verdict == MatchVerdict::MATCH) {
            stats.matched++;
            if (tf.vtable_offset >= 0)
                stats.exported_offset++;
            else if (!tf.export_sig.empty())
                stats.exported_sig++;
        }
    }

    if (swiftly_path) export_swiftly(funcs, swiftly_path);
    if (css_path) export_css(funcs, css_path);

    return stats;
}

} // namespace io
} // namespace tracker

#endif // K4_TRACKER_GAMEDATA_H
