/* io/serialize.h - save tracked funcs to JSON */

#ifndef K4_TRACKER_SERIALIZE_H
#define K4_TRACKER_SERIALIZE_H

#include "core/types.h"

#include <cstdio>
#include <string>
#include <vector>

namespace tracker {
namespace io {

inline std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    qsnprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

class JsonWriter {
    FILE* fp;
    int depth;

    void indent() {
        for (int i = 0; i < depth; ++i)
            fputs("  ", fp);
    }

public:
    JsonWriter(FILE* f) : fp(f), depth(0) {}

    void open_obj() { fputs("{\n", fp); ++depth; }
    void close_obj(bool comma = false) {
        --depth; indent();
        fputs(comma ? "},\n" : "}\n", fp);
    }

    void open_arr(const char* key) {
        indent();
        fprintf(fp, "\"%s\": [\n", key);
        ++depth;
    }
    void close_arr(bool comma = false) {
        --depth; indent();
        fputs(comma ? "],\n" : "]\n", fp);
    }

    void key_str(const char* k, const std::string& v, bool comma = true) {
        indent();
        fprintf(fp, "\"%s\": \"%s\"%s\n", k, json_escape(v).c_str(), comma ? "," : "");
    }

    void key_uint(const char* k, uint64_t v, bool comma = true) {
        indent();
        fprintf(fp, "\"%s\": %llu%s\n", k, (unsigned long long)v, comma ? "," : "");
    }

    void key_int(const char* k, int64_t v, bool comma = true) {
        indent();
        fprintf(fp, "\"%s\": %lld%s\n", k, (long long)v, comma ? "," : "");
    }

    void key_bool(const char* k, bool v, bool comma = true) {
        indent();
        fprintf(fp, "\"%s\": %s%s\n", k, v ? "true" : "false", comma ? "," : "");
    }

    void key_hex(const char* k, uint64_t v, bool comma = true) {
        indent();
        char buf[32];
        qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
        fprintf(fp, "\"%s\": \"%s\"%s\n", k, buf, comma ? "," : "");
    }

    void open_key_obj(const char* k, bool comma_after_close = true) {
        indent();
        fprintf(fp, "\"%s\": {\n", k);
        ++depth;
        (void)comma_after_close; // tracked by caller
    }

    void arr_open_obj() { indent(); fputs("{\n", fp); ++depth; }
    void arr_close_obj(bool comma = true) {
        --depth; indent();
        fputs(comma ? "},\n" : "}\n", fp);
    }

    void write_identity(const Identity& id, bool comma = true) {
        open_key_obj("identity");
        key_str("return_type", id.return_type);

        open_arr("param_types");
        for (size_t i = 0; i < id.param_types.size(); ++i) {
            indent();
            fprintf(fp, "\"%s\"%s\n",
                json_escape(id.param_types[i]).c_str(),
                (i + 1 < id.param_types.size()) ? "," : "");
        }
        close_arr(true);

        key_uint("param_count", id.param_count);
        key_bool("has_return", id.has_return);
        key_bool("has_indirect_call", id.has_indirect_call);
        key_bool("has_switch", id.has_switch);
        key_uint("struct_flags", id.struct_flags, false);
        --depth; indent();
        fputs(comma ? "},\n" : "}\n", fp);
    }

    void write_reinforcement(const Reinforcement& rf, bool comma = true) {
        open_key_obj("reinforcement");
        key_uint("size", rf.size);
        key_uint("bb_count", rf.bb_count);
        key_uint("cyclomatic", rf.cyclomatic);
        key_uint("caller_count", rf.caller_count);
        key_uint("callee_count", rf.callee_count);

        open_arr("strings");
        for (size_t i = 0; i < rf.strings.size(); ++i) {
            indent();
            fprintf(fp, "\"%s\"%s\n",
                json_escape(rf.strings[i]).c_str(),
                (i + 1 < rf.strings.size()) ? "," : "");
        }
        close_arr(true);

        open_arr("constants");
        for (size_t i = 0; i < rf.constants.size(); ++i) {
            indent();
            fprintf(fp, "%llu%s\n",
                (unsigned long long)rf.constants[i],
                (i + 1 < rf.constants.size()) ? "," : "");
        }
        close_arr(false);

        --depth; indent();
        fputs(comma ? "},\n" : "}\n", fp);
    }

    void write_anchor(const Anchor& a, bool comma = true) {
        arr_open_obj();
        key_uint("priority", static_cast<uint8_t>(a.priority));

        if (!a.name.empty())
            key_str("name", a.name);
        if (!a.signature.empty())
            key_str("signature", a.signature.to_ida());
        if (a.signature.offset > 0)
            key_uint("sig_offset", a.signature.offset);
        if (a.index > 0)
            key_uint("index", a.index);
        if (a.vtable_size > 0)
            key_uint("vtable_size", a.vtable_size);
        if (a.vtable_neighbor_before > 0)
            key_uint("vtable_neighbor_before", a.vtable_neighbor_before);
        if (a.vtable_neighbor_after > 0)
            key_uint("vtable_neighbor_after", a.vtable_neighbor_after);
        if (a.rva != 0)
            key_int("rva", static_cast<int64_t>(a.rva));
        if (a.fanout > 0)
            key_uint("fanout", a.fanout);

        if (a.chain_depth > 0) {
            key_uint("chain_depth", a.chain_depth);
            key_uint("chain_directions", a.chain_directions);
            key_uint("chain_landmark_type", a.chain_landmark_type);
            if (a.func_size > 0) key_uint("func_size", a.func_size);
        }

        key_str("priority_name", priority_name(a.priority), false);
        arr_close_obj(comma);
    }

    void write_tracked_func(const TrackedFunc& tf, bool comma = true) {
        arr_open_obj();
        key_str("name", tf.name);
        key_hex("original_ea", tf.original_ea);

        write_identity(tf.identity);
        write_reinforcement(tf.reinforcement);

        key_str("export_sig", tf.export_sig.empty() ? "" : tf.export_sig.to_ida());
        key_str("tracking_sig", tf.tracking_sig.empty() ? "" : tf.tracking_sig.to_ida());
        key_uint("prologue_length", tf.prologue_length);
        if (tf.sig_offset > 0)
            key_int("sig_offset", tf.sig_offset);

        if (!tf.mid_context.empty()) {
            open_arr("mid_context");
            for (size_t i = 0; i < tf.mid_context.size(); ++i) {
                indent();
                fprintf(fp, "%u%s\n",
                    (unsigned)tf.mid_context[i],
                    (i + 1 < tf.mid_context.size()) ? "," : "");
            }
            close_arr(true);
        }

        if (!tf.vtable_class.empty()) {
            key_str("vtable_class", tf.vtable_class);
            key_int("vtable_offset", tf.vtable_offset);
        }

        open_arr("anchors");
        for (size_t i = 0; i < tf.anchors.size(); ++i) {
            write_anchor(tf.anchors[i], i + 1 < tf.anchors.size());
        }
        close_arr(false);

        arr_close_obj(comma);
    }
};

inline bool serialize(const std::vector<TrackedFunc>& funcs,
                      const std::string& binary_name,
                      const char* path)
{
    FILE* fp = fopen(path, "w");
    if (!fp) return false;

    JsonWriter w(fp);
    w.open_obj();
    w.key_str("version", "1.0");
    w.key_str("binary_name", binary_name);
    w.key_uint("function_count", funcs.size());

    w.open_arr("functions");
    for (size_t i = 0; i < funcs.size(); ++i) {
        w.write_tracked_func(funcs[i], i + 1 < funcs.size());
    }
    w.close_arr(false);

    w.close_obj();
    fclose(fp);
    return true;
}

} // namespace io
} // namespace tracker

#endif // K4_TRACKER_SERIALIZE_H
