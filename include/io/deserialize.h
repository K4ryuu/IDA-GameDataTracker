/* io/deserialize.h - load tracked funcs from JSON */

#ifndef K4_TRACKER_DESERIALIZE_H
#define K4_TRACKER_DESERIALIZE_H

#include "core/types.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace tracker {
namespace io {

class JsonReader {
    const char* data;
    size_t pos;
    size_t len;

    void skip_ws() {
        while (pos < len && (data[pos] == ' ' || data[pos] == '\t' ||
               data[pos] == '\n' || data[pos] == '\r'))
            ++pos;
    }

    char peek() { skip_ws(); return pos < len ? data[pos] : 0; }
    char next() { skip_ws(); return pos < len ? data[pos++] : 0; }

    bool expect(char c) {
        skip_ws();
        if (pos < len && data[pos] == c) { ++pos; return true; }
        return false;
    }

    std::string read_string_raw() {
        std::string s;
        if (!expect('"')) return s;
        while (pos < len && data[pos] != '"') {
            if (data[pos] == '\\' && pos + 1 < len) {
                ++pos;
                switch (data[pos]) {
                    case '"':  s += '"'; break;
                    case '\\': s += '\\'; break;
                    case 'n':  s += '\n'; break;
                    case 'r':  s += '\r'; break;
                    case 't':  s += '\t'; break;
                    case 'u':
                        // Skip \uXXXX
                        ++pos;
                        for (int i = 0; i < 4 && pos < len; ++i, ++pos) {}
                        --pos; // will be incremented below
                        break;
                    default: s += data[pos]; break;
                }
            } else {
                s += data[pos];
            }
            ++pos;
        }
        if (pos < len) ++pos; // skip closing "
        return s;
    }

    int64_t read_number() {
        skip_ws();
        bool neg = false;
        if (pos < len && data[pos] == '-') { neg = true; ++pos; }

        int64_t val = 0;
        while (pos < len && data[pos] >= '0' && data[pos] <= '9') {
            val = val * 10 + (data[pos] - '0');
            ++pos;
        }
        if (pos < len && data[pos] == '.') {
            ++pos;
            while (pos < len && data[pos] >= '0' && data[pos] <= '9') ++pos;
        }
        return neg ? -val : val;
    }

    uint64_t read_rva() {
        skip_ws();
        if (pos < len && data[pos] == '-') {
            return static_cast<uint64_t>(read_number());
        }
        uint64_t val = 0;
        while (pos < len && data[pos] >= '0' && data[pos] <= '9') {
            val = val * 10 + (data[pos] - '0');
            ++pos;
        }
        if (pos < len && data[pos] == '.') {
            ++pos;
            while (pos < len && data[pos] >= '0' && data[pos] <= '9') ++pos;
        }
        return val;
    }

    bool read_bool() {
        skip_ws();
        if (pos + 4 <= len && strncmp(data + pos, "true", 4) == 0) {
            pos += 4; return true;
        }
        if (pos + 5 <= len && strncmp(data + pos, "false", 5) == 0) {
            pos += 5; return false;
        }
        return false;
    }

    void skip_value() {
        skip_ws();
        if (pos >= len) return;
        char c = data[pos];
        if (c == '"') { read_string_raw(); }
        else if (c == '{') { skip_object(); }
        else if (c == '[') { skip_array(); }
        else if (c == 't') { pos += 4; }  // true
        else if (c == 'f') { pos += 5; }  // false
        else if (c == 'n') { pos += 4; }  // null
        else { read_number(); }
    }

    void skip_object() {
        expect('{');
        if (peek() == '}') { next(); return; }
        do {
            read_string_raw(); // key
            expect(':');
            skip_value();
        } while (expect(','));
        expect('}');
    }

    void skip_array() {
        expect('[');
        if (peek() == ']') { next(); return; }
        do { skip_value(); } while (expect(','));
        expect(']');
    }

    uint64_t hex_to_u64(const std::string& s) {
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            return strtoull(s.c_str() + 2, nullptr, 16);
        }
        return strtoull(s.c_str(), nullptr, 10);
    }

    Signature parse_signature(const std::string& ida_str) {
        Signature sig;
        if (ida_str.empty()) return sig;

        size_t i = 0;
        while (i < ida_str.size()) {
            while (i < ida_str.size() && ida_str[i] == ' ') ++i;
            if (i >= ida_str.size()) break;

            if (ida_str[i] == '?') {
                sig.bytes.push_back(0);
                sig.mask.push_back(false);
                ++i;
                if (i < ida_str.size() && ida_str[i] == '?') ++i;
            } else {
                char hex[3] = {0};
                hex[0] = ida_str[i++];
                if (i < ida_str.size() && ida_str[i] != ' ')
                    hex[1] = ida_str[i++];
                sig.bytes.push_back(static_cast<uint8_t>(strtoul(hex, nullptr, 16)));
                sig.mask.push_back(true);
            }
        }
        return sig;
    }

    Identity parse_identity() {
        Identity id;
        expect('{');
        while (peek() != '}') {
            std::string key = read_string_raw();
            expect(':');

            if (key == "return_type") {
                id.return_type = read_string_raw();
            } else if (key == "param_types") {
                expect('[');
                while (peek() != ']') {
                    id.param_types.push_back(read_string_raw());
                    expect(',');
                }
                expect(']');
            } else if (key == "param_count") {
                id.param_count = static_cast<uint8_t>(read_number());
            } else if (key == "has_return") {
                id.has_return = read_bool();
            } else if (key == "has_indirect_call") {
                id.has_indirect_call = read_bool();
            } else if (key == "has_switch") {
                id.has_switch = read_bool();
            } else if (key == "struct_flags") {
                id.struct_flags = static_cast<uint32_t>(read_number());
            } else {
                skip_value();
            }
            expect(',');
        }
        expect('}');
        return id;
    }

    Reinforcement parse_reinforcement() {
        Reinforcement rf;
        expect('{');
        while (peek() != '}') {
            std::string key = read_string_raw();
            expect(':');

            if (key == "size") {
                rf.size = static_cast<uint32_t>(read_number());
            } else if (key == "bb_count") {
                rf.bb_count = static_cast<uint16_t>(read_number());
            } else if (key == "cyclomatic") {
                rf.cyclomatic = static_cast<uint16_t>(read_number());
            } else if (key == "caller_count") {
                rf.caller_count = static_cast<uint32_t>(read_number());
            } else if (key == "callee_count") {
                rf.callee_count = static_cast<uint32_t>(read_number());
            } else if (key == "strings") {
                expect('[');
                while (peek() != ']') {
                    rf.strings.push_back(read_string_raw());
                    expect(',');
                }
                expect(']');
            } else if (key == "constants") {
                expect('[');
                while (peek() != ']') {
                    rf.constants.push_back(static_cast<uint64_t>(read_number()));
                    expect(',');
                }
                expect(']');
            } else {
                skip_value();
            }
            expect(',');
        }
        expect('}');
        return rf;
    }

    Anchor parse_anchor() {
        Anchor a;
        expect('{');
        while (peek() != '}') {
            std::string key = read_string_raw();
            expect(':');

            if (key == "priority") {
                a.priority = static_cast<ModulePriority>(read_number());
            } else if (key == "name") {
                a.name = read_string_raw();
            } else if (key == "signature") {
                a.signature = parse_signature(read_string_raw());
            } else if (key == "sig_offset") {
                a.signature.offset = static_cast<uint32_t>(read_number());
            } else if (key == "index") {
                a.index = static_cast<uint32_t>(read_number());
            } else if (key == "vtable_size") {
                a.vtable_size = static_cast<uint32_t>(read_number());
            } else if (key == "vtable_neighbor_before") {
                a.vtable_neighbor_before = static_cast<uint32_t>(read_number());
            } else if (key == "vtable_neighbor_after") {
                a.vtable_neighbor_after = static_cast<uint32_t>(read_number());
            } else if (key == "rva") {
                a.rva = read_rva();
            } else if (key == "fanout") {
                a.fanout = static_cast<uint32_t>(read_number());
            } else if (key == "chain_depth") {
                a.chain_depth = static_cast<uint8_t>(read_number());
            } else if (key == "chain_directions") {
                a.chain_directions = static_cast<uint8_t>(read_number());
            } else if (key == "chain_landmark_type") {
                a.chain_landmark_type = static_cast<uint8_t>(read_number());
            } else if (key == "func_size") {
                a.func_size = static_cast<uint32_t>(read_number());
            } else {
                skip_value(); // priority_name, etc.
            }
            expect(',');
        }
        expect('}');
        return a;
    }

    TrackedFunc parse_tracked_func() {
        TrackedFunc tf;
        expect('{');
        while (peek() != '}') {
            std::string key = read_string_raw();
            expect(':');

            if (key == "name") {
                tf.name = read_string_raw();
            } else if (key == "original_ea") {
                tf.original_ea = static_cast<ea_t>(hex_to_u64(read_string_raw()));
            } else if (key == "identity") {
                tf.identity = parse_identity();
            } else if (key == "reinforcement") {
                tf.reinforcement = parse_reinforcement();
            } else if (key == "export_sig") {
                tf.export_sig = parse_signature(read_string_raw());
            } else if (key == "tracking_sig") {
                tf.tracking_sig = parse_signature(read_string_raw());
            } else if (key == "prologue_length") {
                tf.prologue_length = static_cast<uint8_t>(read_number());
            } else if (key == "sig_offset") {
                tf.sig_offset = static_cast<int32_t>(read_number());
            } else if (key == "mid_context") {
                expect('[');
                while (peek() != ']') {
                    tf.mid_context.push_back(static_cast<uint16_t>(read_number()));
                    expect(',');
                }
                expect(']');
            } else if (key == "vtable_class") {
                tf.vtable_class = read_string_raw();
            } else if (key == "vtable_offset") {
                tf.vtable_offset = static_cast<int32_t>(read_number());
            } else if (key == "anchors") {
                expect('[');
                while (peek() != ']') {
                    tf.anchors.push_back(parse_anchor());
                    expect(',');
                }
                expect(']');
            } else {
                skip_value();
            }
            expect(',');
        }
        expect('}');
        return tf;
    }

public:
    JsonReader(const char* d, size_t l) : data(d), pos(0), len(l) {}

    struct Document {
        std::string version;
        std::string binary_name;
        std::vector<TrackedFunc> functions;
    };

    Document parse() {
        Document doc;
        expect('{');
        while (peek() != '}') {
            std::string key = read_string_raw();
            expect(':');

            if (key == "version") {
                doc.version = read_string_raw();
            } else if (key == "binary_name") {
                doc.binary_name = read_string_raw();
            } else if (key == "function_count") {
                read_number(); // informational, not used
            } else if (key == "functions") {
                expect('[');
                while (peek() != ']') {
                    doc.functions.push_back(parse_tracked_func());
                    expect(',');
                }
                expect(']');
            } else {
                skip_value();
            }
            expect(',');
        }
        expect('}');
        return doc;
    }
};

inline bool deserialize(const char* path,
                        std::vector<TrackedFunc>& out_funcs,
                        std::string& out_binary_name)
{
    FILE* fp = fopen(path, "r");
    if (!fp) return false;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0) { fclose(fp); return false; }

    std::vector<char> buf(static_cast<size_t>(fsize) + 1);
    size_t read_bytes = fread(buf.data(), 1, static_cast<size_t>(fsize), fp);
    fclose(fp);
    buf[read_bytes] = '\0';

    JsonReader reader(buf.data(), read_bytes);
    auto doc = reader.parse();

    out_binary_name = std::move(doc.binary_name);
    out_funcs = std::move(doc.functions);
    return true;
}

} // namespace io
} // namespace tracker

#endif // K4_TRACKER_DESERIALIZE_H
