
package computer_enhance_part2_hw

import "core:os"
import "core:fmt"
import "core:unicode"
import "core:strconv"

Entry :: struct {
    x0, y0, x1, y1: f64,
}

Parser :: struct {
    source: string,
    at: int,
    pairs: [dynamic]Entry,
}

skip_whitespace :: proc(parser: ^Parser) {
    for parser.at < len(parser.source) &&
        unicode.is_space(cast(rune) parser.source[parser.at]) {
        parser.at += 1
    }
}

get_token :: proc(parser: ^Parser) -> (string, bool) {
    skip_whitespace(parser)

    if parser.at >= len(parser.source) {
        return "", false
    }

    r := rune(parser.source[parser.at])

    start := parser.at
    result: string
    if r == '"' {
        parser.at += 1
        for parser.at < len(parser.source) &&
            parser.source[parser.at] != '"' 
        {
            parser.at += 1
        }
        parser.at += 1
    } else if unicode.is_digit(r) || r == '-' {
        for parser.at < len(parser.source) &&
            (unicode.is_digit(cast(rune) parser.source[parser.at]) ||
             parser.source[parser.at] == '-'                       || 
             parser.source[parser.at] == '.')
        {
            parser.at += 1
        }
    } else {
        parser.at += 1
    }
    result = parser.source[start:parser.at]

    skip_whitespace(parser)

    return result, true
}

peek_token :: proc(parser: ^Parser) -> string {
    at := parser.at
    t, _ := get_token(parser)
    parser.at = at
    return t
}

advance_token :: proc(parser: ^Parser) {
    get_token(parser)
}

expect_token :: proc(parser: ^Parser, token: string) -> bool {
    t, _ := get_token(parser)
    return token == t
}

parse_field :: proc(parser: ^Parser, name: string, ending_comma := true) -> (result: f64, ok: bool) {
    expect_token(parser, name) or_return
    expect_token(parser, ":")  or_return
    result = strconv.parse_f64(get_token(parser) or_return) or_return
    if ending_comma {
        expect_token(parser, ",")
    }
    return result, true
}

parse_json :: proc(parser: ^Parser) -> bool {
    expect_token(parser, "{") or_return

    expect_token(parser, "\"pairs\"") or_return
    expect_token(parser, ":") or_return
    expect_token(parser, "[") or_return

    for {
        entry: Entry

        expect_token(parser, "{")
        entry.x0 = parse_field(parser, "\"x0\"") or_return
        entry.y0 = parse_field(parser, "\"y0\"") or_return
        entry.x1 = parse_field(parser, "\"x1\"") or_return
        entry.y1 = parse_field(parser, "\"y1\"", false) or_return
        expect_token(parser, "}")

        append(&parser.pairs, entry)

        if peek_token(parser) != "," {
            break
        }
        advance_token(parser)
    }

    expect_token(parser, "]") or_return
    expect_token(parser, "}") or_return
    return true
}

parse :: proc(path: string) -> (result: []Entry, ok: bool) {
    file_contents := os.read_entire_file(path) or_return
    defer delete(file_contents)

    parser: Parser
    parser.pairs = make([dynamic]Entry)
    parser.source = string(file_contents)
    parse_json(&parser) or_return
    return parser.pairs[:], true
}