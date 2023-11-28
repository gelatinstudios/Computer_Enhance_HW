
package hw_1

import "core:os"
import "core:io"
import "core:bytes"
import "core:fmt"

decode :: proc(reader: io.Reader) -> io.Error {
    reg_name :: proc(reg,w: u8) -> string {
        wreg_table := [?]string {
            "al", "cl", "dl", "bl",
            "ah", "ch", "dh", "bh",

            "ax", "cx", "dx", "bx",
            "sp", "bp", "si", "di"
        }
        return wreg_table[(w<<3) | reg]
    }

    b := io.read_byte(reader) or_return

    d := (b >> 1) & 1
    w := (b >> 0) & 1

    b = io.read_byte(reader) or_return

    mod := (b >> 6) & 0b11
    reg := (b >> 3) & 0b111
    rm  := (b >> 0) & 0b111

    assert(mod == 0b11)
    
    src, dest := reg, rm
    if d == 1 do src, dest = rm, reg

    fmt.printf("mov {},{}\n", reg_name(dest,w), reg_name(src,w))
    
    return .None
}

main :: proc() {
    path := os.args[1]

    contents, ok := os.read_entire_file(path)
    assert(ok)

    byte_reader: bytes.Reader
    bytes.reader_init(&byte_reader, contents)

    fmt.println("bits 16")
    for bytes.reader_length(&byte_reader) > 0 {
        err := decode(bytes.reader_to_stream(&byte_reader))
        if err != .None {
            fmt.eprintln("io error:", err)
        }
    }
}
