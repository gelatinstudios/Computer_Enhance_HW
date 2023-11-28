
package hw_2

import "core:fmt"
import "core:os"
import "core:io"
import "core:bytes"

read_byte :: io.read_byte
read_u8 :: read_byte

read_u16 :: proc(reader: io.Reader) -> (result: u16, err: io.Error) {
    low  := io.read_byte(reader) or_return
    high := io.read_byte(reader) or_return
    return u16(high) << 8 | u16(low), .None
}

decode :: proc(reader: io.Reader) -> io.Error {
    reg_name :: proc(reg, w: u8) -> string {
        names := [?]string {
            "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
            "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
        }
        return names[(w << 3) | reg]
    }
    get_rm_str :: proc(reader: io.Reader, mod, rm, w: u8) -> (result: string, err: io.Error) {
        rm_table := [?]string {
            "bx + si", "bx + di",
            "bp + si", "bp + di",
            "si", "di", "bp", "bx",
        }
        if mod == 0b11 {
            return reg_name(rm, w), .None
        } else {
            if mod == 0b00 && rm == 0b110 {
                return fmt.tprintf("[{}]", read_u16(reader) or_return), .None
            } else {
                disp: i16
                switch mod {
                    case 0b01: disp = i16(i8(read_u8 (reader) or_return))
                    case 0b10: disp = i16(   read_u16(reader) or_return)
                }

                if disp == 0 {
                    return fmt.tprintf("[{}]", rm_table[rm]), .None
                } else if disp > 0 {
                    return fmt.tprintf("[{} + {}]", rm_table[rm],  disp), .None
                } else {
                    return fmt.tprintf("[{} - {}]", rm_table[rm], -disp), .None
                }
            }
        }
        return "", .None
    }
    get_imm_str :: proc(reader: io.Reader, w: u8) -> (result: string, err: io.Error) {
        imm: u16
        type: string
        if w == 1 {
            imm = read_u16(reader) or_return
            type = "word"
        } else {
            imm = u16(read_u8(reader) or_return)
            type = "byte"
        }
        return fmt.tprintf("{} {}", type, imm), .None
    }
    
    b := read_byte(reader) or_return

    dest, src: string
    
    is_first_row  := b & 0b11111100 == 0b10001000
    is_second_row := b & 0b11111110 == 0b11000110
    is_third_row  := b & 0b11110000 == 0b10110000
    is_fourth_or_fifth_row := b & 0b11111100 == 0b10100000
    if is_first_row || is_second_row {
        d := (b >> 1) & 1
        w := (b >> 0) & 1
        
        b = read_byte(reader) or_return
        
        mod := (b >> 6) & 0b11
        reg := (b >> 3) & 0b111
        rm  := (b >> 0) & 0b111
        
        rm_str := get_rm_str(reader, mod, rm, w) or_return

        if  is_first_row {
            reg_str := reg_name(reg, w)

            if d == 1 {
                dest, src = reg_str, rm_str
            } else {
                dest, src = rm_str, reg_str
            }
        } else {
            assert(reg == 0)

            dest = rm_str
            src = get_imm_str(reader, w) or_return
        }
    } else if is_third_row {
        w := (b >> 3) & 1
        reg := b & 0b111
        dest = reg_name(reg, w)
        src = get_imm_str(reader, w) or_return
    } else if is_fourth_or_fifth_row {
        d := (b >> 1) & 1
        w := (b >> 0) & 1

        mem_str := fmt.tprintf("[{}]", read_u16(reader) or_return)

        if d == 1 {
            dest = mem_str
            src = "ax"
        } else {
            dest = "ax"
            src = mem_str
        }
    }
    
    fmt.printf("mov {}, {}\n", dest, src)
    
    return .None
}

main :: proc() {
    path := os.args[1]

    contents, ok := os.read_entire_file(path)
    assert(ok)
    
    reader: bytes.Reader
    bytes.reader_init(&reader, contents)

    fmt.println("bits 16")
    
    stream := bytes.reader_to_stream(&reader)
    for bytes.reader_length(&reader) > 0 {
        err := decode(stream)
        if err != .None {
            fmt.eprintln("ERROR:",err)
            return
        }
    }
}
