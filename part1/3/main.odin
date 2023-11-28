
package hw_3

import "core:strings"
import "core:slice"
import "core:os"
import "core:io"
import "core:bytes"
import "core:fmt"

read_u16 :: proc(reader: io.Reader) -> (result: u16, err: io.Error) {
    low  := io.read_byte(reader) or_return
    high := io.read_byte(reader) or_return
    return u16(high) << 8 | u16(low), .None
}

Field :: enum { d, s, v, w, z, mod, reg, rm, sr, opcode, zero, }
field_lengths := [Field]u8 {
        .d   = 1,
        .s   = 1,
        .w   = 1,
        .v   = 1,
        .z = 1,
        .mod = 2,
        .reg = 3,
        .rm  = 3,
        .sr = 2,
    
        .opcode = 3,
    
        .zero = 1,
}

Field_Arguments :: [Field]Maybe(u8)

Mnemonic_Or_Table :: union { Mnemonic, Mnemonic_Table, }
Mnemonic_Table :: [16]Mnemonic

Mnemonic :: enum {
    None,
    
    mov,
    push, pop,
    xchg,

    IN, // of course it's a fucking keyword god dammit
    out,
    xlat,
    lea, lds, les, lahf,
    sahf, pushf, popf,
    add, adc, inc,
    aaa, daa,
    sub, sbb, dec,
    neg,
    cmp,
    aas, das,
    mul, imul,
    aam,
    div, idiv,
    aad,
    cbw, cwd,
    not, shl, shr, sar,
    rol, ror, rcl, rcr,
    and, test, or, xor,
    movs, cmps, scas, lods, stos,
    call,
    jmp,
    ret,
    retf,
    je, jl, jle, jb, jbe, jp, jo, js,
    jne, jnl, jnle, jnb, jnbe, jnp, jno, jns,
    loop, loopz, loopnz,
    jcxz,

    rep,
    repnz,

    INT,
    int3,

    into, iret,
    clc, cmc, stc, cld, std,
    cli, sti, hlt, wait, lock,
}

Prefix :: struct {
    length: u8,
    bits: u8,
}

Decode_Entry :: struct {
    mnemonic_or_table: Mnemonic_Or_Table,
    kind: Decode_Entry_Kind,
    prefix: Prefix,
}

Decode_Entry_Kind :: enum {
    Reg_Rm,
    Rm, Reg, Sr,
    Rm_with_Reg,
    Reg_with_Acc,
    Imm_Rm, Imm_S_Rm,Imm_Reg,
    Rm_Sr, Sr_Rm,
    Mem_Acc, Acc_Mem, Imm_Acc,
    Jump,
    Fixed_Port, Variable_Port,
    No_Operands,
    Effective_Address,
    ASCII_Adjust, // why why why why
    Shift,
    Rep,
    Direct, Direct_Short, Direct_Interseg,
    Imm8, Imm16,
}

format_table := [Decode_Entry_Kind][]Field{
        .Reg_Rm  = { .d, .w, .mod, .reg, .rm },
        .Imm_Rm  = { .w, .mod, .opcode, .rm },
        .Imm_S_Rm  = { .s, .w, .mod, .opcode, .rm },
        .Imm_Reg = { .w, .reg },
        .Rm_Sr   = {.mod, .zero, .sr, .rm},
        .Sr_Rm   = {.mod, .zero, .sr, .rm},
        .Rm_with_Reg = { .w, .mod, .reg, .rm },
        .Reg_with_Acc = { .reg },
        .Mem_Acc = { .w },
        .Acc_Mem = { .w },
        .Imm_Acc = { .w },
        .Rm = { .w, .mod, .opcode, .rm },
        .Reg = { .reg },
        .Sr = { .sr, .opcode },
        .Jump = {},
        .Fixed_Port    = { .w },
        .Variable_Port = { .w },
        .No_Operands = {},
        .Effective_Address = { .mod, .reg, .rm },
        .ASCII_Adjust = {},
        .Shift = {.v, .w, .mod, .opcode, .rm },
        .Rep = { .z },
        .Direct = {},
        .Direct_Short = {},
        .Direct_Interseg = {},

        .Imm8 = {},
        .Imm16 = {},
}

decode_table := []Decode_Entry {
    { .mov, .Reg_Rm,  {6, 0b100010  } },
    
    { Mnemonic_Table {0b000 = .mov}, .Imm_Rm,  {7, 0b1100011  } },
    
    { .mov, .Imm_Reg, {4, 0b1011    } },
    { .mov, .Mem_Acc, {7, 0b1010000 } },
    { .mov, .Acc_Mem, {7, 0b1010001 } },
    { .mov, .Rm_Sr,   {8, 0b10001110 } },
    { .mov, .Sr_Rm,   {8, 0b10001100 } },

    {
        Mnemonic_Table {
            0b110 = .push,
            0b111 = .pop,
        }, .Sr, {3, 0b000},
    },

    {
        Mnemonic_Table {
            0b110 = .push,
            0b000 = .inc,
            0b001 = .dec,

            0b010 = .call,
            0b011 = .call,

            0b100 = .jmp,
            0b101 = .jmp,
        }, .Rm, {7, 0b1111111}
    },
    
    { .push, .Reg, {5, 0b01010 } },
    
    {
        Mnemonic_Table {
            0b000 = .pop,
        }, .Rm, {7, 0b1000111}
    },
    
    { .pop, .Reg, {5, 0b01011 } },
    

    { .xchg, .Rm_with_Reg,  {7, 0b1000011} },
    { .xchg, .Reg_with_Acc, {5, 0b10010} },

    {  .IN, .Fixed_Port,    {7, 0b1110010 } },
    {  .IN, .Variable_Port, {7, 0b1110110 } },

    { .out, .Fixed_Port,    {7, 0b1110011 } },
    { .out, .Variable_Port, {7, 0b1110111 } },

    { .xlat, .No_Operands, {8, 0b11010111} },

    { .lea, .Effective_Address, {8, 0b10001101} },
    { .lds, .Effective_Address, {8, 0b11000101} },
    { .les, .Effective_Address, {8, 0b11000100} },

    { .lahf, .No_Operands, {8, 0b10011111} },
    { .sahf, .No_Operands, {8, 0b10011110} },
    
    { .pushf, .No_Operands, {8, 0b10011100} },
    { .popf , .No_Operands, {8, 0b10011101} },
    
    {
        Mnemonic_Table {
            0b000 = .add,
            0b010 = .adc,
            0b101 = .sub,
            0b011 = .sbb,
            0b111 = .cmp,
            0b100 = .and,
            0b001 = .or,
            0b110 = .xor, // NOTE: typo in the manual??!?!?!?
        }, .Imm_S_Rm,  {6, 0b100000  }
    },
    
    { .add, .Reg_Rm,  {6, 0b000000  } },
    { .add, .Imm_Acc, {7, 0b0000010 } },

    { .adc, .Reg_Rm,  {6, 0b000100  } },
    { .adc, .Imm_Acc, {7, 0b0001010 } },

    { .inc, .Reg, {5, 0b01000} },

    { .aaa, .No_Operands, {8, 0b00110111} },
    { .daa, .No_Operands, {8, 0b00100111} },
    
    { .sub, .Reg_Rm,  {6, 0b001010  } },
    { .sub, .Imm_Acc, {7, 0b0010110 } },

    { .sbb, .Reg_Rm,  {6, 0b000110  } },
    { .sbb, .Imm_Acc, {7, 0b0001110 } },

    { .dec, .Reg, {5, 0b01001} },

    {
        Mnemonic_Table {
            0b011 = .neg,
            0b100 = .mul,
            0b101 = .imul,
            0b110 = .div,
            0b111 = .idiv,
            0b010 = .not,
            0b000 = .test,
        }, .Rm, {7, 0b1111011}
    },
    
    { .cmp, .Reg_Rm,  {6, 0b001110  } },
    { .cmp, .Imm_Acc, {7, 0b0011110 } },

    { .aas, .No_Operands, {8, 0b00111111} },
    { .das, .No_Operands, {8, 0b00101111} },

    { .aam, .ASCII_Adjust, {8, 0b11010100} },
    { .aad, .ASCII_Adjust, {8, 0b11010101} },

    { .cbw, .No_Operands, {8, 0b10011000} },
    { .cwd, .No_Operands, {8, 0b10011001} },

    {
        Mnemonic_Table {
            0b100 = .shl,
            0b101 = .shr,
            0b111 = .sar,
            0b000 = .rol,
            0b001 = .ror,
            0b010 = .rcl,
            0b011 = .rcr,
        }, .Shift, {6, 0b110100}
    },

    { .and, .Reg_Rm,  {6, 0b001000  } },
    { .and, .Imm_Acc, {7, 0b0010010 } },

    { .test, .Reg_Rm,  {6, 0b100001  } }, // NOTE: typo in the manual
    { .test, .Imm_Acc, {7, 0b1010100 } },

    { .or, .Reg_Rm,  {6, 0b000010  } },
    { .or, .Imm_Acc, {7, 0b0000110 } },

    { .xor, .Reg_Rm,  {6, 0b001100  } },
    { .xor, .Imm_Acc, {7, 0b0011010 } },
    
    { .je     , .Jump, {8,  0b01110100 } },
    { .jl     , .Jump, {8,  0b01111100 } },
    { .jle    , .Jump, {8,  0b01111110 } },
    { .jb     , .Jump, {8,  0b01110010 } },
    { .jbe    , .Jump, {8,  0b01110110 } },
    { .jp     , .Jump, {8,  0b01111010 } },
    { .jo     , .Jump, {8,  0b01110000 } },
    { .js     , .Jump, {8,  0b01111000 } },
    { .jne    , .Jump, {8,  0b01110101 } },
    { .jnl    , .Jump, {8,  0b01111101 } },
    { .jnle   , .Jump, {8,  0b01111111 } },
    { .jnb    , .Jump, {8,  0b01110011 } },
    { .jnbe   , .Jump, {8,  0b01110111 } },
    { .jnp    , .Jump, {8,  0b01111011 } },
    { .jno    , .Jump, {8,  0b01110001 } },
    { .jns    , .Jump, {8,  0b01111001 } },
    { .loop   , .Jump, {8,  0b11100010 } },
    { .loopz  , .Jump, {8,  0b11100001 } },
    { .loopnz , .Jump, {8,  0b11100000 } },
    { .jcxz   , .Jump, {8,  0b11100011 } },

    { .rep, .Rep, {7, 0b1111001} },

    { .call, .Direct,          {8, 0b11101000} },
    { .call, .Direct_Interseg, {8, 0b10011010} },

    { .jmp , .Direct,          {8, 0b11101001} },
    { .jmp , .Direct_Short,    {8, 0b11101011} },
    { .jmp , .Direct_Interseg, {8, 0b11101010} },

    { .ret, .No_Operands, {8, 0b11000011} }, // within segment
    { .retf, .No_Operands, {8, 0b11001011} }, // intersegment
    { .ret, .Imm16, {8, 0b11000010} }, // within segment
    { .retf, .Imm16, {8, 0b11001010} }, // intersegment

    { .INT,  .Imm8,        {8, 0b11001101} },
    { .int3, .No_Operands, {8, 0b11001100} },

    { .into, .No_Operands, {8, 0b11001110} },
    { .iret, .No_Operands, {8, 0b11001111} },
    
    { .clc,  .No_Operands, {8, 0b11111000} },
    { .cmc,  .No_Operands, {8, 0b11110101} },
    { .stc,  .No_Operands, {8, 0b11111001} },
    { .cld,  .No_Operands, {8, 0b11111100} },
    { .std,  .No_Operands, {8, 0b11111101} },
    { .cli,  .No_Operands, {8, 0b11111010} },
    { .sti,  .No_Operands, {8, 0b11111011} },
    { .hlt,  .No_Operands, {8, 0b11110100} },
    { .wait, .No_Operands, {8, 0b10011011} },
    
    { .lock, .No_Operands, {8, 0b11110000} },
}

decode_lut: [256]i16

@init
initialize_lut :: proc() {
    for &n in decode_lut { n = -1 }

    slice.sort_by_key(decode_table[:], proc(e: Decode_Entry) -> u8 { return e.prefix.length })
    
    for entry, entry_index in decode_table {
        prefix := entry.prefix
        shift := 8 - prefix.length
        for _, i in decode_lut {
            if u8(i) >> shift == prefix.bits {
                decode_lut[i] = i16(entry_index)
            }
        }
    }
}

Bit_Reader :: struct {
    reader: io.Reader,
    current_byte: u8,
    byte_offset: u8,
}

read_bits :: proc(using r: ^Bit_Reader, length: u8) -> (result: u8, err: io.Error) {
    assert(length <= 8)
    if byte_offset > 8 do panic("bit reader in invalid state")
    if byte_offset == 8 {
        current_byte = io.read_byte(reader) or_return
        byte_offset = 0
    }
    assert(byte_offset + length <= 8)
    defer byte_offset += length
    mask := u8(1 << length) - 1
    return (current_byte >> (8 - (byte_offset + length))) & mask, .None
}

decode :: proc(reader: io.Reader) -> io.Error {
    get_reg_name :: proc(reg, w: u8) -> string {
        table := [?]string {
            "al", "cl", "dl", "bl",
            "ah", "ch", "dh", "bh",
            
            "ax", "cx", "dx", "bx",
            "sp", "bp", "si", "di",
        }
        return table[(w<<3) | reg]
    }
    get_sr_name :: proc(sr: u8) -> string {
        table := [?]string { "es", "cs", "ss", "ds" }
        return table[sr]
    }
    get_rm_str :: proc(reader: io.Reader, mod,rm,w: u8, segment_prefix := "", no_type:=false, unsigned:=false) -> (result: string, err: io.Error) {
        if mod == 0b11 {
            result = get_reg_name(rm, w)
        } else {
            rm_table := [?]string {
                "bx + si", "bx + di",
                "bp + si", "bp + di",
                "si", "di", "bp", "bx",
            }

            is_direct_address := mod == 0b00 && rm == 0b110
            
            disp: i16
            if is_direct_address {
                disp = i16(read_u16(reader) or_return)
            } else  if mod == 0b01 {
                disp = i16(i8(io.read_byte(reader) or_return))
            } else  if mod == 0b10 {
                disp = i16(read_u16(reader) or_return)
            }

            type := w == 1 ? "word" : "byte"
            if no_type do type = ""
            
            base := rm_table[rm]
            if is_direct_address {
                result = fmt.tprintf("{} {}[{}]", type, segment_prefix, u16(disp))
            } else if disp == 0 {
                result = fmt.tprintf("{} {}[{}]", type, segment_prefix, base)
            } else if disp > 0 {
                result = fmt.tprintf("{} {}[{} + {}]", type, segment_prefix, base, disp)
            } else {
                result = fmt.tprintf("{} {}[{} - {}]", type, segment_prefix, base, -disp)
            }
        }
        return result, .None
    }
    
    get_imm_str :: proc(reader: io.Reader, w: u8) -> (result: string, err: io.Error) {
        type: string
        imm: u16
        if w == 1 {
            type = "word"
            imm = u16(read_u16(reader) or_return)
        } else {
            type = "byte"
            imm = u16(io.read_byte(reader) or_return)
        }
        return fmt.tprint(type, imm), .None
    }
    get_imm_s_str :: proc(reader: io.Reader, s, w: u8) -> (result: string, err: io.Error) {
        type: string
        imm: i16
        if w == 1 {
            type = "word"
            if s == 1 {
                imm = i16(i8(io.read_byte(reader) or_return))
            } else {
                imm = i16(read_u16(reader) or_return)
            }
        } else {
            type = "byte"
            imm = i16(i8(io.read_byte(reader) or_return))
        }
        return fmt.tprint(type, imm), .None
    }
    
    b := io.read_byte(reader) or_return

    segment_prefix: string
    if b & 0b11100111 == 0b00100110 { // segment override prefix
        sr := (b >> 3) & 0b11
        segment_prefix = fmt.tprint(get_sr_name(sr),':',sep="")
        b = io.read_byte(reader) or_return
    }

    decode_index := decode_lut[b]
    if decode_index < 0 {
        fmt.eprintf("UNKNOWN OPCODE: %08b\n", b)
    }
    
    entry := decode_table[decode_index]
    
    bit_reader := &Bit_Reader {reader, b, 0}

    // sanity check
    prefix_bits := read_bits(bit_reader, entry.prefix.length) or_return
    assert(prefix_bits == entry.prefix.bits)

    field_arguments: Field_Arguments
    for field in format_table[entry.kind] {
        bits := read_bits(bit_reader, field_lengths[field]) or_return
        field_arguments[field] = bits
    }

    mnemonic, ok := entry.mnemonic_or_table.(Mnemonic)
    if !ok {
        table := entry.mnemonic_or_table.(Mnemonic_Table)
        mnemonic = table[field_arguments[.opcode].(u8)]
        assert(mnemonic != .None)
    }
    
    operands: [dynamic]string
    defer delete(operands)
    switch entry.kind {
        case .Reg_Rm:
            d   := field_arguments[.d  ].(u8)
            w   := field_arguments[.w  ].(u8)
            mod := field_arguments[.mod].(u8)
            reg := field_arguments[.reg].(u8)
            rm  := field_arguments[.rm ].(u8)
            
            reg_str := get_reg_name(reg, w)
            rm_str := get_rm_str(reader, mod, rm, w, segment_prefix) or_return
            
            if d == 1 {
                append(&operands, reg_str)
                append(&operands, rm_str)
            } else {
                append(&operands, rm_str)
                append(&operands, reg_str)
            }

        case .Imm_Rm:
            w   := field_arguments[.w  ].(u8)
            mod := field_arguments[.mod].(u8)
            rm  := field_arguments[.rm ].(u8)

            append(&operands, get_rm_str(reader, mod, rm, w) or_return)
            append(&operands, get_imm_str(reader, w) or_return)

        case .Imm_S_Rm:
            s   := field_arguments[.s  ].(u8)
            w   := field_arguments[.w  ].(u8)
            mod := field_arguments[.mod].(u8)
            rm  := field_arguments[.rm ].(u8)

            append(&operands, get_rm_str(reader, mod, rm, w, segment_prefix) or_return)
            append(&operands, get_imm_s_str(reader, s, w) or_return)

        case .Imm_Reg:
            w   := field_arguments[.w  ].(u8)
            reg := field_arguments[.reg].(u8)

            append(&operands, get_reg_name(reg, w))
            append(&operands, get_imm_str(reader, w) or_return)

        case .Rm_Sr:
            mod := field_arguments[.mod].(u8)
            sr  := field_arguments[.sr ].(u8)
            rm  := field_arguments[.rm ].(u8)

            append(&operands, get_sr_name(sr))
            append(&operands, get_rm_str(reader, mod, rm, 1, segment_prefix) or_return)

        case .Sr_Rm:
            mod := field_arguments[.mod].(u8)
            sr  := field_arguments[.sr ].(u8)
            rm  := field_arguments[.rm ].(u8)

            append(&operands, get_rm_str(reader, mod, rm, 1, segment_prefix) or_return)
            append(&operands, get_sr_name(sr))
                        
        case .Rm:
            w   := field_arguments[.w  ].(u8)
            mod := field_arguments[.mod].(u8)
            rm  := field_arguments[.rm].(u8)
            
            opcode := field_arguments[.opcode].(u8)

            append(&operands, get_rm_str(reader, mod, rm, w, segment_prefix) or_return)
                
            // fucking why
            if mnemonic == .test {
                append(&operands, get_imm_str(reader, w) or_return)
            }

            if (mnemonic == .call || mnemonic == .jmp) && opcode & 1  == 1 {
                operands[0] = fmt.tprint("far ", operands[0])
            }

        case .Reg:
            reg := field_arguments[.reg].(u8)

            append(&operands, get_reg_name(reg, 1))
            
        case .Sr:
            sr := field_arguments[.sr].(u8)

            append(&operands, get_sr_name(sr))

        case .Rm_with_Reg:
            w   := field_arguments[.w  ].(u8)
            mod := field_arguments[.mod].(u8)
            reg := field_arguments[.reg].(u8)
            rm  := field_arguments[.rm ].(u8)

            append(&operands, get_rm_str(reader, mod, rm, w, segment_prefix) or_return)
            append(&operands, get_reg_name(reg, w))

        case .Reg_with_Acc:
            reg := field_arguments[.reg].(u8)
            
            append(&operands, "ax")
            append(&operands, get_reg_name(reg, 1))
            
        case .Mem_Acc:
            w := field_arguments[.w].(u8)

            append(&operands, w == 1 ? "ax" : "al")
            append(&operands, fmt.tprintf("[{}]", read_u16(reader) or_return))

        case .Acc_Mem:
            w := field_arguments[.w].(u8)

            append(&operands, fmt.tprintf("[{}]", read_u16(reader) or_return))
            append(&operands, w == 1 ? "ax" : "al")

        case .Imm_Acc:
            w := field_arguments[.w].(u8)

            append(&operands, w == 1 ? "ax" : "al")
            append(&operands, get_imm_str(reader, w) or_return)

        case .Jump:
            target := i8(io.read_byte(reader) or_return)
            append(&operands, fmt.tprintf("$+2%+d", target))

        case .Fixed_Port:
            w := field_arguments[.w].(u8)

            // assume in
            append(&operands, w == 1 ? "ax" : "al")
            append(&operands, fmt.tprint(io.read_byte(reader) or_return))

            if mnemonic == .out {
                operands[0], operands[1] = operands[1], operands[0]
            }
            
        case .Variable_Port:
            w := field_arguments[.w].(u8)

            // assume in
            append(&operands, w == 1 ? "ax" : "al")
            append(&operands, "dx")

            if mnemonic == .out {
                operands[0], operands[1] = operands[1], operands[0]
            }

        case .Effective_Address:
            mod := field_arguments[.mod].(u8)
            reg := field_arguments[.reg].(u8)
            rm  := field_arguments[.rm ].(u8)

            append(&operands, get_reg_name(reg, 1))
            append(&operands, get_rm_str(reader, mod, rm, 1, segment_prefix, true) or_return)

        case .ASCII_Adjust:
            b := io.read_byte(reader) or_return
            assert(b == 0b00001010)
            /// ???

        case .Shift:
            v   := field_arguments[.v  ].(u8)
            w   := field_arguments[.w  ].(u8)
            mod := field_arguments[.mod].(u8)
            rm  := field_arguments[.rm ].(u8)

            append(&operands, get_rm_str(reader, mod, rm, w, segment_prefix) or_return)
            append(&operands, v == 1 ? "cl" : "1")

        case .Rep:
            z := field_arguments[.z].(u8)

            if z == 0 do mnemonic = .repnz
            
            b := io.read_byte(reader) or_return
            assert(b & 0b11110000 == 0b10100000)

            opcode := (b >> 1) & 0b111
            w := b & 1

            // TODO: aren't these all seperate instructions ??
            tab := [8]string {
                0b010 = "movs",
                0b011 = "cmps",
                0b111 = "scas",
                0b110 = "lods",
                0b101 = "stos",
            }

            arg := tab[opcode]
            assert(arg != "")
            append(&operands, fmt.tprintf("{}{}", arg, w == 1 ? 'w' : 'b'))

            // TODO:
        case .Direct:
            a := read_u16(reader) or_return

            at := io.seek(reader, 0, .Current) or_return
            
            append(&operands, fmt.tprint(a + u16(at)))

        case .Direct_Short:
            _ = io.read_byte(reader) or_return
            append(&operands, "DIRECT SHORT")

        case .Direct_Interseg:
            a := read_u16(reader) or_return
            b := read_u16(reader) or_return
            append(&operands, fmt.tprint(b,a,sep=":"))

        case .Imm8:
            append(&operands, fmt.tprint(io.read_byte(reader) or_return))

        case .Imm16:
            append(&operands, fmt.tprint(i16(read_u16(reader) or_return)))
            
        case .No_Operands: // do nothing :)
    }
    
    if mnemonic == .lock {
        fmt.print("lock ")
    } else {
        op_str := strings.join(operands[:], ", ", context.temp_allocator)
        fmt.println(mnemonic, op_str)
    }
    
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
        free_all(context.temp_allocator)
        err := decode(stream)
        if err != .None {
            fmt.eprintln(err)
            return
        }
    }
}
