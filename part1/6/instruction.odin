
package hw_6

import "core:io"

Operand :: struct {}

Instruction :: struct {
    mnemonic: Mnemonic,
    operands: [2]Maybe(Operand),
}

Field :: enum { d, w, mod, reg, rm, opcode }
field_lengths :: [Field]u8 {
        .d = 1,
        .w = 1,
        .mod = 2,
        .reg = 3,
        .rm = 3,
        .opcode = 3,
}

Bits :: struct {
    length: u8,
    bits:   u8,
}

Mnemonic :: enum {
    mov,
}

Mnemonic_Table :: [8]Mnemonic

Mnemonic_Or_Table :: union { Mnemonic, Mnemonic_Table }

Instruction_Encoding :: struct {
    prefix: Bits,
    fields: []Field,
    mnemonic: Mnemonic_Table,
}

encoding_table := [?]Instruction_Encoding {
    { {6, 0b100010}, {.d, .w, .mod, .reg, .rm}, .mov,  }
}

decode :: proc(r: io.Reader) -> (result: Instruction, err: io.Error) {
    
    
    return
}
