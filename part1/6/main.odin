
package hw_6

import "core:os"
import "core:fmt"
import "core:bytes"

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
        instruction, err := decode(stream)
        if err != .None {
            fmt.eprintln(err)
            return
        }
        fmt.println(instruction)
    }
}
