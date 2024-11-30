
package computer_enhance_part2_hw_gen

import "core:os"
import "core:flags"
import "core:math/rand"
import "core:encoding/json"
import "core:fmt"

Entry :: struct {
    x0, y0, x1, y1: f64
}

Pairs :: struct {
    pairs: []Entry,
}

generate_json :: proc(pair_count: int, fd: os.Handle) {   
    random_coord :: proc() -> f64 {
        return rand.float64_range(-180, 180)
    }
    pairs: Pairs
    pairs.pairs = make([]Entry, pair_count)
    defer delete(pairs.pairs)
    for &p in pairs.pairs {
        p.x0 = random_coord()
        p.y0 = random_coord()
        p.x1 = random_coord()
        p.y1 = random_coord()
    }
    opt := json.Marshal_Options {
        spec = .JSON,
        pretty = true,
        use_spaces = true,
        spaces = 4,
    }
    data, err := json.marshal(pairs, opt)
    assert(err == nil)
    os.write(fd, data)
}

Options :: struct {
    output_file: os.Handle `args:"pos=0,required,file=wct" usage:"Output json file."`,
    pair_count: int        `args:"pos=1,required"          usage:"Number of pairs to generate"`,
}

main :: proc() {
    opt: Options
    flags.parse_or_exit(&opt, os.args)
    generate_json(opt.pair_count, opt.output_file)
}