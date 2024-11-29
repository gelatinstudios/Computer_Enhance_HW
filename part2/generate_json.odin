
package computer_enhance_part2_hw

import "core:os"
import "core:math/rand"
import "core:encoding/json"
import "core:fmt"

Entry :: struct {
    x0, y0, x1, y1: f64
}

Pairs :: struct {
    pairs: []Entry,
}

generate_json :: proc(pair_count: int, path: string) {   
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
    os.write_entire_file(path, data)
}

main :: proc() {
    counts := []int {100, 1000, 10000, 100000, 1000000}
    for c in counts {
        path := fmt.tprintf("test_data_{}.json", c)
        generate_json(c, path)
    }
}