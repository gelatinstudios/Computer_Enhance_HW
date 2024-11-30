
package computer_enhance_part2_hw

import "core:math"

square :: proc(x: f64) -> f64 { return x*x }

radians_from_degrees :: proc(degrees: f64) -> f64 {
    return 0.01745329251994329577 * degrees
}

reference_haversine :: proc(x0, y0, x1, y1, earth_radius: f64) -> f64 {
    lat1 := y0;
    lat2 := y1;
    lon1 := x0;
    lon2 := x1;
    
    dLat := radians_from_degrees(lat2 - lat1);
    dLon := radians_from_degrees(lon2 - lon1);
    lat1 = radians_from_degrees(lat1);
    lat2 = radians_from_degrees(lat2);
    
    a := square(math.sin(dLat/2.0)) + math.cos(lat1)*math.cos(lat2)*square(math.sin(dLon/2));
    c := 2.0*math.asin(math.sqrt(a));
    
    Result := earth_radius * c;
    
    return Result;
}