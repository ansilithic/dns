import Foundation
import CLICore

func maskToCIDR(_ mask: String) -> Int {
    let octets = mask.split(separator: ".").compactMap { Int($0) }
    guard octets.count == 4 else { return 0 }
    var bits = 0
    for octet in octets {
        switch octet {
        case 255: bits += 8
        case 254: bits += 7
        case 252: bits += 6
        case 248: bits += 5
        case 240: bits += 4
        case 224: bits += 3
        case 192: bits += 2
        case 128: bits += 1
        default: break
        }
    }
    return bits
}

func parseIP(_ ip: String) -> (Int, Int, Int, Int)? {
    let parts = ip.split(separator: ".").compactMap { Int($0) }
    guard parts.count == 4 else { return nil }
    return (parts[0], parts[1], parts[2], parts[3])
}

func calcNetwork(_ ip: String, _ mask: String) -> String? {
    guard let (i1, i2, i3, i4) = parseIP(ip),
          let (m1, m2, m3, m4) = parseIP(mask) else { return nil }
    return "\(i1 & m1).\(i2 & m2).\(i3 & m3).\(i4 & m4)"
}

func calcBroadcast(_ ip: String, _ mask: String) -> String? {
    guard let (i1, i2, i3, i4) = parseIP(ip),
          let (m1, m2, m3, m4) = parseIP(mask) else { return nil }
    return "\(i1 | (255 - m1)).\(i2 | (255 - m2)).\(i3 | (255 - m3)).\(i4 | (255 - m4))"
}

func reverseDNS(_ ip: String) -> String {
    let result = shell("dig +short +time=1 +tries=1 -x \(ip) 2>/dev/null | head -1").output
    if result.hasSuffix(".") {
        return String(result.dropLast())
    }
    return result
}

func resolveIP(_ hostname: String) -> String {
    let cleaned = hostname.hasSuffix(".") ? String(hostname.dropLast()) : hostname
    let result = shell("dig +short \(cleaned) A 2>/dev/null | head -1").output
    return result
}

func printValue(_ label: String, _ value: String, labelWidth: Int = 16) {
    let paddedLabel = label.padding(toLength: labelWidth, withPad: " ", startingAt: 0)
    print("  \(styled(paddedLabel, .gray))\(value)")
}
