import ArgumentParser
import CLICore
import Foundation

@main
struct DNS: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "dns",
        abstract: "Show DNS and network configuration.",
        version: "1.0.0"
    )

    func run() {
        print()
        print(styled("Network", .bold, .cyan))

        // Find active interfaces and show subnet info
        let interfaces = shell("ifconfig -l").output.split(separator: " ").map(String.init)
        for iface in interfaces where iface.hasPrefix("en") {
            let ip = shell("ipconfig getifaddr \(iface) 2>/dev/null").output
            guard !ip.isEmpty else { continue }

            let mask = shell("ipconfig getoption \(iface) subnet_mask 2>/dev/null").output
            let router = shell("ipconfig getoption \(iface) router 2>/dev/null").output

            guard !mask.isEmpty else { continue }

            let cidr = maskToCIDR(mask)

            print()
            print("  \(styled(iface, .bold))")
            printValue("IP", ip)

            if let network = calcNetwork(ip, mask) {
                printValue("Subnet", "\(network)/\(cidr)")

                if let broadcast = calcBroadcast(ip, mask),
                   let (n1, n2, n3, n4) = parseIP(network),
                   let (b1, b2, b3, b4) = parseIP(broadcast) {
                    let first = "\(n1).\(n2).\(n3).\(n4 + 1)"
                    let last = "\(b1).\(b2).\(b3).\(b4 - 1)"
                    printValue("Range", "\(first) - \(last)")
                }

                if !router.isEmpty {
                    printValue("Gateway", router)
                }
                printValue("Scan", styled("nmap -sn \(network)/\(cidr)", .dim))
            }
        }

        // DNS Servers
        print()
        print(styled("DNS Servers", .bold, .cyan))

        for iface in interfaces where iface.hasPrefix("en") {
            let dhcpDNS = shell("ipconfig getpacket \(iface) 2>/dev/null | grep domain_name_server | sed 's/.*{\\(.*\\)}/\\1/' | tr ',' '\\n'").output
            guard !dhcpDNS.isEmpty else { continue }

            print()
            print("  \(styled("\(iface) (DHCP)", .bold))")
            for dns in dhcpDNS.split(separator: "\n").map({ $0.trimmingCharacters(in: .whitespaces) }) where !dns.isEmpty {
                let hostname = reverseDNS(dns)
                if !hostname.isEmpty {
                    print("    \(dns) \(styled("(\(hostname))", .dim))")
                } else {
                    print("    \(dns)")
                }
            }
        }

        // Manual DNS
        let services = shellLines("networksetup -listallnetworkservices 2>/dev/null | tail -n +2")
        for service in services {
            let dns = shell("networksetup -getdnsservers \"\(service)\" 2>/dev/null").output
            guard !dns.contains("There aren't any") else { continue }
            guard !dns.isEmpty else { continue }

            print()
            print("  \(styled("\(service) (manual)", .bold))")
            for server in dns.split(separator: "\n").map(String.init) {
                let hostname = reverseDNS(server)
                if !hostname.isEmpty {
                    print("    \(server) \(styled("(\(hostname))", .dim))")
                } else {
                    print("    \(server)")
                }
            }
        }

        // Search Domains
        print()
        print(styled("Search Domains", .bold, .cyan))

        let domains = shellLines("scutil --dns | awk '/search domain\\[/ {print $4}' | sort -u")
        if domains.isEmpty {
            print("  \(styled("(none)", .dim))")
        } else {
            for d in domains {
                print("  \(d)")
            }
        }

        // Resolvers
        print()
        print(styled("Resolvers", .bold, .cyan))

        let resolvers = shell("""
            scutil --dns | awk '
                /^resolver #/ { resolver = $0; next }
                /nameserver\\[0\\]/ { ns = $3 }
                /domain[[:space:]]*:/ { domain = $3 }
                /if_index/ {
                    iface = $4
                    gsub(/[()]/, "", iface)
                    if (ns != "") {
                        printf "%s|%s|%s\\n", iface, ns, domain
                    }
                    ns = ""; domain = ""
                }
            '
            """).output

        if resolvers.isEmpty {
            print("  \(styled("(none)", .dim))")
        } else {
            for line in resolvers.split(separator: "\n") {
                let parts = line.split(separator: "|", maxSplits: 2).map(String.init)
                guard parts.count >= 2 else { continue }
                let iface = parts[0]
                let ns = parts[1]
                let domain = parts.count > 2 ? parts[2] : ""
                if !domain.isEmpty {
                    print("  \(styled(iface, .gray)): \(ns) \(styled("(\(domain))", .dim))")
                } else {
                    print("  \(styled(iface, .gray)): \(ns)")
                }
            }
        }

        // mDNS/Bonjour
        print()
        print(styled("mDNS/Bonjour", .bold, .cyan))
        let localHostname = shell("scutil --get LocalHostName 2>/dev/null").output
        if !localHostname.isEmpty {
            print("  Local: \(localHostname).local")
        }

        // Active Directory
        print()
        print(styled("Active Directory", .bold, .cyan))

        let searchDomains = shellLines("scutil --dns | awk '/search domain\\[/ {print $4}' | sort -u")
        var foundAD = false

        for domain in searchDomains {
            if domain == "local" || domain.hasSuffix(".local") { continue }

            let dcSrv = shell("dig +short _ldap._tcp.dc._msdcs.\(domain) SRV 2>/dev/null").output
            guard !dcSrv.isEmpty else { continue }

            foundAD = true
            print()
            print("  \(styled(domain, .bold))")

            // PDC
            let pdcSrv = shell("dig +short _ldap._tcp.pdc._msdcs.\(domain) SRV 2>/dev/null").output
            if !pdcSrv.isEmpty {
                print("    \(styled("PDC:", .gray))")
                for line in pdcSrv.split(separator: "\n") {
                    let parts = line.split(separator: " ")
                    guard parts.count >= 4 else { continue }
                    let target = String(parts[3]).trimmingCharacters(in: CharacterSet(charactersIn: "."))
                    let ip = resolveIP(target)
                    if !ip.isEmpty {
                        print("      \(target) (\(ip))")
                    } else {
                        print("      \(target)")
                    }
                }
            }

            // Domain Controllers
            print("    \(styled("Domain Controllers:", .gray))")
            for line in dcSrv.split(separator: "\n") {
                let parts = line.split(separator: " ")
                guard parts.count >= 4 else { continue }
                let target = String(parts[3]).trimmingCharacters(in: CharacterSet(charactersIn: "."))
                let ip = resolveIP(target)
                let isPDC = pdcSrv.contains(target)
                var entry = target
                if !ip.isEmpty { entry += " (\(ip))" }
                if isPDC { entry += " \(styled("[PDC]", .green))" }
                print("      \(entry)")
            }

            // Global Catalog
            let gcSrv = shell("dig +short _gc._tcp.\(domain) SRV 2>/dev/null").output
            if !gcSrv.isEmpty {
                print("    \(styled("Global Catalog:", .gray))")
                for line in gcSrv.split(separator: "\n") {
                    let parts = line.split(separator: " ")
                    guard parts.count >= 4 else { continue }
                    let target = String(parts[3]).trimmingCharacters(in: CharacterSet(charactersIn: "."))
                    let ip = resolveIP(target)
                    if !ip.isEmpty {
                        print("      \(target) (\(ip)) :3268")
                    } else {
                        print("      \(target) :3268")
                    }
                }
            }

            // Kerberos KDCs
            let kdcSrv = shell("dig +short _kerberos._tcp.\(domain) SRV 2>/dev/null").output
            if !kdcSrv.isEmpty {
                print("    \(styled("Kerberos KDCs:", .gray))")
                for line in kdcSrv.split(separator: "\n") {
                    let parts = line.split(separator: " ")
                    guard parts.count >= 4 else { continue }
                    let target = String(parts[3]).trimmingCharacters(in: CharacterSet(charactersIn: "."))
                    let ip = resolveIP(target)
                    if !ip.isEmpty {
                        print("      \(target) (\(ip)) :88")
                    } else {
                        print("      \(target) :88")
                    }
                }
            }

            // LDAP/LDAPS counts
            let ldapCount = shellLines("dig +short _ldap._tcp.\(domain) SRV 2>/dev/null").count
            if ldapCount > 0 {
                print("    \(styled("LDAP Servers:", .gray)) \(ldapCount) (:389)")
            }

            let ldapsCount = shellLines("dig +short _ldaps._tcp.\(domain) SRV 2>/dev/null").count
            if ldapsCount > 0 {
                print("    \(styled("LDAPS Servers:", .gray)) \(ldapsCount) (:636)")
            }
        }

        if !foundAD {
            print("  \(styled("(no AD domains found)", .dim))")
        }

        print()
    }
}
