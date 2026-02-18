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
        let interfaces = shell("ifconfig -l").output.split(separator: " ").map(String.init)

        // Pre-collect active interfaces
        let activeInterfaces = interfaces.filter { $0.hasPrefix("en") }.compactMap {
            iface -> (name: String, ip: String, mask: String, router: String)? in
            let ip = shell("ipconfig getifaddr \(iface) 2>/dev/null").output
            guard !ip.isEmpty else { return nil }
            let mask = shell("ipconfig getoption \(iface) subnet_mask 2>/dev/null").output
            guard !mask.isEmpty else { return nil }
            let router = shell("ipconfig getoption \(iface) router 2>/dev/null").output
            return (iface, ip, mask, router)
        }

        // Pre-collect DNS server groups
        struct DNSGroup {
            let label: String
            let servers: [(ip: String, hostname: String)]
        }
        var dnsGroups: [DNSGroup] = []

        for iface in interfaces where iface.hasPrefix("en") {
            let dhcpDNS = shell(
                "ipconfig getpacket \(iface) 2>/dev/null | grep domain_name_server | sed 's/.*{\\(.*\\)}/\\1/' | tr ',' '\\n'"
            ).output
            guard !dhcpDNS.isEmpty else { continue }
            let servers = dhcpDNS.split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
                .map { ip in (ip: ip, hostname: reverseDNS(ip)) }
            dnsGroups.append(DNSGroup(label: "\(iface) (DHCP)", servers: servers))
        }

        let services = shellLines("networksetup -listallnetworkservices 2>/dev/null | tail -n +2")
        for service in services {
            let dns = shell("networksetup -getdnsservers \"\(service)\" 2>/dev/null").output
            guard !dns.contains("There aren't any"), !dns.isEmpty else { continue }
            let servers = dns.split(separator: "\n").map { ip in
                let s = String(ip)
                return (ip: s, hostname: reverseDNS(s))
            }
            dnsGroups.append(DNSGroup(label: "\(service) (manual)", servers: servers))
        }

        // Pre-collect search domains
        let domains = shellLines("scutil --dns | awk '/search domain\\[/ {print $4}' | sort -u")

        // Pre-collect resolvers
        let resolverOutput = shell("""
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
        struct ResolverEntry {
            let iface: String
            let ns: String
            let domain: String
        }
        let resolverEntries: [ResolverEntry] = resolverOutput.split(separator: "\n").compactMap {
            let parts = $0.split(separator: "|", maxSplits: 2).map(String.init)
            guard parts.count >= 2 else { return nil }
            return ResolverEntry(
                iface: parts[0], ns: parts[1],
                domain: parts.count > 2 ? parts[2] : "")
        }

        // Pre-collect mDNS
        let localHostname = shell("scutil --get LocalHostName 2>/dev/null").output

        // Pre-collect AD
        let searchDomains = shellLines(
            "scutil --dns | awk '/search domain\\[/ {print $4}' | sort -u")
        struct ADDomain {
            let domain: String
            let pdcEntries: [(target: String, ip: String)]
            let dcEntries: [(target: String, ip: String, isPDC: Bool)]
            let gcEntries: [(target: String, ip: String)]
            let kdcEntries: [(target: String, ip: String)]
            let ldapCount: Int
            let ldapsCount: Int
        }
        var adDomains: [ADDomain] = []

        for domain in searchDomains {
            if domain == "local" || domain.hasSuffix(".local") { continue }
            let dcSrv = shell("dig +short _ldap._tcp.dc._msdcs.\(domain) SRV 2>/dev/null").output
            guard !dcSrv.isEmpty else { continue }

            let pdcSrv =
                shell("dig +short _ldap._tcp.pdc._msdcs.\(domain) SRV 2>/dev/null").output
            let pdcEntries: [(String, String)] = pdcSrv.split(separator: "\n").compactMap {
                let parts = $0.split(separator: " ")
                guard parts.count >= 4 else { return nil }
                let target = String(parts[3]).trimmingCharacters(in: CharacterSet(charactersIn: "."))
                return (target, resolveIP(target))
            }

            let dcEntries: [(String, String, Bool)] = dcSrv.split(separator: "\n").compactMap {
                let parts = $0.split(separator: " ")
                guard parts.count >= 4 else { return nil }
                let target = String(parts[3]).trimmingCharacters(in: CharacterSet(charactersIn: "."))
                return (target, resolveIP(target), pdcSrv.contains(target))
            }

            let gcSrv = shell("dig +short _gc._tcp.\(domain) SRV 2>/dev/null").output
            let gcEntries: [(String, String)] = gcSrv.split(separator: "\n").compactMap {
                let parts = $0.split(separator: " ")
                guard parts.count >= 4 else { return nil }
                let target = String(parts[3]).trimmingCharacters(in: CharacterSet(charactersIn: "."))
                return (target, resolveIP(target))
            }

            let kdcSrv =
                shell("dig +short _kerberos._tcp.\(domain) SRV 2>/dev/null").output
            let kdcEntries: [(String, String)] = kdcSrv.split(separator: "\n").compactMap {
                let parts = $0.split(separator: " ")
                guard parts.count >= 4 else { return nil }
                let target = String(parts[3]).trimmingCharacters(in: CharacterSet(charactersIn: "."))
                return (target, resolveIP(target))
            }

            let ldapCount = shellLines(
                "dig +short _ldap._tcp.\(domain) SRV 2>/dev/null"
            ).count
            let ldapsCount = shellLines(
                "dig +short _ldaps._tcp.\(domain) SRV 2>/dev/null"
            ).count

            adDomains.append(ADDomain(
                domain: domain,
                pdcEntries: pdcEntries,
                dcEntries: dcEntries,
                gcEntries: gcEntries,
                kdcEntries: kdcEntries,
                ldapCount: ldapCount,
                ldapsCount: ldapsCount
            ))
        }

        // --- Render ---

        // Determine which sections have content
        let hasNetwork = !activeInterfaces.isEmpty
        let hasDNS = !dnsGroups.isEmpty
        let hasDomains = !domains.isEmpty
        let hasResolvers = !resolverEntries.isEmpty
        let hasMDNS = !localHostname.isEmpty
        let hasAD = true  // always show, even if "(no AD domains found)"

        let sections: [Bool] = [hasNetwork, hasDNS, hasDomains, hasResolvers, hasMDNS, hasAD]
        let lastTrue = sections.lastIndex(of: true) ?? sections.count - 1

        print()
        print(styled("dns", .bold))

        // Network
        if hasNetwork {
            let isFirst = true
            let isLast = (0 == lastTrue)
            print(styled("│", .dim))
            print(Tree.section("Network", isFirst: isFirst, isLast: isLast))
            let sectionPrefix = Tree.childPrefix("", parentIsLast: isLast)

            for (i, iface) in activeInterfaces.enumerated() {
                let ifaceLast = (i == activeInterfaces.count - 1)
                print(sectionPrefix + styled("│", .dim))
                print(Tree.subHeader(iface.name, prefix: sectionPrefix, isLast: ifaceLast))
                let ifacePrefix = Tree.childPrefix(sectionPrefix, parentIsLast: ifaceLast)

                let cidr = maskToCIDR(iface.mask)
                let network = calcNetwork(iface.ip, iface.mask)
                let broadcast = network != nil ? calcBroadcast(iface.ip, iface.mask) : nil

                // Count leaves to track isLast
                var leaves: [(label: String, value: String)] = []
                leaves.append(("IP", iface.ip))
                if let net = network {
                    leaves.append(("Subnet", "\(net)/\(cidr)"))
                    if let bc = broadcast,
                        let (n1, n2, n3, n4) = parseIP(net),
                        let (b1, b2, b3, b4) = parseIP(bc)
                    {
                        let first = "\(n1).\(n2).\(n3).\(n4 + 1)"
                        let last = "\(b1).\(b2).\(b3).\(b4 - 1)"
                        leaves.append(("Range", "\(first) - \(last)"))
                    }
                    if !iface.router.isEmpty {
                        leaves.append(("Gateway", iface.router))
                    }
                    leaves.append(("Scan", styled("nmap -sn \(net)/\(cidr)", .dim)))
                }

                for (j, leaf) in leaves.enumerated() {
                    print(
                        Tree.leaf(
                            leaf.label, leaf.value,
                            prefix: ifacePrefix, isLast: j == leaves.count - 1))
                }
            }
        }

        // DNS Servers
        if hasDNS {
            let sectionIndex = 1
            let isLast = (sectionIndex == lastTrue)
            print(styled("│", .dim))
            print(Tree.section("DNS Servers", isFirst: false, isLast: isLast))
            let sectionPrefix = Tree.childPrefix("", parentIsLast: isLast)

            for (i, group) in dnsGroups.enumerated() {
                let groupLast = (i == dnsGroups.count - 1)
                print(Tree.subHeader(group.label, prefix: sectionPrefix, isLast: groupLast))
                let groupPrefix = Tree.childPrefix(sectionPrefix, parentIsLast: groupLast)

                for (j, server) in group.servers.enumerated() {
                    let serverLast = (j == group.servers.count - 1)
                    let text: String
                    if !server.hostname.isEmpty {
                        text = "\(server.ip) \(styled("(\(server.hostname))", .dim))"
                    } else {
                        text = server.ip
                    }
                    print(Tree.leafText(text, prefix: groupPrefix, isLast: serverLast))
                }
            }
        }

        // Search Domains
        if hasDomains {
            let sectionIndex = 2
            let isLast = (sectionIndex == lastTrue)
            print(styled("│", .dim))
            print(Tree.section("Search Domains", isFirst: false, isLast: isLast))
            let sectionPrefix = Tree.childPrefix("", parentIsLast: isLast)

            for (i, d) in domains.enumerated() {
                print(Tree.leafText(d, prefix: sectionPrefix, isLast: i == domains.count - 1))
            }
        }

        // Resolvers
        if hasResolvers {
            let sectionIndex = 3
            let isLast = (sectionIndex == lastTrue)
            print(styled("│", .dim))
            print(Tree.section("Resolvers", isFirst: false, isLast: isLast))
            let sectionPrefix = Tree.childPrefix("", parentIsLast: isLast)

            for (i, entry) in resolverEntries.enumerated() {
                let text: String
                if !entry.domain.isEmpty {
                    text =
                        "\(styled(entry.iface, .gray)): \(entry.ns) \(styled("(\(entry.domain))", .dim))"
                } else {
                    text = "\(styled(entry.iface, .gray)): \(entry.ns)"
                }
                print(
                    Tree.leafText(
                        text, prefix: sectionPrefix, isLast: i == resolverEntries.count - 1))
            }
        }

        // mDNS/Bonjour
        if hasMDNS {
            let sectionIndex = 4
            let isLast = (sectionIndex == lastTrue)
            print(styled("│", .dim))
            print(Tree.section("mDNS/Bonjour", isFirst: false, isLast: isLast))
            let sectionPrefix = Tree.childPrefix("", parentIsLast: isLast)
            print(Tree.leafText("\(localHostname).local", prefix: sectionPrefix, isLast: true))
        }

        // Active Directory
        if hasAD {
            let sectionIndex = 5
            let isLast = (sectionIndex == lastTrue)
            print(styled("│", .dim))
            print(Tree.section("Active Directory", isFirst: false, isLast: isLast))
            let sectionPrefix = Tree.childPrefix("", parentIsLast: isLast)

            if adDomains.isEmpty {
                print(
                    Tree.leafText(
                        styled("(no AD domains found)", .dim), prefix: sectionPrefix, isLast: true))
            } else {
                for (di, ad) in adDomains.enumerated() {
                    let domainLast = (di == adDomains.count - 1)
                    print(Tree.subHeader(ad.domain, prefix: sectionPrefix, isLast: domainLast))
                    let domainPrefix = Tree.childPrefix(sectionPrefix, parentIsLast: domainLast)

                    // Build list of present sub-sections for isLast tracking
                    enum SubSection {
                        case pdc, dc, gc, kdc, ldap, ldaps
                    }
                    var present: [SubSection] = []
                    if !ad.pdcEntries.isEmpty { present.append(.pdc) }
                    if !ad.dcEntries.isEmpty { present.append(.dc) }
                    if !ad.gcEntries.isEmpty { present.append(.gc) }
                    if !ad.kdcEntries.isEmpty { present.append(.kdc) }
                    if ad.ldapCount > 0 { present.append(.ldap) }
                    if ad.ldapsCount > 0 { present.append(.ldaps) }

                    for (idx, sub) in present.enumerated() {
                        let subLast = (idx == present.count - 1)

                        switch sub {
                        case .pdc:
                            print(
                                Tree.subHeader(
                                    styled("PDC", .gray), prefix: domainPrefix, isLast: subLast))
                            let subPrefix = Tree.childPrefix(domainPrefix, parentIsLast: subLast)
                            for (k, pdc) in ad.pdcEntries.enumerated() {
                                let text =
                                    !pdc.ip.isEmpty ? "\(pdc.target) (\(pdc.ip))" : pdc.target
                                print(
                                    Tree.leafText(
                                        text, prefix: subPrefix,
                                        isLast: k == ad.pdcEntries.count - 1))
                            }

                        case .dc:
                            print(
                                Tree.subHeader(
                                    styled("Domain Controllers", .gray), prefix: domainPrefix,
                                    isLast: subLast))
                            let subPrefix = Tree.childPrefix(domainPrefix, parentIsLast: subLast)
                            for (k, dc) in ad.dcEntries.enumerated() {
                                var text = dc.target
                                if !dc.ip.isEmpty { text += " (\(dc.ip))" }
                                if dc.isPDC { text += " \(styled("[PDC]", .green))" }
                                print(
                                    Tree.leafText(
                                        text, prefix: subPrefix,
                                        isLast: k == ad.dcEntries.count - 1))
                            }

                        case .gc:
                            print(
                                Tree.subHeader(
                                    styled("Global Catalog", .gray), prefix: domainPrefix,
                                    isLast: subLast))
                            let subPrefix = Tree.childPrefix(domainPrefix, parentIsLast: subLast)
                            for (k, gc) in ad.gcEntries.enumerated() {
                                let text =
                                    !gc.ip.isEmpty
                                    ? "\(gc.target) (\(gc.ip)) :3268" : "\(gc.target) :3268"
                                print(
                                    Tree.leafText(
                                        text, prefix: subPrefix,
                                        isLast: k == ad.gcEntries.count - 1))
                            }

                        case .kdc:
                            print(
                                Tree.subHeader(
                                    styled("Kerberos KDCs", .gray), prefix: domainPrefix,
                                    isLast: subLast))
                            let subPrefix = Tree.childPrefix(domainPrefix, parentIsLast: subLast)
                            for (k, kdc) in ad.kdcEntries.enumerated() {
                                let text =
                                    !kdc.ip.isEmpty
                                    ? "\(kdc.target) (\(kdc.ip)) :88" : "\(kdc.target) :88"
                                print(
                                    Tree.leafText(
                                        text, prefix: subPrefix,
                                        isLast: k == ad.kdcEntries.count - 1))
                            }

                        case .ldap:
                            print(
                                Tree.leafText(
                                    "\(styled("LDAP Servers:", .gray)) \(ad.ldapCount) (:389)",
                                    prefix: domainPrefix, isLast: subLast))

                        case .ldaps:
                            print(
                                Tree.leafText(
                                    "\(styled("LDAPS Servers:", .gray)) \(ad.ldapsCount) (:636)",
                                    prefix: domainPrefix, isLast: subLast))
                        }
                    }
                }
            }
        }

        print()
    }
}
