import CLICore

enum Tree {
    static let branch = styled("├─ ", .dim)
    static let corner = styled("└─ ", .dim)
    static let pipe   = styled("│  ", .dim)
    static let space  = "   "
    static let top    = styled("┌─ ", .dim)

    static func section(_ title: String, isFirst: Bool, isLast: Bool) -> String {
        let connector = isFirst ? top : (isLast ? corner : branch)
        return connector + styled(title, .bold, .cyan)
    }

    static func leaf(
        _ label: String, _ value: String,
        prefix: String, isLast: Bool, labelWidth: Int = 16
    ) -> String {
        let connector = isLast ? corner : branch
        let paddedLabel = styled(
            label.padding(toLength: labelWidth, withPad: " ", startingAt: 0),
            .gray
        )
        return prefix + connector + paddedLabel + value
    }

    static func leafText(_ text: String, prefix: String, isLast: Bool) -> String {
        let connector = isLast ? corner : branch
        return prefix + connector + text
    }

    static func subHeader(_ text: String, prefix: String, isLast: Bool) -> String {
        let connector = isLast ? corner : branch
        return prefix + connector + styled(text, .bold)
    }

    static func childPrefix(_ parentPrefix: String, parentIsLast: Bool) -> String {
        parentPrefix + (parentIsLast ? space : pipe)
    }
}
