import Foundation

func shell(_ command: String) -> (output: String, exitCode: Int32) {
    let task = Process()
    let pipe = Pipe()
    task.executableURL = URL(fileURLWithPath: "/bin/zsh")
    task.arguments = ["-c", command]
    task.standardOutput = pipe
    task.standardError = pipe
    task.standardInput = nil

    do {
        try task.run()
        task.waitUntilExit()
    } catch {
        return ("", 1)
    }

    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return (output, task.terminationStatus)
}

func shellLines(_ command: String) -> [String] {
    let (output, _) = shell(command)
    guard !output.isEmpty else { return [] }
    return output.split(separator: "\n").map(String.init)
}
