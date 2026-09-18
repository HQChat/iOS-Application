import Foundation

// Native driver for the ratchet-state target. Mirrors FuzzMain.swift.
let options = FuzzOptions.parse(Array(CommandLine.arguments.dropFirst()))

FuzzEngine(
    corpusDir: URL(fileURLWithPath: options.corpus),
    findingsDir: URL(fileURLWithPath: options.findings),
    iterations: options.iterations,
    seed: options.seed
).run(fuzzRatchetState)
