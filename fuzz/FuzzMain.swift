import Foundation

// Native driver entry point. Compiled as `main.swift` by run.sh (Swift requires
// top-level code to live in a file with that name), which is the same trick
// tests/run.sh uses for each test slice.
let options = FuzzOptions.parse(Array(CommandLine.arguments.dropFirst()))

FuzzEngine(
    corpusDir: URL(fileURLWithPath: options.corpus),
    findingsDir: URL(fileURLWithPath: options.findings),
    iterations: options.iterations,
    seed: options.seed
).run(fuzzMQTTWire)
