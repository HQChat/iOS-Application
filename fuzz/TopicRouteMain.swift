import Foundation

// Native driver entry point for the topic-route target. Mirrors FuzzMain.swift;
// separate because run.sh compiles exactly one main.swift per binary and the
// engine takes one target function.
let options = FuzzOptions.parse(Array(CommandLine.arguments.dropFirst()))

FuzzEngine(
    corpusDir: URL(fileURLWithPath: options.corpus),
    findingsDir: URL(fileURLWithPath: options.findings),
    iterations: options.iterations,
    seed: options.seed
).run(fuzzTopicRoute)
