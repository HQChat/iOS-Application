import Foundation

/// The fuzzing driver: corpus in, mutated inputs out, crashes recorded.
///
/// WHY THIS EXISTS RATHER THAN libFuzzer. Swift's `-sanitize=fuzzer` is refused
/// by Apple's toolchain (`unsupported option '-sanitize=fuzzer' for target
/// 'arm64-apple-macosx'`), and Xcode ships no `libclang_rt.fuzzer_osx.a` to link
/// by hand. So on a stock Mac there is no libFuzzer. This engine is what runs
/// with zero installs; `run.sh --libfuzzer` switches to the real thing once a
/// runtime is available (see README).
///
/// What that costs: this engine is COVERAGE-BLIND. It cannot tell that an input
/// reached a new branch, so it cannot steer. It is a random walk around the
/// seeds, and its reach is bounded by the corpus and the mutator. That bound is
/// the whole lesson — measure it before trusting it.

// MARK: - Deterministic randomness

/// A seeded PRNG, because a finding you cannot replay is barely a finding.
/// `Math.random()`-equivalents are unseedable; splitmix64 is four lines and
/// gives byte-identical runs for a given `--seed`.
struct FuzzRandom {
    private var state: UInt64

    init(seed: UInt64) { self.state = seed &+ 0x9E3779B97F4A7C15 }

    mutating func next() -> UInt64 {
        state = state &+ 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }

    /// Uniform in `0..<upper`. Returns 0 for a non-positive bound so callers
    /// need no empty-collection special case.
    mutating func int(_ upper: Int) -> Int {
        upper <= 0 ? 0 : Int(next() % UInt64(upper))
    }

    mutating func byte() -> UInt8 { UInt8(truncatingIfNeeded: next()) }
    mutating func bool() -> Bool { next() & 1 == 0 }
    mutating func pick<T>(_ xs: [T]) -> T { xs[int(xs.count)] }
}

// MARK: - Engine

struct FuzzEngine {
    let corpusDir: URL
    let findingsDir: URL
    let iterations: Int
    let seed: UInt64

    /// Runs `target` on `iterations` mutated inputs.
    ///
    /// The target is expected to RETURN for every input. If it traps — an
    /// out-of-bounds `Data` subscript, an `Int` overflow, a force-unwrapped nil
    /// — the process dies and this function never returns. That is the finding.
    func run(_ target: (Data) -> Void) {
        var rng = FuzzRandom(seed: seed)
        let seeds = loadCorpus()

        guard !seeds.isEmpty else {
            FileHandle.standardError.write(Data(
                "no seeds in \(corpusDir.path) — run `./run.sh seeds` first\n".utf8))
            exit(2)
        }

        // Unbuffered: a trap is a hard process kill, so anything still sitting in
        // stdout's buffer is lost — which is how a crashing run printed nothing
        // at all and looked like a silent build failure. The input is on disk
        // either way (below), but the operator should not have to know that.
        setvbuf(stdout, nil, _IONBF, 0)
        print("corpus: \(seeds.count) seed(s)  iterations: \(iterations)  seed: \(seed)")

        // THE REPRODUCIBILITY TRICK. A Swift trap is a hard process kill: no
        // catch, no defer, no chance to write anything after the fact. So the
        // input is persisted BEFORE it is run. Whatever is in this file when the
        // process dies is the input that killed it. (libFuzzer does the same
        // thing under `-artifact_prefix`; here it is explicit.)
        let live = findingsDir.appendingPathComponent("current-input.bin")
        try? FileManager.default.createDirectory(at: findingsDir, withIntermediateDirectories: true)

        let started = Date()
        for i in 0..<iterations {
            var input = seeds[rng.int(seeds.count)]
            Mutator.mutate(&input, rng: &rng, corpus: seeds)

            try? input.write(to: live)
            target(input)

            if i > 0 && i % 100_000 == 0 {
                let rate = Double(i) / Date().timeIntervalSince(started)
                print(String(format: "  %d execs  %.0f/s", i, rate))
            }
        }

        try? FileManager.default.removeItem(at: live)
        let elapsed = Date().timeIntervalSince(started)
        print(String(format: "done: %d execs in %.1fs (%.0f/s) — no crash",
                     iterations, elapsed, Double(iterations) / max(elapsed, 0.001)))
    }

    private func loadCorpus() -> [Data] {
        let files = (try? FileManager.default.contentsOfDirectory(
            at: corpusDir, includingPropertiesForKeys: nil)) ?? []
        return files.sorted { $0.path < $1.path }.compactMap { try? Data(contentsOf: $0) }
    }
}

// MARK: - Command line

struct FuzzOptions {
    var iterations = 200_000
    var seed: UInt64 = 1
    var corpus = "corpus"
    var findings = "findings"

    /// `--iterations N  --seed S  --corpus DIR  --findings DIR`
    static func parse(_ args: [String]) -> FuzzOptions {
        var o = FuzzOptions()
        var i = 0
        while i < args.count {
            let flag = args[i]
            let value = i + 1 < args.count ? args[i + 1] : nil
            switch flag {
            case "--iterations": o.iterations = Int(value ?? "") ?? o.iterations; i += 2
            case "--seed":       o.seed = UInt64(value ?? "") ?? o.seed; i += 2
            case "--corpus":     o.corpus = value ?? o.corpus; i += 2
            case "--findings":   o.findings = value ?? o.findings; i += 2
            default: i += 1
            }
        }
        return o
    }
}
