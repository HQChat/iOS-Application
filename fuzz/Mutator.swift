import Foundation

/// ─── YOUR CODE GOES HERE ────────────────────────────────────────────────────
///
/// The mutator is the half of a fuzzer that decides what gets explored. The
/// engine is plumbing; this is the search.
///
/// Right now exactly ONE strategy is implemented (`bitFlip`), so the fuzzer
/// runs end-to-end but barely explores. Adding strategies is the exercise.
/// Measure as you go: run 200k iterations before and after each one and see
/// whether anything changes.
///
/// TUNING NOTE. Mutate too hard and every input is rejected by the first length
/// check, so you only ever test that check. Mutate too gently and you never
/// leave the seed's neighbourhood. Both failure modes look identical from the
/// outside: a fuzzer that runs happily forever and finds nothing.
enum Mutator {

    /// Applies 1–3 random edits to `input`.
    ///
    /// `corpus` is passed in so a mutation can SPLICE — copy a run of bytes out
    /// of a different seed. Splicing is disproportionately effective: it is how
    /// a fuzzer combines "a valid PUBLISH header" with "a SUBACK body" without
    /// having to invent either.
    static func mutate(_ input: inout Data, rng: inout FuzzRandom, corpus: [Data]) {
        let edits = 1 + rng.int(3)
        for _ in 0..<edits {
            switch rng.int(strategyCount) {
            case 0:  bitFlip(&input, rng: &rng)
            case 1:  insertRandomByte(&input, rng: &rng)
            case 2:  truncate(&input, rng: &rng)
            case 3:  extendi(&input, rng: &rng)
            case 4:  spliceFrom(&input, rng: &rng, corpus: corpus)
            case 5:  lengthSmash(&input, rng: &rng)
            default: bitFlip(&input, rng: &rng)
            }
        }
    }

    /// Raise this as you add cases above, or the new strategies are never
    /// selected. (An easy and very quiet way to "add" a mutation that never
    /// runs — check it whenever a new strategy seems to change nothing.)
    private static let strategyCount = 6

    // MARK: - Strategies

    /// Flips one bit. The weakest useful mutation: enough to corrupt a flag or a
    /// length nibble, too small to change the shape of anything.
    private static func bitFlip(_ input: inout Data, rng: inout FuzzRandom) {
        guard !input.isEmpty else { return }
        let index = input.startIndex + rng.int(input.count)
        input[index] ^= 1 << UInt8(rng.int(8))
    }

    private static func insertRandomByte(_ input: inout Data, rng: inout FuzzRandom) {
        let index = input.startIndex + rng.int(input.count)
        input.insert(UInt8(rng.int(256)), at: index)
    }

    private static func truncate(_ input: inout Data, rng: inout FuzzRandom) {
        let index = input.startIndex + rng.int(input.count)
        input.removeSubrange(index..<input.endIndex)

    }

    private static func extendi(_ input: inout Data, rng: inout FuzzRandom) {
        let index = input.startIndex + rng.int(input.count)
        let count = 1 + rng.int(16)
        input.insert(contentsOf: (0..<count).map { _ in UInt8(rng.int(256)) }, at: index)
    }

    /// Copies a run of bytes out of a DIFFERENT corpus entry. The corpus arrives
    /// as a parameter of `mutate` — it is not state on the PRNG.
    private static func spliceFrom(_ input: inout Data, rng: inout FuzzRandom, corpus: [Data]) {
        guard !input.isEmpty, !corpus.isEmpty else { return }
        let other = corpus[rng.int(corpus.count)]
        guard !other.isEmpty else { return }

        let index = input.startIndex + rng.int(input.count)
        let otherIndex = other.startIndex + rng.int(other.count)
        let available = other.endIndex - otherIndex
        let length = 1 + rng.int(min(16, available))
        input.replaceSubrange(index..<input.endIndex,
                              with: other[otherIndex..<(otherIndex + length)])
    }

    private static func lengthSmash(_ input: inout Data, rng: inout FuzzRandom) {
        guard input.count >= 5 else { return }
        let lengthBytes = 1 + rng.int(4)
        let lengthValue: UInt32
        switch rng.int(3) {
        case 0: lengthValue = 0
        case 1: lengthValue = UInt32.max
        default: lengthValue = UInt32(rng.int(1 << (7 * lengthBytes)))
        }
        for i in 0..<lengthBytes {
            let byte = UInt8((lengthValue >> (7 * i)) & 0x7F) | (i < lengthBytes - 1 ? 0x80 : 0x00)
            input[input.startIndex + 1 + i] = byte
        }
    }


}
