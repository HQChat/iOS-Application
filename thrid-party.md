# Third-party licences

`LICENSE` at the root of this repository covers the code this project wrote.
It does not cover the components listed below, which were written by other
people and carry their own terms. Those terms are reproduced or linked here,
and each entry names the exact upstream revision so the claim can be checked
rather than taken.

> **Fill in the `<…>` placeholders before publishing.** An attribution file
> that is approximately right is worse than none: it is a specific claim about
> provenance that a reviewer can falsify in one command.

---

## HQC reference implementation

| | |
|---|---|
| **Where it lives** | `<path/in/tree>` |
| **Upstream** | PQClean — https://github.com/PQClean/PQClean |
| **Revision** | `<full 40-char commit sha>` |
| **Licence** | Public domain (SPDX: `LicenseRef-PublicDomain`) |
| **Modified by this project?** | `<yes — see below / no, vendored verbatim>` |

Provenance chain, newest first:

1. PQClean, `crypto_kem/hqc-*`, at the commit above
2. https://github.com/SWilson4/package-pqclean — `hqc`
3. The authors' submission at https://pqc-hqc.org/implementation.html,
   specification version `<2023-04-30 / other>`

The implementation is released into the public domain by its authors. The
algorithm is the work of the HQC submission team: Carlos Aguilar Melchor,
Nicolas Aragon, Slim Bettaieb, Loïc Bidoux, Olivier Blazy, Jurjen Bos,
Jean-Christophe Deneuville, Arnaud Dion, Philippe Gaborit, Jérôme Lacan,
Edoardo Persichetti, Jean-Marc Robert, Pascal Véron and Gilles Zémor. Public
domain removes the legal obligation to credit them; it does not remove the
reason to.

**Local modifications.** `<List every change, or state "none". If the vendored
source was patched — constant-time fixes, build shims, parameter selection,
API surface — say what and why. A patched crypto primitive that reads as
upstream is the single worst thing this file can hide.>`

---

## `<liboqs — delete this section if unused>`

| | |
|---|---|
| **Where it lives** | `<path/in/tree>` |
| **Upstream** | https://github.com/open-quantum-safe/liboqs |
| **Revision** | `<tag or commit>` |
| **Licence** | MIT |

```
<paste the full MIT text from the upstream LICENSE.txt>
```

---

## Swift and build-time dependencies

One row per package actually linked into a shipped build. Anything that only
runs in CI or tests belongs in the section below it, not here.

| Component | Upstream | Version | Licence |
|---|---|---|---|
| `<package>` | `<url>` | `<version>` | `<SPDX id>` |
| `<package>` | `<url>` | `<version>` | `<SPDX id>` |

### Development and test only — not shipped

| Component | Upstream | Version | Licence |
|---|---|---|---|
| `<package>` | `<url>` | `<version>` | `<SPDX id>` |

---

## Compiled artefacts in this repository

`<libhqc_wrap.dylib>` is a build output, not source. It is `<a convenience for
local development / linked by the shipped app>`, and it is built from
`<path/in/tree>` by `<setup_ios_lib.fish>`.

A binary in a source repository cannot be audited, cannot be diffed, and
inherits none of the guarantees this file makes about the source beside it. If
it is not needed for a from-source build, it should be deleted and
`.gitignore`d; if it is, the build that produces it should be reproducible and
documented here.

---

## Full licence texts

`<Either inline each licence above, or keep them under `third-party/licenses/`
and link them here. Public-domain components need no text, only the
attribution above.>`

---

## Keeping this accurate

- Update this file in the **same commit** that adds, removes or bumps a
  dependency.
- Record commit SHAs, not branch names. A branch is not a provenance claim.
- Re-check upstream licences on every bump — projects relicense.
- When a vendored component is patched, the patch belongs in the tree as a
  patch file, so the diff against upstream stays visible.

Questions or corrections: <support@martinrougeron.me>.
