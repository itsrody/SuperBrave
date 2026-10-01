# Licensing

SuperBrave is a derived work. It contains rules copied verbatim from the upstream
filter lists configured in `config.toml`, plus a small number of repaired forms
where a rule could never match in the engine.

The tooling in this repository is licensed under MPL-2.0, matching the engine it
targets (`adblock`, formerly `adblock-rust`).

## Upstream sources

Redistributing `SuperBrave.txt` redistributes content from every list below. Each
entry records the licence declared in `config.toml`. **These identifiers are
config metadata, not a legal determination.** Verify them against each project's
own licence text before publishing.

| List | Upstream | Licence (as declared) |
| --- | --- | --- |
| EasyList | https://easylist.to/easylist/easylist.txt | GPL-3.0-or-later |
| EasyPrivacy | https://easylist.to/easylist/easyprivacy.txt | GPL-3.0-or-later |
| uBlock filters | https://github.com/uBlockOrigin/uAssets | GPL-3.0-or-later |
| uBlock privacy | https://github.com/uBlockOrigin/uAssets | GPL-3.0-or-later |
| uBlock badware | https://github.com/uBlockOrigin/uAssets | GPL-3.0-or-later |
| uBlock quick-fixes | https://github.com/uBlockOrigin/uAssets | GPL-3.0-or-later |
| AdGuard Base | https://filters.adtidy.org | GPL-3.0-or-later |

## Open questions

These are unresolved and block redistribution:

- The EasyList and uBlock Origin projects are GPL-3.0-or-later. Whether a
  consolidated list of their rules can be distributed under terms compatible with
  GPL section 5, and what attribution and copyleft obligations attach to
  `SuperBrave.txt`, needs a real answer rather than a guess.
- Scriptlet and redirect resources referenced by `$redirect=` and `##+js()` are
  *not* included in this build. The pipeline treats a rule whose behaviour depends
  on an absent resource as unverifiable and does not rely on it.
- The engine's `resource-assembler` feature is compiled in, but no resource bundle
  is loaded, so resource-dependent rules parse but cannot take effect. Confirm
  whether any such rules survive into the output before publishing.

## Provenance

Every build records the SHA-256 of each downloaded list. `dist/report.json`
carries per-source counts and rejection reasons, and the header of
`SuperBrave.txt` records the generator version and the engine features the output
was validated against.