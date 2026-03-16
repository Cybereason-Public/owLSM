# Rule Examples

Example rules for owLSM. Use these as reference when writing your own rules.

## SigmaHQRules
Real rules from [SigmaHQ](https://github.com/SigmaHQ/sigma/tree/master/rules/linux), adapted to work with owLSM.  
**What changed from the originals:**
- `id` — Changed to an integer (owLSM requires numeric IDs)
- `field names` — Mapped to owLSM field names (e.g. `CommandLine` → `target.process.cmd`)
- `action` and `events` — Added (required by owLSM, not present in standard Sigma)

## CustomExampleRules
Custom rules written specifically for owLSM to showcase its capabilities — different event types, modifiers, field comparisons, and complex conditions.
