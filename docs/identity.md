# Rule identity

Implementation: `src/suriharvest/identity.py`. Golden tests: `tests/test_identity.py`.

| key | computed from |
|---|---|
| `content_hash` | SHA-256 of the logical rule line (continuations joined, leading `#` and surrounding space removed) |
| `rule_key` | `namespace:gid:sid`; namespace = best-priority `sid_namespace` among every source that ever published this exact text |
| `logic_hash` | `SHA-256("suriharvest-logic-v1\n" + canonical JSON)` of `{header, options}` |
| `semantic_hash` | `SHA-256("suriharvest-semantic-v1\n" + canonical JSON)` of `{header, globals, buffers}` |
| `alerting_hash` | threshold / detection_filter / noalert |

## logic_hash

- header: protocol lower case; address and port expressions canonical (lists sorted and de-duplicated, `!` kept,
  `$VARS` kept, `any` lower case, single-host CIDRs written as the address); for `<>` the two endpoints are sorted.
- options: every option except metadata (msg sid rev gid classtype priority reference metadata target), alerting
  options and performance options (fast_pattern, prefilter), **in their original order**. Content modifiers
  that follow a content are attached to it and sorted. content values are decoded and re-encoded (printable ASCII
  literal except `" ; \ |`, the rest as `|XX|`), case-folded with nocase. pcre values become `/pattern/flags` with
  sorted flags. `flow` tokens are sorted. Other values: whitespace collapsed, no spaces around commas.

## semantic_hash

On top of the logic form: legacy content modifiers -> sticky buffers, legacy sticky names -> current names,
uricontent -> http.uri content, pcre buffer flags -> buffers, `startswith` -> `depth:<len>`, `offset:0` dropped.
Buffer-relative options (content, pcre, isdataat, byte_*, dataset, transforms ...) are grouped per buffer in
order; groups are sorted; all other options are sorted.

## Changing the rules

Bump `LOGIC_VERSION` / `SEMANTIC_VERSION` when a hash changes, or `FACTS_REVISION` when any other fact computed
at ingest changes. The next `suriharvest index` recomputes stored facts from each version's text.
