# RunReconcile receipt

Verdict: **ACCEPTED**

Project: &#82;&#117;&#110;&#82;&#101;&#99;&#111;&#110;&#99;&#105;&#108;&#101;&#32;&#108;&#111;&#99;&#97;&#108;&#32;&#100;&#101;&#109;&#111; (`local-demo`)
Run ID: `public-example-001`
Contract SHA-256: `1544d427addb1bae216332ab23ac8eb9fe48bf400c3c76192768b3172068e3bf`
Receipt JSON SHA-256: `2203e49e7bdc7f08ae094411b196500575f58128d287ad2110ef68a1ec034f23`

## Checks

| ID | Public label | Type | Status | Code |
|---|---|---|---|---|
| `result-artifact` | &#100;&#101;&#109;&#111;&#32;&#114;&#101;&#115;&#117;&#108;&#116;&#32;&#97;&#114;&#116;&#105;&#102;&#97;&#99;&#116;&#32;&#101;&#120;&#105;&#115;&#116;&#115; | artifact | pass | `satisfied` |
| `result-complete` | &#100;&#101;&#109;&#111;&#32;&#114;&#101;&#115;&#117;&#108;&#116;&#32;&#114;&#101;&#112;&#111;&#114;&#116;&#115;&#32;&#99;&#111;&#109;&#112;&#108;&#101;&#116;&#105;&#111;&#110; | json | pass | `satisfied` |
| `delivery-correlated` | &#109;&#111;&#99;&#107;&#32;&#100;&#101;&#108;&#105;&#118;&#101;&#114;&#121;&#32;&#114;&#101;&#99;&#101;&#105;&#112;&#116;&#32;&#105;&#115;&#32;&#99;&#111;&#114;&#114;&#101;&#108;&#97;&#116;&#101;&#100;&#32;&#116;&#111;&#32;&#116;&#104;&#105;&#115;&#32;&#114;&#117;&#110; | delivery | pass | `satisfied` |

## Final write surface

- Allowed changes: 3
- Unexpected changes: 0

## Coverage limitations

- Point-in-time final-state comparison; transient writes are not observed.
- Changes during the observation window are not attributed to a specific process.
- Only declared watch roots and post-run checks are covered.
- The receipt is integrity-hashed but is not digitally signed.

The JSON receipt is the machine-readable source of truth.
