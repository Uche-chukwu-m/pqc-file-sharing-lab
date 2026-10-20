# Attack table

Trials per random attack: 200, seed 1.

| Attack | Version A | Version B v1 | Version B v2 |
|---|---|---|---|
| Edit invoice $100 → $900 | ❌ succeeded 1/1 | ✅ blocked 1/1 (GCM tag) | ✅ blocked 1/1 (bad signature) |
| Random bit flip (anywhere) | ❌ succeeded 166/200 (rest: padding error (luck)) | ✅ blocked 200/200 (GCM tag, length check) | ✅ blocked 200/200 (bad signature, malformed package) |
| Random bit flip in header | — | — | ✅ blocked 40/40 (addressed to someone else, bad signature, malformed package, sender certificate invalid) |
| Random bit flip in KEM ciphertext | — | — | ✅ blocked 40/40 (bad signature) |
| Random bit flip in nonce | — | — | ✅ blocked 40/40 (bad signature) |
| Random bit flip in AES ciphertext + tag | — | — | ✅ blocked 40/40 (bad signature) |
| Random bit flip in signature | — | — | ✅ blocked 40/40 (bad signature) |
| Truncate last block | ✅ blocked 1/1 (padding error (luck)) | ✅ blocked 1/1 (GCM tag) | ✅ blocked 1/1 (malformed package) |
| Cloud forges a new file | ❌ succeeded 1/1 | ❌ succeeded 1/1 | ✅ blocked 1/1 (bad signature) |
| Replay an old file | ❌ succeeded 1/1 | ❌ succeeded 1/1 | ✅ blocked 1/1 (replay) |
| Mallory pretends to be Alice | ❌ succeeded 1/1 | ❌ succeeded 1/1 | ✅ blocked 1/1 (bad signature) |
| Wrong person opens the file | ❌ succeeded 1/1 | ✅ blocked 1/1 (GCM tag) | ✅ blocked 1/1 (addressed to someone else) |
| Cloud swaps recipient's key | n/a | ❌ succeeded 1/1 | ✅ blocked 1/1 (sender refused certificate) |
| Signature swap | n/a | n/a | ✅ blocked 1/1 (decryption failed) |
| Redirect package to Mallory | n/a | n/a | ✅ blocked 1/1 (bad signature) |
