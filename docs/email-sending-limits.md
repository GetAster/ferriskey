# Email sending limits

Magic links (including passwordless signup), verification messages (registration,
resend, and automatic verification after password or provider login), and password
reset messages share process-local recipient and realm budgets. The recipient key
is SHA-256 of the trimmed, lowercased address, shared across realms and message
kinds. The address is not stored in the limiter or in limit-denial security events.

- Recipient: at most one reservation per 60 seconds and five in any rolling hour.
- Client address: ten requests per rolling hour across magic-link, registration,
  resend-verification, and forgot-password HTTP endpoints. IPv6 addresses share a
  /64; IPv4-mapped IPv6 shares its IPv4 bucket. Missing addresses share one bucket.
- Realm: 1000 reservations per rolling hour by default. Set
  `EMAIL_REALM_SENDS_PER_HOUR` (integer 1 through 100000) before startup to change
  the cap for each realm. Invalid configuration fails startup before resources open.

A single mutex reserves recipient and realm budgets atomically. IP attempts are
charged separately before recipient lookup, including requests later refused for
other reasons. Recipient and realm budget is charged before token creation;
magic-link signup also reserves before user creation. Verification-mail throttling
is a delivery error during registration, so its existing user rollback runs.
Budgets are not refunded after delivery failures. Each table holds at most 10000
keys and refuses new keys when full until expired entries can be reclaimed.

Magic-link, password-reset and resend responses suppress recipient/realm limit
errors to preserve their ordinary successful response. IP denials answer HTTP429
with `Retry-After` and a JSON `message` plus reason `email_rate_limited`.
Registration also returns that error after rollback on verification-mail denial.
All denials for a valid realm record an `EmailNotSent` security event with reason
`email_rate_limited`, the limited dimension, and only a recipient hash when known.

These are single-instance safeguards: counters reset on restart and are not
coordinated across processes. Keep the trusted-proxy/client-address configuration
correct. The outer proxy rate limit remains useful but does not replace these
recipient and realm budgets.

The existing `KeyedRateLimiter` intentionally admits untracked identities when
full and uses token refill. Those semantics are appropriate to its original
client-authentication use, but do not implement strict email windows. This policy
uses the bounded-window pattern from `RealmBudget`, with rolling windows and a
combined reservation instead of changing those existing policies.
