# Apple broker

Apple uses the existing OAuth broker and callback path, with form POST support.
Configure the provider with `provider_id: "apple"` and this config:

```json
{
  "client_id": "YOUR_SERVICES_ID",
  "authorization_url": "https://appleid.apple.com/auth/authorize",
  "token_url": "https://appleid.apple.com/auth/token",
  "jwks_url": "https://appleid.apple.com/auth/keys",
  "issuer": "https://appleid.apple.com",
  "scopes": ["name", "email"],
  "use_pkce": false,
  "apple": {
    "team_id": "YOUR_TEAM_ID",
    "key_id": "YOUR_KEY_ID",
    "key_file": "/etc/aster-idp/apple/AuthKey.p8"
  }
}
```

Omit `client_secret` and `userinfo_url`. The server must be able to read the
absolute key path; private key bytes never enter provider configuration or the
database. The existing administrative admission policy controls who can configure
providers. Mount the key with minimum necessary filesystem permissions.

Apple mode pins Apple's public endpoints and signs a five-minute ES256 client
assertion for each token exchange. It requests `response_mode=form_post`; register
the existing `/api/realms/{realm}/broker/{alias}/endpoint` as the Apple return URL.
The callback exchanges the code and verifies the returned ID token normally,
including signature, issuer, audience and an always-present transaction nonce.
Apple uses the random broker state as its upstream nonce; the relying party's
original nonce remains separate and unchanged. It never trusts a form-supplied
ID token or email. Apple string-valued `email_verified` is interpreted only after
signature verification. Private relay addresses follow the same email policy.

The first-consent `user` JSON supplies bounded display names for a new account.
These are untrusted profile text, not identity evidence. Existing linked account
names are not overwritten. Provider `trust_email` remains a separate policy;
Apple mode does not enable automatic account linking or local email verification.
No Apple notification endpoint is added by this patch.

References: [Apple authorization](https://developer.apple.com/documentation/signinwithapplerestapi/request-an-authorization-to-the-sign-in-with-apple-server.)
and [token exchange](https://developer.apple.com/documentation/signinwithapplerestapi/generate-and-validate-tokens).
