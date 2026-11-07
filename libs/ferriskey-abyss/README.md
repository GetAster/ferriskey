# FerrisKey Abyss

## Overview

`ferriskey-abyss` is the **Identity Provider Federation** engine for the FerrisKey ecosystem. It bridges the gap between FerrisKey and external identity providers (IdPs), allowing users to bring their existing identities from systems like Google, GitHub, Discord, or enterprise SAML/OIDC providers.

## Domain & Responsibilities

This library operates within the **Identity Federation** bounded context. Its primary responsibilities include:

- **OpenID Connect Federation**: Acting as a relying party to authenticate users via upstream OIDC providers.
- **SAML 2.0 Bridge**: Integrating with legacy enterprise identity systems (upcoming).
- **Social Login (OAuth 2.0)**: Handling authentication flows with popular social networks.
- **Identity Mapping & Transform**: Normalizing claims from various external providers into FerrisKey's internal identity model.

## Core Components

- **IdentityProvider**: The core entity representing an upstream IdP configuration.
- **Federation Flow**: Handles the redirects, callbacks, and token exchanges required by OIDC/OAuth2 protocols.
- **Claim Mappers**: Translates external assertions into FerrisKey user attributes.

## Technical Details

The library implements a robust state machine for authentication flows (`identity_provider.rs`). It securely handles OAuth2 states and nonces to prevent CSRF and replay attacks, bridging ephemeral credentials from external providers into persistent FerrisKey identities.

## Dependencies

- `ferriskey-domain`: Core domain types and traits.
- `maskass`: Utility for masking sensitive data during logging.

## Microsoft multi-tenant OpenID Connect

The broker supports Microsoft's public-cloud tenant-independent issuer when
`issuer` is exactly `https://login.microsoftonline.com/{tenantid}/v2.0`.
Use `/common/oauth2/v2.0/authorize` and `/common/oauth2/v2.0/token` on
`https://login.microsoftonline.com`, JWKS URL
`https://login.microsoftonline.com/common/discovery/v2.0/keys`, and the
`openid email profile` scopes. Existing provider fields suffice; no new endpoint,
configuration key or database migration is needed.

A signed ID token is required in this mode: the broker validates its audience,
expiry, nonce and signature, requires a lowercase hyphenated GUID `tid`, and
checks the token's issuer against the configured template with that tenant.
It also checks the selected signing key's `issuer`: a matching Microsoft template
or the exact tenant issuer is required. A different tenant's key, missing key
issuer, or a userinfo-only response is rejected. This follows Microsoft's
[tenant-independent validation requirements](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens).
Fixed-issuer providers retain their existing behavior.

External account links use the provider ID plus
`<canonical tid>:<base64url-without-padding UTF-8 sub>` in this mode. This prevents
two tenants with the same subject from sharing a link. Configure a new provider
for this mode; changing an existing fixed-issuer provider changes its link-key
format and does not migrate old links automatically.

Email is not an identity key. Automatic email linking still requires all three:
`trust_email`, a verified upstream email claim, and a verified local email.
Microsoft's `xms_edov` is not interpreted as email verification.
