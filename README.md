# zotonic_mod_sso_openidc

OpenID Connect (OIDC) single sign-on for Zotonic. Users authenticate at an external
identity provider, and Zotonic links the provider's subject identifier to a local
user identity. The module integrates with Zotonic's logon, signup, and account
connection flows.

## Installation

Place `zotonic_mod_sso_openidc` in Zotonic's `apps_user/` directory or add it as a
project dependency, build Zotonic, and enable `mod_sso_openidc` on the site.

The module depends on `mod_authentication` and uses Zotonic's OAuth2 service
controllers for authorization and callback handling. Its `rebar.config` declares
the `oidcc` dependency with version constraint `~> 3.2.0`; use that declaration
rather than installing an arbitrary latest version separately.

## Configure a provider

Open **Auth → OpenID Connect Providers** in the admin. Provider administration
requires administrator access or `use.mod_sso_openidc`. Visitors do not need that
configuration permission to log in.

1. Add a unique provider name and discovery domain, without the `https://` prefix.
   The module fetches `https://<domain>/.well-known/openid-configuration` and stores
   the discovered issuer.
2. Register the Zotonic site as a client at the identity provider. Use the absolute
   callback URL returned by `mod_sso_openidc:return_url(Context)` as the redirect
   URI. This resolves the `oauth2_service_redirect` dispatch rule without a
   language prefix.
3. Enter the client ID, client secret, and display description. Optionally set a
   logo URL.
4. Enable the provider and allow authentication. Select a display priority other
   than `99` to show it among the standard extra logon buttons. Newly created
   providers are disabled and start at priority `99`.
5. Configure scopes, email policy, and any domain or organization restrictions.

Provider records are stored in the `sso_openidc_provider` table. These are not
ordinary module configuration keys. The admin form does not allow the provider
name, discovery domain, or issuer to be changed after creation. Provider names
form part of stored identity keys.

### Scopes and user information

The module always requests `openid`. An empty scope configuration falls back to
`openid email`; newly created provider records initially request
`openid email email_verified profile`. The authorization helper also requests
`email_verified` when advertised by the provider and `email` is requested.

Enable additional user information to retrieve UserInfo and supplement ID-token
claims. Elevated ACR values select requested authentication context classes;
unsupported configured values cause authorization to fail with `acr_unsupported`.

### Email and signup policy

- **Require email** rejects authentication without an email address.
- **Trust that all email addresses are verified** treats returned email addresses
  as verified. Otherwise the module uses the returned `email_verified` value,
  defaulting to false when absent. A `verified_primary_email` claim is treated
  as verified.
- **Add a username/password on signup** requests a local username/password
  identity for new signups. It does not request one when connecting SSO to an
  existing account.
- **Signup category** selects the new resource category, defaulting to `person`.

SSO does not, by itself, make an email identity verified. New accounts follow the
site's existing signup handling.

### Domains and organizations

These fields serve different purposes:

- **Domains** assigns primary email domains to a provider. The two-step logon
  uses these assignments to direct users to that provider. Authentication
  postchecks reject other services for controlled users with `user_external`.
  Conflicting provider assignments also prevent acceptance.
- **Organizations** restricts the organizations accepted from this provider. The
  module checks the `schac_home_organization` claim from the ID token or UserInfo.
  When the claim is absent, it uses the email domain only if the provider's
  trust-verified-email setting is enabled and the email is verified. An empty
  organization list imposes no organization restriction.

Multiple values can be separated by commas, semicolons, spaces, or newlines.

## Authentication flow

Browser logon uses Authorization Code Flow. Client Credentials is not enabled as
an alternative browser logon flow in the admin form.

1. The `oauth2_oidc_authorize` dispatch rule invokes
   `controller_oauth2_service_authorize` with `z_oidc_oauth_service`.
2. The service helper ensures the provider worker is running and asks `oidcc` to
   construct the authorization URL with the callback, state, scopes, and any ACR
   values.
3. The user authenticates at the provider and returns through Zotonic's shared
   OAuth2 callback with an authorization code.
4. The service helper exchanges the code through `oidcc`, reads the validated
   ID-token claims, and optionally fetches UserInfo.
5. After checking email and organization requirements,
   `z_oidc_oauth_service:auth_validated/3` returns an `auth_validated` record to
   Zotonic's authentication/signup integration.

The module supervises provider workers and reloads their configuration after
provider edits. It observes `admin_menu`, `auth_identity_types`, `logon_options`,
and `auth_postcheck`.

## Identities and claims

SSO identities use type `mod_sso_openidc` and key `provider:subject`, where
`provider` is the configured provider name and `subject` is the `sub` claim.

| Claim | Zotonic value |
| --- | --- |
| `sub` | Provider-prefixed `service_uid` |
| `email` or `verified_primary_email` | Resource email and email identity |
| `given_name` | `props.name_first` |
| `family_name` | `props.name_surname` |
| `name` | `props.title` |

The returned `auth_validated` record has `service = mod_sso_openidc`, resource
properties in `props`, and email identities in `identities`. Its `service_props`
is an empty list, not a copy of the token claims. `ensure_username_pw` follows
the signup option, and `is_connect` distinguishes account connection from logon.

## Templates and model API

Use the public provider list to render authentication links:

```django
{% for provider in m.sso_openidc.providers.list.auth %}
    <a href="{% url oauth2_oidc_authorize provider=provider.name %}">
        {{ provider.description|escape }}
    </a>
{% endfor %}
```

The public `providers.list.auth`, `providers.list.import`, and `providers.list.all`
paths return enabled provider display/routing fields without client credentials.
The standard logon template additionally omits priority `99`; custom templates
can make their own display choices.

Full records from `providers.list` and `providers.byid[id]`, and discovery reads
under `provider[name]`, require provider-administration permission. Full records
include client credentials and must not be exposed in public output.
`m.sso_openidc.is_user_external` indicates whether the current user's primary
email domain is controlled by an enabled authentication provider.

Direct Erlang storage functions in `m_sso_openidc` do not enforce these model-path
ACL checks. Administrative callers must check `m_sso_openidc:is_authorized/1`.
See the module and model `-moduledoc` documentation for the full interface.

## Troubleshooting

- **Provider cannot be added:** check its discovery domain and HTTPS discovery
  response. A duplicate name returns `duplicate_name`; failed discovery returns
  `oidc_config`.
- **No logon button:** check that the provider is enabled for authentication and
  its display priority is not `99`.
- **Callback rejected:** compare the registered redirect URI with
  `mod_sso_openidc:return_url(Context)` for the site.
- **`email_required`:** the configured policy requires an email, but none was
  available in the claims or UserInfo.
- **`organization`:** the organization restriction did not match.
- **`user_external`:** check domain assignments and which provider authenticated
  the user, including conflicting assignments.
- **`acr_unsupported`:** check the selected ACR values against provider discovery.
