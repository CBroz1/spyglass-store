# Registering the GitHub OAuth app

The broker identifies users through GitHub's device flow. Each deployment needs
its own OAuth app, so these steps get repeated — by whoever stands up a broker,
not once for the project.

Expect this to take about five minutes.

## Why an app at all

The broker only ever needs to answer one question about a caller: *who are
you?* GitHub's `GET /user` answers that for any token, including one a
developer already has from `gh auth token`. So an app is not strictly required
to make login work.

It is required to make login **safe**. A token from `gh` carries whatever
scopes the CLI asked for — typically `repo`, `workflow`, and `gist` — so
handing one to the broker hands it a credential that can push to the user's
private repositories. An app that requests **no scopes** issues a token that
can read a username and do nothing else. If the broker host is ever
compromised, that difference is the whole blast radius.

## Steps

1. Go to **<https://github.com/settings/developers>** → **OAuth Apps** → **New
   OAuth App**. To own the app organizationally rather than personally, use
   `https://github.com/organizations/<org>/settings/applications` instead.
   Prefer the organization: a personal app disappears with the person.

2. Fill in the form:

    | Field | Value |
    |---|---|
    | Application name | `spyglass-store (<site>)` — name the deployment, since users see this when approving |
    | Homepage URL | `https://github.com/LorenFrankLab/spyglass-store` |
    | Authorization callback URL | `https://github.com/LorenFrankLab/spyglass-store` |
    | Enable Device Flow | **checked** |

3. **Request no scopes.** There is nothing to do here — scopes are requested
   per authorization, and the broker requests none. Just do not add any later.

4. Create the app and copy the **Client ID**. It looks like `Ov23li…`, and it
   is not a secret: it is sent to every client that starts a login.

5. Configure the broker:

    ```bash
    export SPYGLASS_STORE_GITHUB_CLIENT_ID=Ov23li...
    ```

    Or put it in the `.env` file the broker reads from its working directory.

You do **not** need the client secret. Device flow for a public client does not
use one, and the broker never asks for it.

## About that callback URL

The field is required by GitHub's form and unused by this flow. Device flow has
no redirect: the user types a code at `github.com/login/device`, and the client
polls the broker for the result. Nothing is ever sent to the callback URL.

Pointing it at the repository keeps it honest — a real page, owned by the
project, that explains what the app is. Do not point it at the broker; that
would imply a redirect endpoint that does not exist.

If someone later adds browser-based OAuth alongside device flow, *that* would
need a real callback URL. This one would then have to change.

## Checking it works

```bash
curl -X POST https://<broker-host>/api/v1/auth/device
```

A correct setup returns a `user_code` and a `verification_uri`. Two failures
are worth recognizing:

| Response | Cause |
|---|---|
| `No GitHub client id configured` | `SPYGLASS_STORE_GITHUB_CLIENT_ID` is unset or empty |
| `device_flow_disabled` | The **Enable Device Flow** checkbox was missed |

Both are 503s from the broker, named plainly, because they are configuration
mistakes rather than user errors.

## Revoking

Users manage their own grant at
<https://github.com/settings/applications> — revoking there cuts the broker
off without touching their `gh` login or any other tooling. That separation is
a second reason to register an app rather than reuse a CLI token: revoking a
`gh` token breaks all of a user's git tooling at once.

Revoking the app's authorization does not invalidate broker tokens already
issued. Those live in the broker's `ClientToken` table and are revoked there.
