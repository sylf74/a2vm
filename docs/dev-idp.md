# A development identity provider

Since v0.23.15. The chat, the review page of the alerts (where a validator also confirms the
actions asked in the chat) and the page of the remediation requests sign their users in with the
tenant's identity provider (OIDC, `docs/sign-in.md`). A platform for development may get no
client from the company's provider. With `A2VM_DEV_IDP_HOST`, `deploy-k8s` then runs a Keycloak in
the tenant's namespace, with a realm made for A2VM, and the sign-in uses it as it would the
company's.

**Never for production.** Its accounts are local, apart from the company's directory; its sign-in
page says DEVELOPMENT; `deploy-k8s` warns at each deployment. Without `A2VM_DEV_IDP_HOST` nothing is
deployed. With `A2VM_OIDC_ISSUER` set, `A2VM_DEV_IDP_HOST` is ignored: the company's provider wins.

## 1. Variables of the tenant project

| Key | Value | Options |
| --- | --- | --- |
| `A2VM_DEV_IDP_HOST` | Host of the Keycloak, e.g. `idp-dev.apps.example.org` | Visible |
| `A2VM_DEV_IDP_USERS` | The accounts, `e-mail:group` comma-separated, group `readers`, `validators` or `admins`, e.g. `ana@example.org:admins,bob@example.org:validators` | Visible |
| `A2VM_DEV_IDP_STORAGE_CLASS` | Optional: storage class of its volume (1 GiB), else the cluster's default | Visible |
| `A2VM_DEV_IDP_TLS_SECRET` | Optional: an existing certificate (Secret of type TLS) for its host | Visible |
| `A2VM_OIDC_CA` | The CA of the ingress certificates when it is not public (cert-manager with a company CA): the chat and the review page check the provider's certificate | File |

Its ingress is the chat's: controller, class and cert-manager issuer (`A2VM_CHAT_INGRESS_*`,
`A2VM_CHAT_CLUSTER_ISSUER`, else `A2VM_INTAKE_*`). Its host resolves to the ingress controller like
the chat's.

## 2. What deploy-k8s does

1. `deploy/chat/dev_idp_values.py` makes the realm `a2vm-dev`:
   - the client `a2vm-<tenant>`: confidential, standard flow and PKCE (`S256`), redirect URIs of the
     chat (`/oauth/oidc/callback`), of the review page and of the remediation page
     (`/oauth2/callback`), a `groups` claim (group names, not paths) in the ID token, the access token
     and the userinfo;
   - the groups `a2vm-readers`, `a2vm-validators`, `a2vm-admins`; an account `admins` is in
     `a2vm-validators` and `a2vm-admins`;
   - the accounts: e-mail verified, a temporary password to change at the first sign-in (12
     characters at least), registration and password reset off, brute force protection on.
2. The admin's password (`dev-idp-admin-password`), the client's secret (`dev-idp-client-secret`)
   and each account's first password (`dev-idp-password-<n>`, in the order of
   `A2VM_DEV_IDP_USERS`) are made once and kept in the Secret `a2vm-tenant`. None is printed: the
   job prints which key goes with which account.
3. The sign-in is set from it: issuer `https://<host>/realms/a2vm-dev`, client `a2vm-<tenant>`,
   readers, validators and admins the three groups, provider reached through the ingress
   (`A2VM_OIDC_IN_CLUSTER`), button « A2VM DEV ».
4. The chart runs Keycloak (`devIdp.image`, `quay.io/keycloak/keycloak:26.4`), `start
   --import-realm`, an H2 file database on its volume (kept when the release is removed). Only
   `/realms/` and `/resources/` are published; the admin console stays inside the cluster.

## 3. First sign-in of an account

```bash
NS=a2vm-lab
kubectl -n $NS get secret a2vm-tenant -o jsonpath='{.data.dev-idp-password-0}' | base64 -d; echo
```

Give it to its owner by a safe channel; the first sign-in asks for a new password.

## 4. Changes

The realm is imported at the first start only: an existing realm is left as it is. To add or
remove an account, either the admin console:

```bash
NS=a2vm-lab
kubectl -n $NS get secret a2vm-tenant -o jsonpath='{.data.dev-idp-admin-password}' | base64 -d; echo
kubectl -n $NS port-forward $(kubectl -n $NS get pod -l app.kubernetes.io/component=idp-dev -o name) 8080:8080
```

then <http://localhost:8080/admin>, user `admin`; or start again from `A2VM_DEV_IDP_USERS` (the
accounts' passwords are lost):

```bash
NS=a2vm-lab
kubectl -n $NS scale deploy -l app.kubernetes.io/component=idp-dev --replicas=0
kubectl -n $NS delete pvc -l app.kubernetes.io/component=idp-dev
```

then run `deploy-k8s` again.

## 5. Moving to the company's provider

Ask for a client as in `docs/sign-in.md` §1, set `A2VM_OIDC_ISSUER`, `A2VM_OIDC_CLIENT_ID`,
`A2VM_OIDC_CLIENT_SECRET` and the groups, remove `A2VM_DEV_IDP_*`, run `deploy-k8s`. Then remove
the Keycloak's volume (§4). Nothing else changes in A2VM.

## 6. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Chat: « Invalid redirect URI » | The chat's host changed after the first start | §4: the admin console, or start again |
| Chat or review page do not start: certificate verify failed on the issuer | The ingress certificate is signed by a private CA | `A2VM_OIDC_CA` (File) |
| Keycloak pod not ready for minutes | First start: Keycloak builds itself, then imports the realm | Wait; `kubectl logs` shows `Realm 'a2vm-dev' imported` |
| « Account is not fully set up » | The first password was not changed | Sign in through the chat, which asks for a new one |
