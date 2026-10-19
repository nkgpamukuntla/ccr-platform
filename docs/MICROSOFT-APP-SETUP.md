# Microsoft app registration: setup and roles

The collector reads each county's Microsoft 365 tenant through **one multi-tenant Entra app**
with **read-only application permissions** and **certificate authentication** (R7). The
certificate's private key is a non-exportable KMS key in the hosting account (R3); only the
public certificate is uploaded here. No client secret is ever created.

| | Dev (now) | Production (later) |
|---|---|---|
| Home tenant (holds the registration) | CDX lab tenant `m365b547779.onmicrosoft.com` | D-Biz tenant chosen under decision D7 (Tim) |
| Test target ("Lab County A") | The same CDX tenant | Each county's own tenant |
| Lifetime | Until the CDX tenant expires (~90 days) | Permanent; hardened per handover section 8 |

## Values to enter

| Setting | Value |
|---|---|
| Name | `CCR Evidence Collector (dev)` |
| Supported account types | **Accounts in any organizational directory (Any Microsoft Entra ID tenant – Multitenant)** |
| Redirect URI (platform **Web**) | `https://d2589qqp8c0e2b.cloudfront.net/consent/microsoft/callback` |
| Certificate to upload | `ccr-evidence-collector-dev.cer` (CN=CCR Evidence Collector dev, valid to 19 Oct 2027) |
| Expected thumbprint after upload | `32B6238E6DB574992A89A9216F20E58B2AAEB245` |
| Client secrets | **None.** Do not create one. |

### Microsoft Graph **application** permissions (not delegated)

| Permission | What we read with it | What else it reaches (disclosed on the consent page) |
|---|---|---|
| `Policy.Read.All` | Conditional Access policies; Security Defaults | Every other policy object in the directory, read-only |
| `RoleManagement.Read.Directory` | Role definitions; role assignments | The rest of the role-management configuration, read-only |
| `AuditLog.Read.All` | The authentication-method registration report only | Every sign-in and directory audit record |
| `Device.Read.All` | Devices | Every property of every device object, read-only |
| `LicenseAssignment.Read.All` | Subscribed SKUs | Licence assignments for users and groups |

Each is the least-privileged permission its endpoint's documentation names (handover section 7).

## Steps (Entra admin center, as the home tenant's administrator)

1. **Identity → Applications → App registrations → New registration.** Enter the name, choose
   *Multitenant*, set the redirect URI (platform *Web*) as above, **Register**.
2. On **Overview**, copy the **Application (client) ID** and send it to the platform team. It is not a secret.
3. **Certificates & secrets → Certificates → Upload certificate:** choose the `.cer` file,
   description `KMS signing key (dev)`, **Add**. Check the thumbprint matches the table above.
4. **API permissions → Add a permission → Microsoft Graph → Application permissions:** add the
   five permissions above. Remove the default delegated `User.Read` (not used).
   Do **not** click *Grant admin consent* here; consent is given from the portal, as a county would.
5. **Branding & properties:** set the publisher domain if available. (Publisher verification is a
   production step.)

## Consent as "Lab County A" (portal)

1. Sign in to the portal, open the office, go to **step 4 Connect**.
2. **Sign in and grant consent** → sign in as the CDX **Global Administrator** → review the five
   permissions → **Accept**.
3. The portal records the tenant id; the office's tenant id is added to Terraform so its own raw
   key is created; the worker then collects on schedule (or on demand).

To revoke: in the county's tenant, **Enterprise applications → CCR Evidence Collector (dev) →
Properties → Delete**, or remove the permissions. The portal's record keeps the history.

## Roles needed (for the D-Biz production request)

| Task | Least-privileged Entra role | Notes |
|---|---|---|
| Create the app registration | **Application Developer** (or *Cloud Application Administrator*) | Application Developer only works if creation is allowed; it makes the creator an owner |
| Upload / rotate the certificate | **Owner of the registration** or *Cloud Application Administrator* | Handover section 8: exactly two named people, under PIM, phishing-resistant MFA, no other owners |
| Grant admin consent in a tenant for Microsoft Graph **application** permissions | **Privileged Role Administrator** or *Global Administrator* | Cloud Application Administrator cannot grant Graph app roles; each county's own administrator does this for their tenant |
| Publisher verification | Application Administrator + Microsoft Partner Center (MPN ID) | Shows a verified publisher on every county's consent screen |
| Alert on credential changes | Security Administrator (to configure the alert) | Any change to the registration's certificate list raises an alert |

Production hardening (handover section 8): default app-management policy blocks password
secrets; the registration's credential list is monitored; certificate thumbprints are recorded on
every county's evidence record; a successor certificate is uploaded before the incumbent expires
(the collector refuses to run within 14 days of expiry).

## Certificate renewal

Issue a new certificate (signed in KMS by the worker role):

```
aws ecs run-task --cluster ec-dev-cluster --task-definition ec-dev-worker --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[<worker subnets>],securityGroups=[<worker sg>]}" \
  --overrides '{"containerOverrides":[{"name":"worker","command":["python","-m","app.tools.make_cert","--cn","CCR Evidence Collector dev","--days","365"]}]}'
```

The PEM and thumbprints appear in the task's log (`/ecs/ec-dev/worker`); nothing secret is printed.
Upload the new certificate alongside the old one, update `ms_cert_thumbprint_*` in tfvars, apply,
then remove the old certificate.
