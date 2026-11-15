# AP01 — Illicit consent grant → Graph token theft

- **Layer:** Entra ID
- **Cost:** ~0 (identity-only, Entra Free)
- **MITRE ATT&CK:** [T1528](https://attack.mitre.org/techniques/T1528/) (Steal Application Access Token) · [T1098.003](https://attack.mitre.org/techniques/T1098/003/) (Additional Cloud Roles / app abuse)
- **Maps to cert:** CARTP / CARTE
- **Precondition seeded by the range:**
  - Multi-tenant app `azrange-ap01-NewsletterSync` requesting dangerous delegated scopes (`Mail.Read`, `Files.Read.All`, `offline_access`).
  - **Permissive** user-consent policy (any user can consent to any app) — applied by `scripts/seed-ap01.ps1`.

---

## 🎯 Learning objective

Help the student understand why **user consent is both an initial-access and a persistence surface**, not a UX detail: a delegated token obtained through consent survives password changes and MFA, and does not show up as a classic "sign-in".

---

## 🔴 Exploit (how it is abused)

Classic *consent phishing* flow (training level; public reference tooling: **GraphRunner**, **365-Stealer**, **TokenTactics**):

1. **Deploy the range with AP01 enabled** and retrieve the consent URL:
   ```powershell
   ./azrange.ps1 deploy
   cd terraform; terraform output -raw ap01_consent_url
   ```
   The URL points to the tenant's legitimate `login.microsoftonline.com` endpoint — which is exactly what makes it credible.

2. **The victim consents.** In the range you play the victim by opening that URL as an `azrange-userN`.
   Because the policy is permissive, Entra **does not require admin approval** and records the grant.
   > Shortcut for a demo without re-doing the consent by hand:
   > `./scripts/seed-ap01.ps1 -AppId <appId> -PreConsent -VictimUpn azrange-user1@<tenant>`

3. **code→token exchange.** The attacker swaps the redirect's `code` for an *access token* + *refresh token* against `/oauth2/v2.0/token`. The refresh token is the prize: it renews access persistently.

4. **Abuse via Graph.** With the token, read the victim's mail and files:
   ```
   GET https://graph.microsoft.com/v1.0/me/messages
   GET https://graph.microsoft.com/v1.0/me/drive/root/children
   ```
   Learning goal: observe that **there is no new interactive sign-in** for each access — only token refresh.

---

## 🟢 Remediate (remediation)

The fix is a policy change, not an app change. The range applies it with `./azrange.ps1 reset` (or the script in `-Remediate` mode):

```powershell
# Disable user consent: only an admin can consent to apps.
Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
    PermissionGrantPoliciesAssigned = @()
}
```

Recommended alternative in production (don't block entirely, but **scope the consent**):
- Portal → *Enterprise applications* → *Consent and permissions* → **"Allow user consent for apps from verified publishers, for selected permissions"**.
- Enable the **admin consent workflow** so a user can *request* and an admin approves.
- Review existing grants: `Get-MgOauth2PermissionGrant` and revoke any suspicious ones.

---

## 🔵 Detect

The tell-tale event is in the **Entra ID Audit Logs**: `Consent to application` / `Add delegated permission grant`, filtered by high-value scopes.

- KQL (Sentinel / Defender XDR): [`detections/kql/AP01-illicit-consent.kql`](../../detections/kql/AP01-illicit-consent.kql)
- Sigma: [`detections/sigma/AP01-illicit-consent.yml`](../../detections/sigma/AP01-illicit-consent.yml)

Complementary hunting signals:
- **Newly created multi-tenant app** requesting `Mail.*` / `Files.*` / `offline_access`.
- Grant with `consentType = Principal` (consent from a single user, typical of targeted phishing).
- Graph access **with no correlated interactive sign-in** (refresh tokens only).

---

## 📚 References

- Microsoft — [Investigate risky OAuth apps / illicit consent grant](https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth)
- Microsoft — [Configure how users consent to applications](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent)
- MITRE ATT&CK — T1528, T1098.003
