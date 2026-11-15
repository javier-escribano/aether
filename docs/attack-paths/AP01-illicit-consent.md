# AP01 — Illicit consent grant → robo de token Graph

- **Capa:** Entra ID
- **Coste:** ~0 (identity-only, Entra Free)
- **MITRE ATT&CK:** [T1528](https://attack.mitre.org/techniques/T1528/) (Steal Application Access Token) · [T1098.003](https://attack.mitre.org/techniques/T1098/003/) (Additional Cloud Roles / app abuse)
- **Mapea a cert:** CARTP / CARTE
- **Precondición sembrada por el range:**
  - App multi-tenant `caelum-ap01-NewsletterSync` que pide scopes delegados peligrosos (`Mail.Read`, `Files.Read.All`, `offline_access`).
  - User-consent policy **permisiva** (cualquier usuario puede consentir cualquier app) — aplicada por `scripts/seed-ap01.ps1`.

---

## 🎯 Objetivo didáctico

Que el alumno entienda por qué **el consentimiento de usuario es una superficie de acceso inicial y de persistencia**, no un detalle de UX: un token delegado obtenido por consentimiento sobrevive a cambios de contraseña y a MFA, y no aparece como "inicio de sesión" clásico.

---

## 🔴 Rompe (cómo se explota)

Flujo clásico de *consent phishing* (nivel entrenamiento; herramientas públicas de referencia: **GraphRunner**, **365-Stealer**, **TokenTactics**):

1. **Despliega el range con AP01 activo** y recupera la URL de consentimiento:
   ```powershell
   ./caelum.ps1 deploy
   cd terraform; terraform output -raw ap01_consent_url
   ```
   La URL apunta al endpoint legítimo `login.microsoftonline.com` del tenant — por eso es creíble.

2. **La víctima consiente.** En el range haces de víctima abriendo esa URL con un `caelum-userN`.
   Como la policy es permisiva, Entra **no exige aprobación de admin** y registra el grant.
   > Atajo para demo sin repetir el consent a mano:
   > `./scripts/seed-ap01.ps1 -AppId <appId> -PreConsent -VictimUpn caelum-user1@<tenant>`

3. **Canje code→token.** El atacante intercambia el `code` del redirect por un *access token* + *refresh token* contra `/oauth2/v2.0/token`. El refresh token es la joya: renueva acceso de forma persistente.

4. **Abuso vía Graph.** Con el token, lee el correo y los ficheros de la víctima:
   ```
   GET https://graph.microsoft.com/v1.0/me/messages
   GET https://graph.microsoft.com/v1.0/me/drive/root/children
   ```
   Objetivo de aprendizaje: observar que **no hay un sign-in interactivo nuevo** por cada acceso — solo refresh de token.

---

## 🟢 Arregla (remediación)

La corrección es de política, no del app. El range la aplica con `./caelum.ps1 reset` (o el script en modo `-Remediate`):

```powershell
# Deshabilita el consentimiento de usuario: solo un admin puede consentir apps.
Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{
    PermissionGrantPoliciesAssigned = @()
}
```

Alternativa recomendada en producción (no bloquear del todo, sino **consentimiento acotado**):
- Portal → *Enterprise applications* → *Consent and permissions* → **"Allow user consent for apps from verified publishers, for selected permissions"**.
- Activar el **admin consent workflow** para que el usuario pueda *solicitar* y un admin apruebe.
- Revisar grants existentes: `Get-MgOauth2PermissionGrant` y revocar los sospechosos.

---

## 🔵 Detecta

El evento delator está en los **Entra ID Audit Logs**: `Consent to application` / `Add delegated permission grant`, filtrando por scopes de alto valor.

- KQL (Sentinel / Defender XDR): [`detections/kql/AP01-illicit-consent.kql`](../../detections/kql/AP01-illicit-consent.kql)
- Sigma: [`detections/sigma/AP01-illicit-consent.yml`](../../detections/sigma/AP01-illicit-consent.yml)

Señales de caza complementarias:
- App **multi-tenant recién creada** que pide `Mail.*` / `Files.*` / `offline_access`.
- Grant con `consentType = Principal` (consentimiento de un único usuario, típico del phishing dirigido).
- Acceso a Graph **sin sign-in interactivo** correlacionado (solo refresh tokens).

---

## 📚 Referencias

- Microsoft — [Investigate risky OAuth apps / illicit consent grant](https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth)
- Microsoft — [Configure how users consent to applications](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent)
- MITRE ATT&CK — T1528, T1098.003
