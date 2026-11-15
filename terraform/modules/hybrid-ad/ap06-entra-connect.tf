# ==================================================================
# AP06 - Entra Connect / Seamless SSO (AZUREADSSOACC$): on-prem->cloud bridge.
#
# The range's 2nd HYBRID path and the one that CLOSES the catalog. SHARED
# substrate with AP05 (local.need_dc in main.tf): a single DC/CA serves both.
# The AP06 AD artifacts (the AZUREADSSOACC$ machine account with its SPNs +
# the synchronization account with DCSync ACEs over the naming context) are NOT
# azurerm resources (they live in the DC's directory, like the AP05 ESC1
# template): they are seeded by scripts/seed-ap06.ps1 (imperative, post-apply, via
# az vm run-command). Only the SECRETS live here (they land in STATE and are
# exposed via sensitive outputs); need_dc and the xpath_* live in
# main.tf/monitoring.tf; the ap06_* outputs in outputs.tf.
#
# KEY LESSON (different from AP05, which ends in on-prem DCSync): the on-prem
# compromise JUMPS to the cloud. With the sync account credential (DCSync)
# you extract the Kerberos keys of AZUREADSSOACC$; you forge a SILVER
# TICKET for HTTP/autologon.microsoftazuread-sso.com impersonating any
# synchronized user; Entra validates it -> authentication to the CLOUD without a password.
# The key of AZUREADSSOACC$ NEVER rotates by default -> eternal persistence.
# ==================================================================

# FIXED/known password of AZUREADSSOACC$. Its RC4 Kerberos key = MD4(UTF16LE(pwd))
# is reproducible, and the account has no host to rotate it -> "never rotated". The
# "non-rotated" property is structural (no entity rotates AZUREADSSOACC$), not that the
# key is weak: it is generated randomly (never hardcoded) but WE KNOW IT
# (it lands in state and is exposed via a sensitive output for the forge).
resource "random_password" "ap06_sso" {
  count            = var.enable_ap06 ? 1 : 0
  length           = 24
  min_lower        = 1
  min_upper        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#$%*()-_=+"
}

# Password of the synchronization account (Entra Connect credential with
# DCSync rights): the attacker's starting credential for AP06.
resource "random_password" "ap06_sync" {
  count            = var.enable_ap06 ? 1 : 0
  length           = 24
  min_lower        = 1
  min_upper        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#$%*()-_=+"
}
