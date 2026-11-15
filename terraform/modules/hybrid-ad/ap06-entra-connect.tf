# ==================================================================
# AP06 - Entra Connect / Seamless SSO (AZUREADSSOACC$): puente on-prem->cloud.
#
# 2a ruta HIBRIDA del range y la que CIERRA el catalogo. Substrato COMPARTIDO
# con AP05 (local.need_dc en main.tf): un unico DC/CA sirve a ambas. Los
# artefactos AD de AP06 (la cuenta de maquina AZUREADSSOACC$ con sus SPNs +
# la cuenta de sincronizacion con ACEs DCSync sobre el naming context) NO son
# recursos azurerm (viven en el directorio del DC, como la plantilla ESC1 de
# AP05): los siembra scripts/seed-ap06.ps1 (imperativo, post-apply, via
# az vm run-command). Aqui solo viven los SECRETOS (que aterrizan en el ESTADO
# y se exponen via outputs sensibles); need_dc y los xpath_* viven en
# main.tf/monitoring.tf; los outputs ap06_* en outputs.tf.
#
# LECCION ESTRELLA (distinta de AP05, que acaba en DCSync on-prem): el
# compromiso on-prem SALTA a la nube. Con la credencial de la cuenta de sync
# (DCSync) se extraen las claves Kerberos de AZUREADSSOACC$; se forja un SILVER
# TICKET para HTTP/autologon.microsoftazuread-sso.com suplantando a cualquier
# usuario sincronizado; Entra lo valida -> autenticacion a la NUBE sin password.
# La clave de AZUREADSSOACC$ NUNCA se rota por defecto -> persistencia eterna.
# ==================================================================

# Password FIJA/conocida de AZUREADSSOACC$. Su clave Kerberos RC4 = MD4(UTF16LE(pwd))
# es reproducible, y la cuenta no tiene host que la rote -> "nunca rotada". Lo
# "no-rotado" es estructural (ninguna entidad rota AZUREADSSOACC$), no que la
# clave sea debil: se genera aleatoriamente (nunca hardcode) pero LA CONOCEMOS
# (aterriza en el estado y se expone via output sensible para el forge).
resource "random_password" "ap06_sso" {
  count            = var.enable_ap06 ? 1 : 0
  length           = 24
  min_lower        = 1
  min_upper        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#$%*()-_=+"
}

# Password de la cuenta de sincronizacion (credencial de Entra Connect con
# derechos DCSync): la credencial de arranque del atacante de AP06.
resource "random_password" "ap06_sync" {
  count            = var.enable_ap06 ? 1 : 0
  length           = 24
  min_lower        = 1
  min_upper        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#$%*()-_=+"
}
