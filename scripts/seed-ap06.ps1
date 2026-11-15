<#
.SYNOPSIS
    Completa (o remedia) la condicion vulnerable de AP06 - Entra Connect / Seamless SSO.

.DESCRIPTION
    AP06 es la 2a ruta HIBRIDA del catalogo y la que lo CIERRA: el puente
    on-prem -> cloud. Reusa el MISMO DC hibrido que AP05 (substrato compartido
    via local.need_dc en Terraform). La DSC base ya levanto el bosque; esta pieza
    siembra (seed) o neutraliza (-Remediate) los dos artefactos de directorio que
    habilitan la cadena, que NO son recursos azurerm (como la plantilla ESC1 de
    AP05, viven en el directorio y se crean imperativamente):

      1) AZUREADSSOACC$  -> la cuenta de MAQUINA de Seamless SSO. Su clave
         Kerberos se COMPARTE con Entra ID. Un cliente pide un TGS para el SPN
         HTTP/autologon.microsoftazuread-sso.com cifrado con la clave de
         AZUREADSSOACC$, y Entra lo valida. DEBILIDAD ESTRELLA: la password de
         AZUREADSSOACC$ NUNCA se rota por defecto (al contrario que las cuentas
         de maquina normales, que rotan cada 30 dias) -> su hash, robado una vez,
         vale para SIEMPRE = persistencia eterna. La clave RC4/NT es
         determinista: MD4(UTF16LE(password)); con una password FIJA/conocida la
         clave es reproducible y se puede forjar un SILVER TICKET (T1558.001).

      2) Cuenta de SINCRONIZACION (analoga a MSOL_/Sync_ de Entra Connect) con
         derechos DCSync sobre el defaultNamingContext. Representa \"has
         comprometido el servidor Entra Connect y volcado la cred de sync\"
         (T1552). Con DCSync (T1003.006) el atacante extrae las claves Kerberos
         de AZUREADSSOACC$ y, con ellas, forja el silver ticket que autentica a
         la NUBE como cualquier usuario sincronizado SIN su password (T1550).

    CADENA rompe (lo que diferencia AP06 de AP05, que acaba en DCSync on-prem):
      cred de sync (T1552) -> DCSync (T1003.006) -> claves de AZUREADSSOACC$
      -> SILVER TICKET para HTTP/autologon.microsoftazuread-sso.com (T1558.001)
      -> autenticacion a la NUBE como usuario privilegiado (T1550).

    Modo por defecto (seed): crea AZUREADSSOACC$ + cuenta de sync con DCSync
                             segun -SsoMode (idempotente).
    -Remediate             : rota la clave de AZUREADSSOACC$ DOS veces (fix MS),
                             quita los ACEs DCSync y deshabilita la cuenta de sync.

    -SsoMode:
      silver_ticket -> SOLO AZUREADSSOACC$ (+ SPNs, clave fija/no-rotada).
      sync_dcsync   -> SOLO la cuenta de sync con ACEs DCSync sobre el NC.
      both          -> ambos (cadena completa; default, honra T1552+T1558).

    CONTEXTO: `az vm run-command` corre como SYSTEM (cuenta de maquina del DC),
    que NO es Enterprise Admin y NO puede crear la cuenta de maquina de SSO ni
    escribir el nTSecurityDescriptor del naming context. Este script construye un
    PSCredential EA (DOMINIO\Administrator) desde -EaPassword y usa -Credential en
    TODAS las llamadas AD. FALLA RUIDOSAMENTE si no tiene derechos EA.

    Simetria exacta con seed-ap05.ps1 (SYSTEM->EA, preflight ruidoso, idempotente,
    -Remediate reset-safe). Toca SOLO estos objetos: NUNCA la CA ni la plantilla
    ESC1 de AP05 (comparten DC pero no artefactos).

.NOTES
    Requiere el modulo ActiveDirectory (RSAT-AD-PowerShell, lo instala la DSC).
    La habilitacion de auditoria de los EventID 4662/4769/4741/4742 la hace ESTE
    seed (gated enable_ap06 desde fuera), NO la DSC compartida -> AP05 intacto.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$DomainFqdn,
    [Parameter(Mandatory = $true)] [string]$DomainNetbios,
    [string]$EaUser = 'Administrator',
    [Parameter(Mandatory = $true)] [string]$EaPassword,
    [ValidateSet('silver_ticket', 'sync_dcsync', 'both')]
    [string]$SsoMode = 'both',
    [string]$SsoAccountName  = 'AZUREADSSOACC',
    [string]$SyncAccountName = 'Sync_CAELUM',
    # Passwords conocidas (aterrizan en el estado de Terraform y se pasan aqui).
    # Obligatorias en modo seed; NO en -Remediate (que genera passwords frescas).
    [string]$SsoPassword,
    [string]$SyncPassword,
    [string[]]$SsoSpns = @('HTTP/autologon.microsoftazuread-sso.com', 'HTTP/aadg.windows.net.nsatc.net'),
    [bool]$Remediate = $false
)

$ErrorActionPreference = 'Stop'

# GUIDs de los extended rights de REPLICACION de directorio. Los DOS juntos = la
# primitiva DCSync completa; uno solo NO basta para un DCSync funcional.
#   DS-Replication-Get-Changes      -> leer cambios de replicacion.
#   DS-Replication-Get-Changes-All  -> incluye los SECRETOS (hashes/claves Kerberos).
$REPL_GET_CHANGES     = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
$REPL_GET_CHANGES_ALL = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

Import-Module ActiveDirectory -ErrorAction Stop

# --- Generador de passwords SIN dependencias ($System.Web no se autocarga) ----
# Windows PowerShell 5.1 (donde corre `az vm run-command`) NO autocarga el
# ensamblado System.Web, asi que [System.Web.Security.Membership]::GeneratePassword
# lanza 'Unable to find type' y, con ErrorActionPreference=Stop, ABORTARIA el
# -Remediate antes de quitar los ACEs DCSync y deshabilitar la cuenta de sync.
# Este helper no depende de ningun ensamblado externo y garantiza complejidad AD
# (>=2 de cada categoria, barajadas). La password es de un solo uso: solo sirve
# para INVALIDAR la clave de AZUREADSSOACC$; nunca necesitamos conocerla.
function New-ComplexPassword {
    param([int]$Length = 32)
    $upper   = 65..90
    $lower   = 97..122
    $digit   = 48..57
    $special = 33, 35, 36, 37, 42, 40, 41, 45, 95, 61, 43
    $all     = $upper + $lower + $digit + $special
    $chars   = @()
    $chars  += $upper   | Get-Random -Count 2 | ForEach-Object { [char]$_ }
    $chars  += $lower   | Get-Random -Count 2 | ForEach-Object { [char]$_ }
    $chars  += $digit   | Get-Random -Count 2 | ForEach-Object { [char]$_ }
    $chars  += $special | Get-Random -Count 2 | ForEach-Object { [char]$_ }
    $remaining = [Math]::Max(0, $Length - $chars.Count)
    if ($remaining -gt 0) {
        $chars += 1..$remaining | ForEach-Object { [char]($all | Get-Random) }
    }
    # Baraja para no dejar las categorias en posiciones fijas.
    -join ($chars | Get-Random -Count $chars.Count)
}

# --- Credencial EA cualificada (run-command = SYSTEM, no EA) ----------------
# IMPRESCINDIBLE desde -EaPassword (= dc_admin_password / ap06_dc_admin_password),
# NO desde SsoPassword: el contexto SYSTEM del run-command no puede crear la cuenta
# de maquina de SSO ni escribir el descriptor de seguridad del naming context.
$sec = ConvertTo-SecureString $EaPassword -AsPlainText -Force
$EA  = New-Object System.Management.Automation.PSCredential(\"$DomainNetbios\$EaUser\", $sec)

$defaultNC = (Get-ADRootDSE -Server $DomainFqdn -Credential $EA).defaultNamingContext
$ssoSam    = \"$SsoAccountName`$\"   # sAMAccountName de una cuenta de maquina lleva '$'

# --- Preflight: exige derechos EA; falla ruidosamente si SYSTEM/no-EA --------
try {
    Get-ADObject -Identity $defaultNC -Server $DomainFqdn -Credential $EA -ErrorAction Stop | Out-Null
} catch {
    throw \"[AP06] No puedo leer el naming context '$defaultNC' como '$DomainNetbios\$EaUser'. \" +
          \"az vm run-command corre como SYSTEM (no EA): pasa EaPassword = password del Administrator \" +
          \"de DOMINIO (dc_admin_password / ap06_dc_admin_password). Detalle: $($_.Exception.Message)\"
}

# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------
function Get-SsoComputer {
    Get-ADComputer -Filter \"sAMAccountName -eq '$ssoSam'\" -Server $DomainFqdn -Credential $EA `
        -Properties servicePrincipalName, PasswordLastSet -ErrorAction SilentlyContinue
}

function Get-SyncUser {
    Get-ADUser -Filter \"sAMAccountName -eq '$SyncAccountName'\" -Server $DomainFqdn -Credential $EA `
        -Properties SID -ErrorAction SilentlyContinue
}

# ===========================================================================
# -Remediate: corta la cadena on-prem->cloud. Cualquiera de los tres cortes
# basta (defensa en profundidad); aplicamos los tres, reset-safe/idempotente.
# ===========================================================================
if ($Remediate) {
    Write-Host \"[*] Remediando AP06 (Entra Connect / Seamless SSO) ...\" -ForegroundColor Green
    $didSomething = $false

    # (A) Rotar la clave Kerberos de AZUREADSSOACC$ DOS veces. El fix oficial de
    # Microsoft es rolar la decryption key de Seamless SSO DOS veces: invalida el
    # hash ya robado Y los silver tickets ya forjados con la clave anterior. Una
    # sola rotacion deja una ventana con la clave previa aun aceptada.
    $sso = Get-SsoComputer
    if ($sso) {
        foreach ($i in 1, 2) {
            $fresh = New-ComplexPassword -Length 32
            Set-ADAccountPassword -Identity $sso.DistinguishedName -Reset `
                -NewPassword (ConvertTo-SecureString $fresh -AsPlainText -Force) `
                -Server $DomainFqdn -Credential $EA
            Write-Host \"[+] Clave de $ssoSam rotada (pase $i/2).\" -ForegroundColor Green
        }
        $didSomething = $true
    } else {
        Write-Host \"[i] $ssoSam no existe: sin clave de Seamless SSO que rotar.\" -ForegroundColor DarkGray
    }

    # (B) Quitar los ACEs DCSync de la cuenta de sync sobre el naming context.
    $sync = Get-SyncUser
    if ($sync) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sync.SID)
        $obj = Get-ADObject -Identity $defaultNC -Server $DomainFqdn -Credential $EA -Properties nTSecurityDescriptor
        $sd  = $obj.nTSecurityDescriptor
        $removed = $false
        foreach ($guid in @($REPL_GET_CHANGES, $REPL_GET_CHANGES_ALL)) {
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [System.Security.AccessControl.AccessControlType]::Allow, $guid)
            if ($sd.RemoveAccessRule($ace)) { $removed = $true }
        }
        if ($removed) {
            # Mismo gotcha binario que seed-ap05: Set-ADObject espera el descriptor
            # en su forma NATIVA (octet-string). Pasar el objeto ActiveDirectorySecurity
            # no serializa fiable y, con ErrorActionPreference=Stop, abortaria.
            Set-ADObject -Identity $defaultNC -Server $DomainFqdn -Credential $EA `
                -Replace @{ nTSecurityDescriptor = $sd.GetSecurityDescriptorBinaryForm() }
            Write-Host \"[+] ACEs DCSync (Get-Changes + Get-Changes-All) retirados de $SyncAccountName.\" -ForegroundColor Green
        } else {
            Write-Host \"[i] $SyncAccountName no tenia ACEs DCSync que retirar (idempotente).\" -ForegroundColor DarkGray
        }

        # (C) Deshabilitar la cuenta de sync (securizar/decomisionar la cred de
        # Entra Connect comprometida). Se deshabilita, no se borra, para dejar
        # rastro forense; cambia a Remove-ADUser si quieres purga total.
        Disable-ADAccount -Identity $sync.DistinguishedName -Server $DomainFqdn -Credential $EA
        Write-Host \"[+] Cuenta de sync $SyncAccountName deshabilitada.\" -ForegroundColor Green
        $didSomething = $true
    } else {
        Write-Host \"[i] $SyncAccountName no existe: sin cred de sync que neutralizar.\" -ForegroundColor DarkGray
    }

    if ($didSomething) {
        Write-Host \"[+] AP06 remediado: clave de Seamless SSO rotada 2x + DCSync fuera + sync deshabilitada.\" -ForegroundColor Green
        Write-Host \"[i] La cuenta de maquina AZUREADSSOACC$ se conserva (deshabilitarla rompe el SSO real); lo que mata la persistencia es la DOBLE rotacion de su clave.\" -ForegroundColor Cyan
    } else {
        Write-Host \"[i] Nada que remediar: ni AZUREADSSOACC$ ni $SyncAccountName presentes.\" -ForegroundColor DarkGray
    }
    return
}

# ===========================================================================
# seed (por defecto): siembra los artefactos AP06 segun -SsoMode. Idempotente.
# ===========================================================================

# Habilitacion de auditoria (GATED AQUI, no en la DSC compartida -> AP05 intacto).
# Las detecciones KQL/Sigma de AP06 dependen de estos EventID; sin la subcategoria
# activa (y, para 4662, una SACL sobre el NC) las firmas disparan en el vacio.
# auditpol es idempotente (fijar un valor ya fijado es no-op).
Write-Host \"[*] Habilitando auditoria para las detecciones de AP06 ...\" -ForegroundColor Yellow
auditpol /set /subcategory:\"Directory Service Access\"          /success:enable /failure:enable | Out-Null  # 4662 (DCSync)
auditpol /set /subcategory:\"Kerberos Service Ticket Operations\" /success:enable                 | Out-Null  # 4769 (TGS del SPN SSO)
auditpol /set /subcategory:\"Computer Account Management\"        /success:enable                 | Out-Null  # 4741/4742 (AZUREADSSOACC$)
Write-Host \"[+] Auditoria 4662/4769/4741/4742 habilitada.\" -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# (1) AZUREADSSOACC$ : cuenta de MAQUINA de Seamless SSO (modos silver_ticket|both).
# ---------------------------------------------------------------------------
if ($SsoMode -eq 'silver_ticket' -or $SsoMode -eq 'both') {
    $sso = Get-SsoComputer
    if ($sso) {
        Write-Host \"[i] $ssoSam ya existe: seed idempotente, no recreo.\" -ForegroundColor DarkGray
        # Garantizar los SPNs aunque la cuenta ya existiera (idempotente).
        foreach ($spn in $SsoSpns) {
            if ($sso.servicePrincipalName -notcontains $spn) {
                Set-ADComputer -Identity $sso.DistinguishedName -ServicePrincipalNames @{ Add = $spn } `
                    -Server $DomainFqdn -Credential $EA
                Write-Host \"[+] SPN anadido a $ssoSam : $spn\" -ForegroundColor Yellow
            }
        }
    } else {
        if (-not $SsoPassword) {
            throw \"[AP06] Modo '$SsoMode' requiere -SsoPassword (la password FIJA/conocida de $ssoSam). \" +
                  \"Debe venir del output sensible ap06_sso_password.\"
        }
        Write-Host \"[*] Sembrando la cuenta de Seamless SSO $ssoSam ...\" -ForegroundColor Yellow

        # La password es conocida/fija -> su clave Kerberos RC4/NT es determinista
        # (MD4(UTF16LE(pwd))) y por tanto reproducible para forjar el silver ticket.
        # Lo \"no-rotado\" es ESTRUCTURAL: ninguna entidad rota AZUREADSSOACC$, asi que
        # su PasswordLastSet se queda fijo/antiguo = la firma de la no-rotacion.
        # Es un objeto COMPUTER (sAMAccountName AZUREADSSOACC$), NO un usuario.
        $ssoSec = ConvertTo-SecureString $SsoPassword -AsPlainText -Force
        New-ADComputer -Name $SsoAccountName -SAMAccountName $ssoSam `
            -ServicePrincipalNames $SsoSpns `
            -AccountPassword $ssoSec -PasswordNeverExpires:$true -Enabled $true `
            -Description 'Seamless SSO computer account (Caelum Range AP06; clave NO rotada por diseno)' `
            -Server $DomainFqdn -Credential $EA

        $spnList = $SsoSpns -join ', '
        Write-Host \"[+] $ssoSam creada con SPNs: $spnList (clave fija/no-rotada -> silver ticket forjable).\" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# (2) Cuenta de SINCRONIZACION con DCSync (modos sync_dcsync|both).
# ---------------------------------------------------------------------------
if ($SsoMode -eq 'sync_dcsync' -or $SsoMode -eq 'both') {
    $sync = Get-SyncUser
    if ($sync) {
        Write-Host \"[i] $SyncAccountName ya existe: seed idempotente, no recreo.\" -ForegroundColor DarkGray
    } else {
        if (-not $SyncPassword) {
            throw \"[AP06] Modo '$SsoMode' requiere -SyncPassword (la password de la cuenta de sync). \" +
                  \"Debe venir del output sensible ap06_sync_password.\"
        }
        Write-Host \"[*] Sembrando la cuenta de sincronizacion $SyncAccountName ...\" -ForegroundColor Yellow
        $syncSec = ConvertTo-SecureString $SyncPassword -AsPlainText -Force
        New-ADUser -Name $SyncAccountName -SamAccountName $SyncAccountName `
            -AccountPassword $syncSec -Enabled $true -PasswordNeverExpires $true `
            -Description 'Entra Connect sync account (Caelum Range AP06; DCSync on-prem)' `
            -Server $DomainFqdn -Credential $EA
        Write-Host \"[+] $SyncAccountName creada.\" -ForegroundColor Yellow
        $sync = Get-SyncUser
    }

    # Conceder DCSync = ACEs DS-Replication-Get-Changes (+ -All) sobre el NC RAIZ
    # (defaultNamingContext, NO el config NC: el config NC seria otra cosa). Los
    # DOS extended rights son necesarios para un DCSync funcional (el segundo trae
    # los secretos). Guardas if-contains => idempotente.
    $sid = New-Object System.Security.Principal.SecurityIdentifier($sync.SID)
    $obj = Get-ADObject -Identity $defaultNC -Server $DomainFqdn -Credential $EA -Properties nTSecurityDescriptor
    $sd  = $obj.nTSecurityDescriptor
    # Las ACEs leidas de nTSecurityDescriptor exponen IdentityReference como
    # SecurityIdentifier, no como NTAccount: normalizamos AMBOS lados a SID para
    # que el re-run detecte las ACEs ya presentes (idempotencia real = no-op).
    $existing = $sd.Access | Where-Object {
        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
        ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and
        ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $sid)
    }
    $added = $false
    foreach ($guid in @($REPL_GET_CHANGES, $REPL_GET_CHANGES_ALL)) {
        $already = $existing | Where-Object { $_.ObjectType -eq $guid }
        if (-not $already) {
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                [System.Security.AccessControl.AccessControlType]::Allow, $guid)
            $sd.AddAccessRule($ace)
            $added = $true
        }
    }
    if ($added) {
        # Mismo gotcha binario que seed-ap05: escribir el descriptor en su forma
        # NATIVA (octet-string), no el objeto ActiveDirectorySecurity.
        Set-ADObject -Identity $defaultNC -Server $DomainFqdn -Credential $EA `
            -Replace @{ nTSecurityDescriptor = $sd.GetSecurityDescriptorBinaryForm() }
        Write-Host \"[+] DCSync concedido a $SyncAccountName sobre $defaultNC (Get-Changes + Get-Changes-All).\" -ForegroundColor Yellow
    } else {
        Write-Host \"[i] $SyncAccountName ya tenia ambos ACEs DCSync (idempotente).\" -ForegroundColor DarkGray
    }
}

Write-Host \"`n[+] AP06 sembrado (modo=$SsoMode). Cadena: cred de sync -> DCSync -> claves de $ssoSam -> silver ticket -> NUBE.\" -ForegroundColor Green
Write-Host \"[i] Ruta en docs/attack-paths/AP06-entra-connect-seamless-sso.md\" -ForegroundColor Cyan
Write-Host \"[i] Arregla in-place: seed-ap06.ps1 -Remediate (rota la clave de $ssoSam 2x + quita DCSync + deshabilita sync).\" -ForegroundColor Cyan
