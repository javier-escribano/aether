<#
.SYNOPSIS
    Completa (o remedia) la condicion vulnerable de AP05 - AD CS ESC1.

.DESCRIPTION
    La DSC base levanta el bosque + Enterprise Root CA + usuario low-priv +
    auditoria. La pieza que lo hace explotable es la PLANTILLA ESC1
    (Enrollee-Supplies-Subject), que este script crea/publica (seed) o
    neutraliza (-Remediate). Simetria exacta con seed-ap01.ps1.

    Condiciones ESC1 que fija el seed sobre la plantilla:
      C1  Enroll para low-priv  -> ACE Certificate-Enrollment a 'Domain Users'.
      C2  sin manager approval  -> msPKI-Enrollment-Flag SIN 0x2 (PEND_ALL_REQUESTS).
      C3  sin firmas RA         -> msPKI-RA-Signature = 0.
      C4  EKU client auth       -> 1.3.6.1.5.5.7.3.2 en pKIExtendedKeyUsage y
                                   msPKI-Certificate-Application-Policy.
      C5  NUCLEO load-bearing   -> msPKI-Certificate-Name-Flag CON 0x1
                                   (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT).

    Modo por defecto (seed) : crea+publica la plantilla vulnerable (idempotente).
    -Remediate              : neutraliza ESC1 (quita 0x1, anade 0x2, despublica).

    CONTEXTO: `az vm run-command` corre como SYSTEM (cuenta de maquina del DC),
    que NO es Enterprise Admin y NO puede escribir el contenedor Certificate
    Templates (Configuration NC). Este script construye un PSCredential EA
    (DOMINIO\Administrator) desde -EaPassword y usa -Credential en TODAS las
    llamadas AD/CA. FALLA RUIDOSAMENTE si no tiene derechos EA.

.NOTES
    Requiere el modulo ActiveDirectory (RSAT-AD-PowerShell, lo instala la DSC).
    Alternativa documentada abajo: modulo ADCSTemplate (New-/Remove-ADCSTemplate).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$DomainFqdn,
    [Parameter(Mandatory = $true)] [string]$DomainNetbios,
    [string]$EaUser       = 'Administrator',
    [Parameter(Mandatory = $true)] [string]$EaPassword,
    [string]$LowPrivGroup = 'Domain Users',
    [string]$TemplateName = 'CaelumAuthESC1',
    [string]$CaCommonName = 'caelum-CA',
    [switch]$Remediate
)

$ErrorActionPreference = 'Stop'

# Flags ESC1 (confirmado: 0x1 vive en msPKI-Certificate-Name-Flag, NO en
# msPKI-Enrollment-Flag; la aprobacion de manager 0x2 si vive en Enrollment-Flag).
$CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1   # msPKI-Certificate-Name-Flag
$CT_FLAG_PEND_ALL_REQUESTS         = 0x2   # msPKI-Enrollment-Flag
$EKU_CLIENT_AUTH                   = '1.3.6.1.5.5.7.3.2'
# Extended rights de enrolamiento (C1).
$RIGHT_ENROLL     = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$RIGHT_AUTOENROLL = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

Import-Module ActiveDirectory -ErrorAction Stop

# --- Credencial EA cualificada (run-command = SYSTEM, no EA) ----------------
$sec = ConvertTo-SecureString $EaPassword -AsPlainText -Force
$EA  = New-Object System.Management.Automation.PSCredential("$DomainNetbios\$EaUser", $sec)

$configNC     = (Get-ADRootDSE -Server $DomainFqdn -Credential $EA).configurationNamingContext
$templatesDN  = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$templateDN   = "CN=$TemplateName,$templatesDN"
$enrollSvcDN  = "CN=$CaCommonName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"

# --- Preflight: exige derechos EA; falla ruidosamente si SYSTEM/no-EA --------
try {
    Get-ADObject -Identity $templatesDN -Server $DomainFqdn -Credential $EA -ErrorAction Stop | Out-Null
} catch {
    throw "[AP05] No puedo leer el contenedor Certificate Templates como '$DomainNetbios\$EaUser'. " +
          "az vm run-command corre como SYSTEM (no EA): pasa EaPassword = password del Administrator " +
          "de DOMINIO (dc_admin_password). Detalle: $($_.Exception.Message)"
}

function Get-TemplateObject {
    Get-ADObject -Identity $templateDN -Server $DomainFqdn -Credential $EA `
        -Properties 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'nTSecurityDescriptor' `
        -ErrorAction SilentlyContinue
}

# Publica/despublica la plantilla = anade/quita su cn del atributo multivaluado
# certificateTemplates del objeto Enrollment Services (Configuration NC) CON la
# credencial EA. El contexto SYSTEM del run-command NO puede escribir ese objeto,
# y `certutil -config -` no es un destino valido (requiere Machine\CAName); por eso
# NO se usa certutil para publicar. Guardas if-contains => idempotente.
function Publish-Esc1Template {
    $svc = Get-ADObject -Identity $enrollSvcDN -Server $DomainFqdn -Credential $EA -Properties certificateTemplates
    if ($svc.certificateTemplates -notcontains $TemplateName) {
        Set-ADObject -Identity $enrollSvcDN -Server $DomainFqdn -Credential $EA -Add @{ certificateTemplates = $TemplateName }
        # Forzar al servicio de la CA a recargar su lista de plantillas emisibles.
        Restart-Service certsvc -Force -ErrorAction SilentlyContinue
        return $true
    }
    return $false
}

function Unpublish-Esc1Template {
    $svc = Get-ADObject -Identity $enrollSvcDN -Server $DomainFqdn -Credential $EA -Properties certificateTemplates
    if ($svc.certificateTemplates -contains $TemplateName) {
        Set-ADObject -Identity $enrollSvcDN -Server $DomainFqdn -Credential $EA -Remove @{ certificateTemplates = $TemplateName }
        Restart-Service certsvc -Force -ErrorAction SilentlyContinue
    }
}

# ===========================================================================
# -Remediate: neutraliza ESC1 (defensa en profundidad; cualquiera corta la ruta).
# ===========================================================================
if ($Remediate) {
    $tpl = Get-TemplateObject
    if (-not $tpl) {
        Write-Host "[i] La plantilla $TemplateName no existe: nada que remediar." -ForegroundColor DarkGray
        return
    }
    Write-Host "[*] Remediando ESC1 en $TemplateName ..." -ForegroundColor Green

    $nameFlag = [int]$tpl.'msPKI-Certificate-Name-Flag'
    $enrFlag  = [int]$tpl.'msPKI-Enrollment-Flag'

    # Antidoto directo: quitar ENROLLEE_SUPPLIES_SUBJECT (0x1).
    $newNameFlag = $nameFlag -band (-bnot $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    # Defensa en profundidad: exigir manager approval (0x2).
    $newEnrFlag  = $enrFlag -bor $CT_FLAG_PEND_ALL_REQUESTS

    Set-ADObject -Identity $templateDN -Server $DomainFqdn -Credential $EA -Replace @{
        'msPKI-Certificate-Name-Flag' = $newNameFlag
        'msPKI-Enrollment-Flag'       = $newEnrFlag
    }
    # Y despublicar de la CA (ya no es solicitable) con la credencial EA.
    Unpublish-Esc1Template
    Write-Host "[+] ESC1 neutralizado (0x1 fuera, 0x2 dentro, despublicada). AP05 remediado." -ForegroundColor Green
    Write-Host "[i] Control de fondo: KB5014754 strong certificate mapping (StrongCertificateBindingEnforcement)." -ForegroundColor Cyan
    return
}

# ===========================================================================
# seed (por defecto): crea+publica la plantilla vulnerable ESC1 (idempotente).
# ===========================================================================
if (Get-TemplateObject) {
    Write-Host "[i] La plantilla $TemplateName ya existe: seed idempotente, no recreo." -ForegroundColor DarkGray
} else {
    Write-Host "[*] Sembrando plantilla ESC1 vulnerable: $TemplateName ..." -ForegroundColor Yellow

    # Clonar los blobs de soporte de la built-in 'User' para que la CA la acepte.
    $user = Get-ADObject -Identity "CN=User,$templatesDN" -Server $DomainFqdn -Credential $EA `
        -Properties pKIExpirationPeriod, pKIOverlapPeriod, pKIKeyUsage, pKIDefaultKeySpec, pKIDefaultCSPs

    # OID de plantilla unico (arc de plantillas de MS). Suficiente para el lab.
    $templateOid = "1.3.6.1.4.1.311.21.8.$(Get-Random -Minimum 1000000 -Maximum 2147483647).$(Get-Random -Minimum 1000000 -Maximum 2147483647)"

    $attrs = @{
        'flags'                               = 0x20000
        'revision'                            = 100
        'msPKI-Template-Schema-Version'       = 2
        'msPKI-Template-Minor-Revision'       = 0
        'msPKI-Minimal-Key-Size'              = 2048
        'msPKI-Cert-Template-OID'             = $templateOid
        'pKIDefaultKeySpec'                   = 1
        'pKIMaxIssuingDepth'                  = 0
        'pKICriticalExtensions'               = '2.5.29.15'
        'pKIExpirationPeriod'                 = $user.pKIExpirationPeriod
        'pKIOverlapPeriod'                    = $user.pKIOverlapPeriod
        'pKIKeyUsage'                         = $user.pKIKeyUsage
        'pKIDefaultCSPs'                      = $user.pKIDefaultCSPs
        # C4: EKU client authentication (pKI y application-policy).
        'pKIExtendedKeyUsage'                 = $EKU_CLIENT_AUTH
        'msPKI-Certificate-Application-Policy' = $EKU_CLIENT_AUTH
        # C3: sin firmas RA.
        'msPKI-RA-Signature'                  = 0
        # C2: sin manager approval (SIN 0x2). 0x0 = vulnerable.
        'msPKI-Enrollment-Flag'               = 0
        # C5 NUCLEO: ENROLLEE_SUPPLIES_SUBJECT (0x1) -> el solicitante pone el SAN.
        'msPKI-Certificate-Name-Flag'         = $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        'displayName'                         = 'Caelum Auth (ESC1)'
    }

    New-ADObject -Name $TemplateName -Type 'pKICertificateTemplate' -Path $templatesDN `
        -DisplayName 'Caelum Auth (ESC1)' -OtherAttributes $attrs `
        -Server $DomainFqdn -Credential $EA

    # C1: ACE de Enroll (+Autoenroll) para el grupo low-priv.
    $grp = Get-ADGroup -Identity $LowPrivGroup -Server $DomainFqdn -Credential $EA
    $sid = New-Object System.Security.Principal.SecurityIdentifier($grp.SID)
    $obj = Get-ADObject -Identity $templateDN -Server $DomainFqdn -Credential $EA -Properties nTSecurityDescriptor
    $sd  = $obj.nTSecurityDescriptor
    foreach ($right in @($RIGHT_ENROLL, $RIGHT_AUTOENROLL)) {
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow, $right)
        $sd.AddAccessRule($ace)
    }
    # Read generico para que el grupo vea/enrole la plantilla.
    $sd.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
        [System.Security.AccessControl.AccessControlType]::Allow)))
    # Set-ADObject espera nTSecurityDescriptor en su forma NATIVA (octet-string),
    # NO un objeto ActiveDirectorySecurity (no serializa fiable -> error de
    # conversion que, con ErrorActionPreference=Stop, ABORTA el seed antes de
    # publicar y deja a Domain Users SIN enroll). Pasar la forma binaria:
    Set-ADObject -Identity $templateDN -Server $DomainFqdn -Credential $EA -Replace @{ nTSecurityDescriptor = $sd.GetSecurityDescriptorBinaryForm() }

    Write-Host "[+] Plantilla ESC1 creada (C1-C5). OID=$templateOid" -ForegroundColor Yellow
}

# Publicar en la CA con la credencial EA (sin esto la plantilla existe pero NO es
# solicitable; Certify/certipy no la pueden pedir). Idempotente.
if (Publish-Esc1Template) {
    Write-Host "[+] Plantilla publicada en la CA $CaCommonName. ESC1 explotable por $LowPrivGroup." -ForegroundColor Yellow
} else {
    Write-Host "[i] La plantilla $TemplateName ya estaba publicada en $CaCommonName (idempotente)." -ForegroundColor DarkGray
}
Write-Host "`n[i] Ruta en docs/attack-paths/AP05-adcs-esc1.md" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# ALTERNATIVA documentada (modulo ADCSTemplate de PSGallery; edita el
# Configuration NC -> EXIGE Enterprise Admin, -Publish publica en TODOS los CA):
#   New-ADCSTemplate -DisplayName 'Caelum Auth (ESC1)' -Name CaelumAuthESC1 `
#       -JSON (Get-Content esc1.json -Raw) -Identity 'CAELUM\Domain Users' -Publish
#   Set-ADCSTemplateACL -DisplayName 'Caelum Auth (ESC1)' -Type Allow -Identity 'CAELUM\Domain Users' -Enroll
#   # Remediacion: Remove-ADCSTemplate -DisplayName 'Caelum Auth (ESC1)'
# ESC1 puro NO necesita EDITF_ATTRIBUTESUBJECTALTNAME2 en la CA (el SAN llega
# por ENROLLEE_SUPPLIES_SUBJECT; EDITF seria ESC6).
# ---------------------------------------------------------------------------
