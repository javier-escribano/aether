<#
.SYNOPSIS
    Completes (or remediates) the AP05 vulnerable condition - AD CS ESC1.

.DESCRIPTION
    The base DSC stands up the forest + Enterprise Root CA + low-priv user +
    auditing. The piece that makes it exploitable is the ESC1 TEMPLATE
    (Enrollee-Supplies-Subject), which this script creates/publishes (seed) or
    neutralizes (-Remediate). Exact symmetry with seed-ap01.ps1.

    ESC1 conditions the seed sets on the template:
      C1  Enroll for low-priv   -> Certificate-Enrollment ACE to 'Domain Users'.
      C2  no manager approval   -> msPKI-Enrollment-Flag WITHOUT 0x2 (PEND_ALL_REQUESTS).
      C3  no RA signatures      -> msPKI-RA-Signature = 0.
      C4  EKU client auth       -> 1.3.6.1.5.5.7.3.2 in pKIExtendedKeyUsage and
                                   msPKI-Certificate-Application-Policy.
      C5  CORE load-bearing     -> msPKI-Certificate-Name-Flag WITH 0x1
                                   (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT).

    Default mode (seed)     : creates+publishes the vulnerable template (idempotent).
    -Remediate              : neutralizes ESC1 (removes 0x1, adds 0x2, unpublishes).

    CONTEXT: `az vm run-command` runs as SYSTEM (the DC's machine account),
    which is NOT Enterprise Admin and CANNOT write the Certificate Templates
    container (Configuration NC). This script builds an EA PSCredential
    (DOMAIN\Administrator) from -EaPassword and uses -Credential on ALL
    AD/CA calls. FAILS LOUDLY if it lacks EA rights.

.NOTES
    Requires the ActiveDirectory module (RSAT-AD-PowerShell, installed by the DSC).
    Documented alternative below: the ADCSTemplate module (New-/Remove-ADCSTemplate).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$DomainFqdn,
    [Parameter(Mandatory = $true)] [string]$DomainNetbios,
    [string]$EaUser       = 'Administrator',
    [Parameter(Mandatory = $true)] [string]$EaPassword,
    [string]$LowPrivGroup = 'Domain Users',
    [string]$TemplateName = 'AzRangeAuthESC1',
    [string]$CaCommonName = 'azrange-CA',
    [switch]$Remediate
)

$ErrorActionPreference = 'Stop'

# ESC1 flags (confirmed: 0x1 lives in msPKI-Certificate-Name-Flag, NOT in
# msPKI-Enrollment-Flag; the manager approval 0x2 does live in Enrollment-Flag).
$CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1   # msPKI-Certificate-Name-Flag
$CT_FLAG_PEND_ALL_REQUESTS         = 0x2   # msPKI-Enrollment-Flag
$EKU_CLIENT_AUTH                   = '1.3.6.1.5.5.7.3.2'
# Enrollment extended rights (C1).
$RIGHT_ENROLL     = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$RIGHT_AUTOENROLL = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

Import-Module ActiveDirectory -ErrorAction Stop

# --- Qualified EA credential (run-command = SYSTEM, not EA) ------------------
$sec = ConvertTo-SecureString $EaPassword -AsPlainText -Force
$EA  = New-Object System.Management.Automation.PSCredential("$DomainNetbios\$EaUser", $sec)

$configNC     = (Get-ADRootDSE -Server $DomainFqdn -Credential $EA).configurationNamingContext
$templatesDN  = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$templateDN   = "CN=$TemplateName,$templatesDN"
$enrollSvcDN  = "CN=$CaCommonName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"

# --- Preflight: requires EA rights; fails loudly if SYSTEM/non-EA ------------
try {
    Get-ADObject -Identity $templatesDN -Server $DomainFqdn -Credential $EA -ErrorAction Stop | Out-Null
} catch {
    throw "[AP05] Cannot read the Certificate Templates container as '$DomainNetbios\$EaUser'. " +
          "az vm run-command runs as SYSTEM (not EA): pass EaPassword = the DOMAIN Administrator " +
          "password (dc_admin_password). Detail: $($_.Exception.Message)"
}

function Get-TemplateObject {
    Get-ADObject -Identity $templateDN -Server $DomainFqdn -Credential $EA `
        -Properties 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'nTSecurityDescriptor' `
        -ErrorAction SilentlyContinue
}

# Publish/unpublish the template = add/remove its cn from the multi-valued
# certificateTemplates attribute of the Enrollment Services object (Configuration NC)
# WITH the EA credential. The run-command's SYSTEM context CANNOT write that object,
# and `certutil -config -` is not a valid target (it requires Machine\CAName); that is
# why certutil is NOT used to publish. if-contains guards => idempotent.
function Publish-Esc1Template {
    $svc = Get-ADObject -Identity $enrollSvcDN -Server $DomainFqdn -Credential $EA -Properties certificateTemplates
    if ($svc.certificateTemplates -notcontains $TemplateName) {
        Set-ADObject -Identity $enrollSvcDN -Server $DomainFqdn -Credential $EA -Add @{ certificateTemplates = $TemplateName }
        # Force the CA service to reload its list of issuable templates.
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
# -Remediate: neutralizes ESC1 (defense in depth; any one of these cuts the path).
# ===========================================================================
if ($Remediate) {
    $tpl = Get-TemplateObject
    if (-not $tpl) {
        Write-Host "[i] Template $TemplateName does not exist: nothing to remediate." -ForegroundColor DarkGray
        return
    }
    Write-Host "[*] Remediating ESC1 on $TemplateName ..." -ForegroundColor Green

    $nameFlag = [int]$tpl.'msPKI-Certificate-Name-Flag'
    $enrFlag  = [int]$tpl.'msPKI-Enrollment-Flag'

    # Direct antidote: remove ENROLLEE_SUPPLIES_SUBJECT (0x1).
    $newNameFlag = $nameFlag -band (-bnot $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
    # Defense in depth: require manager approval (0x2).
    $newEnrFlag  = $enrFlag -bor $CT_FLAG_PEND_ALL_REQUESTS

    Set-ADObject -Identity $templateDN -Server $DomainFqdn -Credential $EA -Replace @{
        'msPKI-Certificate-Name-Flag' = $newNameFlag
        'msPKI-Enrollment-Flag'       = $newEnrFlag
    }
    # And unpublish from the CA (no longer requestable) with the EA credential.
    Unpublish-Esc1Template
    Write-Host "[+] ESC1 neutralized (0x1 out, 0x2 in, unpublished). AP05 remediated." -ForegroundColor Green
    Write-Host "[i] Background control: KB5014754 strong certificate mapping (StrongCertificateBindingEnforcement)." -ForegroundColor Cyan
    return
}

# ===========================================================================
# seed (default): creates+publishes the vulnerable ESC1 template (idempotent).
# ===========================================================================
if (Get-TemplateObject) {
    Write-Host "[i] Template $TemplateName already exists: idempotent seed, not recreating." -ForegroundColor DarkGray
} else {
    Write-Host "[*] Seeding vulnerable ESC1 template: $TemplateName ..." -ForegroundColor Yellow

    # Clone the supporting blobs from the built-in 'User' template so the CA accepts it.
    $user = Get-ADObject -Identity "CN=User,$templatesDN" -Server $DomainFqdn -Credential $EA `
        -Properties pKIExpirationPeriod, pKIOverlapPeriod, pKIKeyUsage, pKIDefaultKeySpec, pKIDefaultCSPs

    # Unique template OID (MS template arc). Sufficient for the lab.
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
        # C4: EKU client authentication (pKI and application-policy).
        'pKIExtendedKeyUsage'                 = $EKU_CLIENT_AUTH
        'msPKI-Certificate-Application-Policy' = $EKU_CLIENT_AUTH
        # C3: no RA signatures.
        'msPKI-RA-Signature'                  = 0
        # C2: no manager approval (WITHOUT 0x2). 0x0 = vulnerable.
        'msPKI-Enrollment-Flag'               = 0
        # C5 CORE: ENROLLEE_SUPPLIES_SUBJECT (0x1) -> the requester sets the SAN.
        'msPKI-Certificate-Name-Flag'         = $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        'displayName'                         = 'AzRange Auth (ESC1)'
    }

    New-ADObject -Name $TemplateName -Type 'pKICertificateTemplate' -Path $templatesDN `
        -DisplayName 'AzRange Auth (ESC1)' -OtherAttributes $attrs `
        -Server $DomainFqdn -Credential $EA

    # C1: Enroll (+Autoenroll) ACE for the low-priv group.
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
    # Generic Read so the group can see/enroll the template.
    $sd.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead,
        [System.Security.AccessControl.AccessControlType]::Allow)))
    # Set-ADObject expects nTSecurityDescriptor in its NATIVE form (octet-string),
    # NOT an ActiveDirectorySecurity object (it does not serialize reliably -> a
    # conversion error that, with ErrorActionPreference=Stop, ABORTS the seed before
    # publishing and leaves Domain Users WITHOUT enroll). Pass the binary form:
    Set-ADObject -Identity $templateDN -Server $DomainFqdn -Credential $EA -Replace @{ nTSecurityDescriptor = $sd.GetSecurityDescriptorBinaryForm() }

    Write-Host "[+] ESC1 template created (C1-C5). OID=$templateOid" -ForegroundColor Yellow
}

# Publish on the CA with the EA credential (without this the template exists but is NOT
# requestable; Certify/certipy cannot request it). Idempotent.
if (Publish-Esc1Template) {
    Write-Host "[+] Template published on CA $CaCommonName. ESC1 exploitable by $LowPrivGroup." -ForegroundColor Yellow
} else {
    Write-Host "[i] Template $TemplateName was already published on $CaCommonName (idempotent)." -ForegroundColor DarkGray
}
Write-Host "`n[i] Attack path in docs/attack-paths/AP05-adcs-esc1.md" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Documented ALTERNATIVE (the ADCSTemplate module from PSGallery; edits the
# Configuration NC -> REQUIRES Enterprise Admin, -Publish publishes on ALL CAs):
#   New-ADCSTemplate -DisplayName 'AzRange Auth (ESC1)' -Name AzRangeAuthESC1 `
#       -JSON (Get-Content esc1.json -Raw) -Identity 'AZRANGE\Domain Users' -Publish
#   Set-ADCSTemplateACL -DisplayName 'AzRange Auth (ESC1)' -Type Allow -Identity 'AZRANGE\Domain Users' -Enroll
#   # Remediation: Remove-ADCSTemplate -DisplayName 'AzRange Auth (ESC1)'
# Pure ESC1 does NOT need EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA (the SAN arrives
# via ENROLLEE_SUPPLIES_SUBJECT; EDITF would be ESC6).
# ---------------------------------------------------------------------------
