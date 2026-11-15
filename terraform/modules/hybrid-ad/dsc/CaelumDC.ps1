<#
    CaelumDC.ps1 - Configuracion DSC de la BASE BENIGNA de AP05.

    Levanta SOLO la base: bosque AD DS de usar-y-tirar + Enterprise Root CA
    + usuario low-priv + auditoria CA/Kerberos + StrongCertificateBinding
    (KB5014754) en modo Compatibility. NO crea la plantilla ESC1: esa la
    siembra scripts/seed-ap05.ps1 (seed | -Remediate) via az vm run-command,
    con simetria exacta a seed-ap01.ps1.

    Reboot-aware: el LCM posee el reboot de DCPromo (RebootNodeIfNeeded +
    ActionAfterReboot='ContinueConfiguration') y REANUDA la config tras
    reiniciar; la extension DSC solo reporta success cuando TODO (incluido
    AD CS post-reboot y la auditoria) queda Compliant.

    Credenciales: llegan cifradas por protected_settings.configurationArguments
    de la extension. El configurationData (PSDscAllowDomainUser/PlainText) lo
    aporta la extension como blob aparte.
#>

# ------------------------------------------------------------------
# Bootstrap de modulos DSC (corre al COMPILAR la MOF en la VM).
# REQUIERE salida 443 a PSGallery en el deploy. Fallback air-gap: bakear
# ActiveDirectoryDsc/ActiveDirectoryCSDsc dentro del zip (Publish-AzVMDsc
# Configuration o commitear los arboles de modulo) y quitar este bloque.
# Pins (reproducibilidad; un modulo sin pin es un failure mode conocido).
# ------------------------------------------------------------------
$ErrorActionPreference = 'Stop'

if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
}
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue

if (-not (Get-Module -ListAvailable -Name ActiveDirectoryDsc | Where-Object { $_.Version -eq '6.6.0' })) {
    Install-Module -Name ActiveDirectoryDsc -RequiredVersion 6.6.0 -Force -AllowClobber | Out-Null
}
if (-not (Get-Module -ListAvailable -Name ActiveDirectoryCSDsc | Where-Object { $_.Version -eq '5.0.0' })) {
    Install-Module -Name ActiveDirectoryCSDsc -RequiredVersion 5.0.0 -Force -AllowClobber | Out-Null
}

Configuration CaelumDC {
    param(
        [Parameter(Mandatory = $true)] [string]       $DomainFqdn,
        [Parameter(Mandatory = $true)] [string]       $DomainNetbios,
        [Parameter(Mandatory = $true)] [pscredential] $AdminCredential,
        [Parameter(Mandatory = $true)] [pscredential] $SafemodeCredential,
        [Parameter(Mandatory = $true)] [pscredential] $LowPrivCredential,
        [string] $LowPrivUser           = 'ap05user',
        [string] $CaCommonName          = 'caelum-CA',
        [string] $StrongCertBindingMode = '1'
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ActiveDirectoryDsc   -ModuleVersion '6.6.0'
    Import-DscResource -ModuleName ActiveDirectoryCSDsc -ModuleVersion '5.0.0'

    # Credencial de dominio CUALIFICADA para la CA enterprise (exige Enterprise
    # Admin; el built-in Administrator lo es en el dominio raiz del bosque).
    $domainCred = New-Object System.Management.Automation.PSCredential(
        "$DomainNetbios\$($AdminCredential.UserName)", $AdminCredential.Password)

    Node localhost {

        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
            ActionAfterReboot  = 'ContinueConfiguration'
            ConfigurationMode  = 'ApplyOnly'
        }

        # 1) Roles. ADCS-Cert-Authority se instala ya (la CONFIGURACION de la
        #    CA ocurre post-promocion, en AdcsCertificationAuthority).
        WindowsFeature DNS       { Name = 'DNS';                 Ensure = 'Present' }
        WindowsFeature ADDS      { Name = 'AD-Domain-Services';  Ensure = 'Present'; DependsOn = '[WindowsFeature]DNS' }
        WindowsFeature RSATADPS  { Name = 'RSAT-AD-PowerShell';  Ensure = 'Present' }
        WindowsFeature ADCS      { Name = 'ADCS-Cert-Authority'; Ensure = 'Present' }
        WindowsFeature RSATADCS  { Name = 'RSAT-ADCS-Mgmt';      Ensure = 'Present' }

        # 2) El built-in Administrator (RID 500) perdura como EA tras DCPromo;
        #    el admin SAM 'caelumadmin' DESAPARECE (los DC no tienen cuentas
        #    locales salvo DSRM). Set+enable con dc_admin_password ANTES de
        #    promover, para que el seed autentique luego como DOMINIO\Administrator.
        User BuiltinAdmin {
            UserName             = 'Administrator'
            Password             = $AdminCredential
            Disabled             = $false
            PasswordNeverExpires = $true
            Ensure               = 'Present'
            DependsOn            = '[WindowsFeature]ADDS'
        }

        # 3) Nuevo bosque. Credential = Administrator local (se convierte en DA).
        ADDomain Forest {
            DomainName                    = $DomainFqdn
            DomainNetbiosName             = $DomainNetbios
            Credential                    = $AdminCredential
            SafemodeAdministratorPassword = $SafemodeCredential
            ForestMode                    = 'WinThreshold'
            DomainMode                    = 'WinThreshold'
            DependsOn                     = '[User]BuiltinAdmin'
        }

        # Robustez post-reboot: no sigas hasta que el dominio responda.
        WaitForADDomain WaitForest {
            DomainName = $DomainFqdn
            DependsOn  = '[ADDomain]Forest'
        }

        # 4) Usuario low-priv (credencial de arranque del atacante). Solo Domain
        #    Users; NO se siembra ninguna credencial de DA (el DA se forja).
        ADUser LowPriv {
            DomainName           = $DomainFqdn
            UserName             = $LowPrivUser
            UserPrincipalName    = "$LowPrivUser@$DomainFqdn"
            Password             = $LowPrivCredential
            PasswordNeverExpires = $true
            Ensure               = 'Present'
            DependsOn            = '[WaitForADDomain]WaitForest'
        }

        # 5) Enterprise Root CA (requiere dominio + credencial EA cualificada).
        AdcsCertificationAuthority CA {
            IsSingleInstance = 'Yes'
            CAType           = 'EnterpriseRootCA'
            CACommonName     = $CaCommonName
            Credential       = $domainCred
            Ensure           = 'Present'
            DependsOn        = '[WaitForADDomain]WaitForest', '[WindowsFeature]ADCS'
        }

        # 6) Auditoria de la CA (4886/4887/4899/4900). Sin AuditFilter+auditpol
        #    la CA NO audita y la pata Detecta dispara en vacio. Lo hace la BASE
        #    (no el seed) para que persista entre ciclos seed/-Remediate.
        Script CaAudit {
            GetScript  = { @{ Result = ((certutil -getreg CA\AuditFilter) 2>$null | Out-String) } }
            TestScript = {
                $r = (certutil -getreg CA\AuditFilter) 2>$null | Out-String
                return ($r -match '0x7f|127')
            }
            SetScript  = {
                certutil -setreg CA\AuditFilter 127 | Out-Null
                Restart-Service certsvc -Force
                auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable | Out-Null
            }
            DependsOn = '[AdcsCertificationAuthority]CA'
        }

        # 7) Auditoria Kerberos (4768 con Certificate Information en PKINIT).
        Script KerberosAudit {
            GetScript  = { @{ Result = ((auditpol /get /subcategory:"Kerberos Authentication Service") | Out-String) } }
            TestScript = {
                $r = (auditpol /get /subcategory:"Kerberos Authentication Service") | Out-String
                return ($r -match 'Success')
            }
            SetScript  = {
                auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable | Out-Null
            }
            DependsOn = '[WaitForADDomain]WaitForest'
        }

        # 8) KB5014754: Compatibility (1) para que ESC1 sea explotable como se
        #    ensena. Full Enforcement (2, default si no se configura post-feb-2025)
        #    lee la SID extension y RECHAZA el SAN forjado -> parece 'ya parcheado'
        #    (de hecho, es el fix real). Control ensenable; la base NO corre
        #    Windows Update.
        Registry StrongCertBinding {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
            ValueName = 'StrongCertificateBindingEnforcement'
            ValueData = $StrongCertBindingMode
            ValueType = 'Dword'
            Ensure    = 'Present'
            DependsOn = '[WaitForADDomain]WaitForest'
        }
    }
}
