<#
    AzRangeDC.ps1 - DSC configuration of the AP05 BENIGN BASE.

    Brings up ONLY the base: throwaway AD DS forest + Enterprise Root CA
    + low-priv user + CA/Kerberos auditing + StrongCertificateBinding
    (KB5014754) in Compatibility mode. Does NOT create the ESC1 template: that is
    seeded by scripts/seed-ap05.ps1 (seed | -Remediate) via az vm run-command,
    in exact symmetry with seed-ap01.ps1.

    Reboot-aware: the LCM owns the DCPromo reboot (RebootNodeIfNeeded +
    ActionAfterReboot='ContinueConfiguration') and RESUMES the config after
    rebooting; the DSC extension only reports success when EVERYTHING (including
    post-reboot AD CS and the auditing) is Compliant.

    Credentials: arrive encrypted via protected_settings.configurationArguments
    of the extension. The configurationData (PSDscAllowDomainUser/PlainText) is
    supplied by the extension as a separate blob.
#>

# ------------------------------------------------------------------
# DSC module bootstrap (runs when COMPILING the MOF on the VM).
# REQUIRES outbound 443 to PSGallery at deploy. Air-gap fallback: bake
# ActiveDirectoryDsc/ActiveDirectoryCSDsc into the zip (Publish-AzVMDsc
# Configuration or commit the module trees) and remove this block.
# Pins (reproducibility; an unpinned module is a known failure mode).
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

Configuration AzRangeDC {
    param(
        [Parameter(Mandatory = $true)] [string]       $DomainFqdn,
        [Parameter(Mandatory = $true)] [string]       $DomainNetbios,
        [Parameter(Mandatory = $true)] [pscredential] $AdminCredential,
        [Parameter(Mandatory = $true)] [pscredential] $SafemodeCredential,
        [Parameter(Mandatory = $true)] [pscredential] $LowPrivCredential,
        [string] $LowPrivUser           = 'ap05user',
        [string] $CaCommonName          = 'azrange-CA',
        [string] $StrongCertBindingMode = '1'
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ActiveDirectoryDsc   -ModuleVersion '6.6.0'
    Import-DscResource -ModuleName ActiveDirectoryCSDsc -ModuleVersion '5.0.0'

    # QUALIFIED domain credential for the enterprise CA (requires Enterprise
    # Admin; the built-in Administrator is one in the forest root domain).
    $domainCred = New-Object System.Management.Automation.PSCredential(
        "$DomainNetbios\$($AdminCredential.UserName)", $AdminCredential.Password)

    Node localhost {

        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
            ActionAfterReboot  = 'ContinueConfiguration'
            ConfigurationMode  = 'ApplyOnly'
        }

        # 1) Roles. ADCS-Cert-Authority is installed now (the CA CONFIGURATION
        #    happens post-promotion, in AdcsCertificationAuthority).
        WindowsFeature DNS       { Name = 'DNS';                 Ensure = 'Present' }
        WindowsFeature ADDS      { Name = 'AD-Domain-Services';  Ensure = 'Present'; DependsOn = '[WindowsFeature]DNS' }
        WindowsFeature RSATADPS  { Name = 'RSAT-AD-PowerShell';  Ensure = 'Present' }
        WindowsFeature ADCS      { Name = 'ADCS-Cert-Authority'; Ensure = 'Present' }
        WindowsFeature RSATADCS  { Name = 'RSAT-ADCS-Mgmt';      Ensure = 'Present' }

        # 2) The built-in Administrator (RID 500) persists as EA after DCPromo;
        #    the SAM admin 'azrangeadmin' DISAPPEARS (DCs have no local accounts
        #    except DSRM). Set+enable with dc_admin_password BEFORE promoting,
        #    so the seed later authenticates as DOMAIN\Administrator.
        User BuiltinAdmin {
            UserName             = 'Administrator'
            Password             = $AdminCredential
            Disabled             = $false
            PasswordNeverExpires = $true
            Ensure               = 'Present'
            DependsOn            = '[WindowsFeature]ADDS'
        }

        # 3) New forest. Credential = local Administrator (becomes DA).
        ADDomain Forest {
            DomainName                    = $DomainFqdn
            DomainNetbiosName             = $DomainNetbios
            Credential                    = $AdminCredential
            SafemodeAdministratorPassword = $SafemodeCredential
            ForestMode                    = 'WinThreshold'
            DomainMode                    = 'WinThreshold'
            DependsOn                     = '[User]BuiltinAdmin'
        }

        # Post-reboot robustness: do not proceed until the domain responds.
        WaitForADDomain WaitForest {
            DomainName = $DomainFqdn
            DependsOn  = '[ADDomain]Forest'
        }

        # 4) Low-priv user (attacker's starting credential). Domain Users
        #    only; NO DA credential is seeded (the DA is forged).
        ADUser LowPriv {
            DomainName           = $DomainFqdn
            UserName             = $LowPrivUser
            UserPrincipalName    = "$LowPrivUser@$DomainFqdn"
            Password             = $LowPrivCredential
            PasswordNeverExpires = $true
            Ensure               = 'Present'
            DependsOn            = '[WaitForADDomain]WaitForest'
        }

        # 5) Enterprise Root CA (requires domain + qualified EA credential).
        AdcsCertificationAuthority CA {
            IsSingleInstance = 'Yes'
            CAType           = 'EnterpriseRootCA'
            CACommonName     = $CaCommonName
            Credential       = $domainCred
            Ensure           = 'Present'
            DependsOn        = '[WaitForADDomain]WaitForest', '[WindowsFeature]ADCS'
        }

        # 6) CA auditing (4886/4887/4899/4900). Without AuditFilter+auditpol
        #    the CA does NOT audit and the Detect leg fires on nothing. Done by the
        #    BASE (not the seed) so it persists across seed/-Remediate cycles.
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

        # 7) Kerberos auditing (4768 with Certificate Information in PKINIT).
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

        # 8) KB5014754: Compatibility (1) so ESC1 is exploitable as taught.
        #    Full Enforcement (2, the default if not configured after Feb 2025)
        #    reads the SID extension and REJECTS the forged SAN -> looks 'already patched'
        #    (in fact, it is the real fix). A teachable control; the base does NOT run
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
