param(
    [Parameter(Mandatory = $false, Position = 1)]
    [string]$PasswordDataFileName = $null,
    # Monospaced font used across all GUI elements (forms, grids, buttons, status bar)
    [double]$FontSize = 10
)
$Script:version = '1.15 (18 Nov 2026)'
<#
.SYNOPSIS
  Secure Password Storage Manager
.DESCRIPTION
 Creates and manages password storage using RSA encryption. It is recommended to use hardware smartcards
 RDP connection functionality uses an embedded C# wrapper (compiled at runtime via Add-Type) over the native
 Windows Credential Manager API - no external PSCredentialManager DLLs are required
.NOTES
 Author:         Andrew Afanasiev
 Contacts:       AfanasievAA@yandex.ru
 CommonFunctions.ps1 is required
.EXAMPLE
  GUI Interface. Just run and enjoy
    $script:passwordDataFileName = "secure_passwords_v1.xml"
    # Decrypts passwords for multiple users from SECURE XML storage and returns an hashtable of PSCredential objects
    function Get-SecureUserCredentials {
        param(
            [Parameter(Mandatory=$true)]
            [string[]]$userNames
        )

        if (-Not (Test-Path $script:passwordDataFileName)) {
            Write-Warning "File not found: $($script:passwordDataFileName)"
            return $null
        }

        try {
            $cliObj = Import-Clixml $script:passwordDataFileName

            if ($cliObj.Version -ne 1) {
                Write-Error "Incorrect File Version. Version 1 is required"
                return $null
            }

            # 1. Query certificate storage ONCE
            $myCerts = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue | Where-Object { $_.HasPrivateKey }

            $decryptionCert = $null
            $correctKeyIndex = -1

            # 2. Search for the matching certificate ONCE
            for ($i = 0; $i -lt $cliObj.Keys.Count; $i++) {
                $targetThumb = $cliObj.Keys[$i]
                $foundCert = $myCerts | Where-Object { $_.Thumbprint -eq $targetThumb } | Select-Object -First 1
                if ($foundCert) {
                    $decryptionCert = $foundCert
                    $correctKeyIndex = $i
                    break
                }
            }

            if (-not $decryptionCert) {
                Write-Error "No decryption certificate is found. No smart-card or token connected?"
                return $null
            }

            # 3. Decrypt the names block ONCE
            $namesEncrypted = ($cliObj.Names -split ",")[$correctKeyIndex]
            $namesContent = "-----BEGIN CMS-----$($namesEncrypted)-----END CMS-----"
            $namesDecrypted = Unprotect-CmsMessage -To $decryptionCert -Content $namesContent -ErrorAction Stop

            $usersArray = $namesDecrypted -split "`r`n"

            # 4. Create a hash table for instant lookup of user indices in the file
            $userIndexMap = @{}
            for ($j = 0; $j -lt $usersArray.Count; $j++) {
                $parts = $usersArray[$j] -split "##", 2
                if (-not $userIndexMap.ContainsKey($parts[0])) {
                    $userIndexMap[$parts[0]] = $j
                }
            }

            # 5. Create a hash table for results (Key = UserName, Value = PSCredential)
            $resultCredentials = @{}

            # 6. Iterate over requested user names
            foreach ($reqUser in $userNames) {
                if ($userIndexMap.ContainsKey($reqUser)) {
                    $targetIndex = $userIndexMap[$reqUser]

                    # Decrypt password only for the found user
                    $pwdEncrypted = ($cliObj.PWDS[$targetIndex] -split ",")[$correctKeyIndex]
                    $pwdContent = "-----BEGIN CMS-----$($pwdEncrypted)-----END CMS-----"

                    $plainPwd = Unprotect-CmsMessage -To $decryptionCert -Content $pwdContent -ErrorAction Stop
                    $secString = ConvertTo-SecureString -String $plainPwd -AsPlainText -Force

                    # Add the PSCredential object to the resulting hash table
                    $resultCredentials[$reqUser] = [PSCredential]::new($reqUser, $secString)
                } else {
                    Write-Warning "User '$reqUser' not found in the secure storage."
                }
            }

            # Return the hash table
            return $resultCredentials

        } catch {
            Write-Error "Failed to read credentials: $($_.Exception.Message)"
            return $null
        }
    }


    $script:passwordDataFileName = "secure_passwords_v1.xml"

    # Request 3 passwords at once
    $users = @("admin", "user1", "domain\service_account")
    $creds = Get-SecureUserCredentials -userNames $users
    $adminCreds = $creds["admin"]
    $users1Creds = $creds["user1"]
#>
$Script:ScriptRootFolderRunPath = Split-Path (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Path
[string]$MonoFontName = 'Consolas'

# Load Common Functions
try {
    . "$Script:ScriptRootFolderRunPath\inc\Common_Functions.ps1"
} catch {
    Write-Error "Error loading Common_Functions.ps1: $_"
    exit 1
}

# Returns the full path to a settings file, checking a set of common locations.
function Get-SettingsFilePath([string]$FileName) {
    # Directories to search (ordered by priority)
    $searchFolders = @(
        (Get-Location).ProviderPath,          # current PowerShell location
        [Environment]::CurrentDirectory,      # process' current directory
        $Script:ScriptRootFolderRunPath       # folder where the script resides
    )

    foreach ($folder in $searchFolders) {
        $candidate = Join-Path -Path $folder -ChildPath $FileName
        if (Test-Path -LiteralPath $candidate) {
            $CommonObj.LogInfo("$FileName found at $candidate")
            return $candidate
        }
    }
    # Not found - return a default path inside the script folder
    return Join-Path -Path $Script:ScriptRootFolderRunPath -ChildPath $FileName
}

# Load System.Drawing explicitly: PowerShell 7 does not preload it, and the font
# objects below are created before the Add-Type for System.Windows.Forms runs
Add-Type -AssemblyName System.Drawing
# Shared font objects: created once and reused by every form, grid and button.
# Forms, grids and the status bar share one size; Save is bold, the +/- buttons use 16 pt bold
$Script:FormFont = New-Object System.Drawing.Font($MonoFontName, $FontSize, [System.Drawing.FontStyle]::Regular)
$Script:GridFont = New-Object System.Drawing.Font($MonoFontName, $FontSize, [System.Drawing.FontStyle]::Regular)
$Script:BoldFont = New-Object System.Drawing.Font($MonoFontName, $FontSize, [System.Drawing.FontStyle]::Bold)
$Script:SignFont = New-Object System.Drawing.Font($MonoFontName, 16, [System.Drawing.FontStyle]::Bold)
$Script:iniFileFullPath = Get-SettingsFilePath 'pwd_manager.ini'
$Script:rdpFileFullPath = Get-SettingsFilePath 'RDPSettings.rdp'
# A file name passed as a script parameter overrides the default search
if ([string]::IsNullOrWhiteSpace($PasswordDataFileName)) {
    $Script:PasswordDataFilePath = Get-SettingsFilePath 'secure_passwords_v1.xml'
} else {
    $Script:PasswordDataFilePath = $PasswordDataFileName
}
# Load INI Configuration
$CommonObj.LogInfo('Loading pwd_manager.ini...')
# ReadINIFileIfChanged: $true = file was (re)read, $false = unchanged since the last read, $null = file not found
$iniFileIsRead = $Script:CommonObj.ReadINIFileIfChanged($Script:iniFileFullPath)
if ($true -eq $iniFileIsRead) {
    $CommonObj.LogInfo('pwd_manager.ini was loaded.', '-Fore DarkGray')
} elseif ($false -eq $iniFileIsRead) {
    $CommonObj.LogInfo('pwd_manager.ini unchanged since the last read, using cached settings.')
} else {
    $CommonObj.LogInfo('pwd_manager.ini not found, default settings are used.')
}


# Inline C# replacement for PSCredentialManager.Common.dll and PSCredentialManager.Api.dll.
# The code wraps the native Windows Credential Manager API (advapi32.dll), eliminating external DLL dependencies entirely.
$Script:PSCredentialManagerDllLoaded = $false
try {
    if (-not ('PSCredentialManager.Api.CredentialManager' -as [type])) {
        $credentialManagerCSharp = @'
using System;
using System.Runtime.InteropServices;

namespace PSCredentialManager.Common
{
    // Managed representation of the native CREDENTIAL structure from advapi32.dll
    [StructLayout(LayoutKind.Sequential)]
    public class NativeCredential
    {
        public int Flags;
        public int Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }
}

namespace PSCredentialManager.Api
{
    public class CredentialManager
    {
        [DllImport("advapi32.dll", EntryPoint = "CredWriteW", SetLastError = true)]
        private static extern bool CredWriteW(IntPtr credential, uint flags);

        [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredDeleteW(string target, int type, int reservedFlag);

        public bool WriteCred(PSCredentialManager.Common.NativeCredential credential)
        {
            // Marshal the managed class to a native structure pointer
            int structSize = Marshal.SizeOf(typeof(PSCredentialManager.Common.NativeCredential));
            IntPtr credPtr = Marshal.AllocHGlobal(structSize);
            try
            {
                Marshal.StructureToPtr(credential, credPtr, false);
                if (!CredWriteW(credPtr, 0))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(credPtr);
            }
        }

        public bool DeleteCred(string target, int type)
        {
            if (!CredDeleteW(target, type, 0))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            return true;
        }
    }
}
'@
        Add-Type -TypeDefinition $credentialManagerCSharp -Language CSharp -ErrorAction Stop
    }
    $Script:PSCredentialManagerDllLoaded = $true
} catch {
    Write-Host '❌ PSCredentialManager inline compilation failed! RDP connections will not be available'
    Write-Host $_.Exception.Message -ForegroundColor DarkGray
}

Add-Type -AssemblyName System.Windows.Forms -ErrorAction stop
# System.Security.dll (Pkcs: EnvelopedCms, CmsRecipient, ContentInfo) is preloaded in PowerShell 7
# but not in Windows PowerShell 5.1; without it every [System.Security.Cryptography.Pkcs.*] literal fails
if (-not ('System.Security.Cryptography.Pkcs.EnvelopedCms' -as [type])) {
    Add-Type -AssemblyName System.Security -ErrorAction Stop
}
[void][System.Windows.Forms.Application]::EnableVisualStyles()

$Script:certThumbprint = ''
$Script:StatusBarTextBox = $null
$Script:CachedPrivateKeyCert = $null
$Script:PwdClearTimer = $null
$Script:ConnectionHistory = @{
    RDP = New-Object System.Collections.Queue
    SMB = New-Object System.Collections.Queue
}

#region Helper Functions

function Write-Statusbar {
    param([string]$Text, [string]$Color = 'blue')
    if ($Script:StatusBarTextBox) {
        $Script:StatusBarTextBox.Text = $Text
        $Script:StatusBarTextBox.ForeColor = $Color
        $Script:StatusBarTextBox.Update()
    }
}

function Set-DataGridColumnWidth {
    param($DataGridView, [int[]]$Widths)
    $cnt = 0
    foreach ($width in $Widths) {
        if ($DataGridView.Columns[$cnt]) {
            if ($width -gt 0) {
                $DataGridView.Columns[$cnt].Width = $width
            } else {
                $DataGridView.Columns[$cnt].Visible = $false
            }
        }
        $cnt++
    }
}

function Get-CertificateDnsNames {
    param($Cert)
    if ($Cert.DnsNameList -and $Cert.DnsNameList.Count -gt 0) {
        $dnsNames = @($Cert.DnsNameList | ForEach-Object { $_.Unicode })
        return $dnsNames -join ', '
    } elseif ($Cert.Subject -match 'CN=([^,]+)') {
        return $matches[1]
    } else {
        return 'No DNS Names'
    }
}
function Find-CertificateByThumbprint {
    param(
        [string[]]$Thumbprints,
        [bool]$HasPrivateKey = $false
    )

    $ThumbprintLookup = @{}
    foreach ($thumb in $Thumbprints) {
        $ThumbprintLookup[$thumb.ToUpper()] = $true
    }

    $stores = if ($HasPrivateKey) { @('Cert:\CurrentUser\My') } else { @('Cert:\CurrentUser\My', 'Cert:\CurrentUser\AddressBook', 'Cert:\CurrentUser\TrustedPeople') }

    foreach ($storePath in $stores) {
        if (Test-Path $storePath) {
            $certStore = Get-ChildItem $storePath -ErrorAction SilentlyContinue
            foreach ($cert in $certStore) {
                if ($ThumbprintLookup.ContainsKey($cert.Thumbprint.ToUpper())) {
                    if (-not $HasPrivateKey -or $cert.HasPrivateKey) {
                        return $cert
                    }
                }
            }
        }
    }
    return $null
}
function Find-CertificatesByThumbprints {
    param(
        [string[]]$Thumbprints,
        [bool]$HasPrivateKey = $false
    )

    $ThumbprintLookup = @{}
    foreach ($thumb in $Thumbprints) { $ThumbprintLookup[$thumb.ToUpper()] = $true }

    $stores = if ($HasPrivateKey) { @('Cert:\CurrentUser\My') } else { @('Cert:\CurrentUser\My', 'Cert:\CurrentUser\AddressBook', 'Cert:\CurrentUser\TrustedPeople') }
    $foundCerts = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()

    foreach ($storePath in $stores) {
        if (Test-Path $storePath) {
            foreach ($cert in (Get-ChildItem $storePath -ErrorAction SilentlyContinue)) {
                if ($ThumbprintLookup.ContainsKey($cert.Thumbprint.ToUpper())) {
                    if (-not $HasPrivateKey -or $cert.HasPrivateKey) {
                        $foundCerts.Add($cert)
                    }
                }
            }
        }
    }
    return $foundCerts.ToArray()
}
function Get-PrivateKeyCertificate {
    [array]$thumbprints = $null
    if ($Script:CertificateDataGridView -and $Script:CertificateDataGridView.DataSource) {
        # Enumerate DefaultView: piping a DataTable itself does not enumerate its rows
        $thumbprints = @($Script:CertificateDataGridView.DataSource.DefaultView | Select-Object -ExpandProperty Thumbprint)
    }
    if (-not $thumbprints -and $Script:certThumbprint) {
        $thumbprints = @($Script:certThumbprint)
    }

    if ($thumbprints) {
        # Cache key derived from the thumbprint list: the store is rescanned only when
        # the grid content changes, not on every decrypt/encrypt call
        $cacheKey = ($thumbprints | ForEach-Object { "$_".Trim().ToUpper() }) -join '|'
        if ($Script:CachedPrivateKeyCert -and $Script:CachedPrivateKeyCertKey -eq $cacheKey) {
            return $Script:CachedPrivateKeyCert
        }
        $Script:CachedPrivateKeyCert = Find-CertificateByThumbprint -Thumbprints $thumbprints -HasPrivateKey $true
        if ($Script:CachedPrivateKeyCert) {
            $Script:CachedPrivateKeyCertKey = $cacheKey
        } else {
            Write-Statusbar 'No private key found for the selected certificate' 'red'
        }
        return $Script:CachedPrivateKeyCert
    }
    Write-Statusbar 'No certificate thumbprints available' 'red'
    return $null
}

function Protect-RsaMessage {
    param(
        [string]$MessageText,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$Thumbprint
    )

    $certToUse = $Certificate
    if (-not $certToUse -and $Thumbprint) {
        $certToUse = Find-CertificateByThumbprint -Thumbprints $Thumbprint
    }

    if (-not $certToUse) {
        Write-Host '❌ No certificate provided for encryption' -ForegroundColor red
        return $null
    }
    try {
        # EnvelopedCms does not check the Document Encryption EKU, unlike Protect-CmsMessage.
        # The output is the same CMS format, so it stays compatible with files created earlier
        $contentInfo = [System.Security.Cryptography.Pkcs.ContentInfo]::new([System.Text.Encoding]::UTF8.GetBytes($MessageText))
        $envCms = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new($contentInfo)
        $recipient = [System.Security.Cryptography.Pkcs.CmsRecipient]::new([System.Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber, $certToUse)
        $envCms.Encrypt($recipient)
        # Base64 body without PEM header/footer, consistent with the existing storage format
        return [Convert]::ToBase64String($envCms.Encode())
    } catch {
        Write-Host "❌ Encryption failed: $($_.Exception.Message)" -ForegroundColor red
        return $null
    }
}
function Protect-PasswordForCurrentCertificates {
    param([string]$PlainPassword)

    $encryptedBlocks = @()

    # Get all certificates from the grid
    if ($Script:CertificateDataGridView.DataSource -is [System.Data.DataTable]) {
        $dataTable = $Script:CertificateDataGridView.DataSource
        # One store scan for all grid thumbprints instead of a scan per row
        $certByThumb = @{}
        foreach ($c in (Find-CertificatesByThumbprints -Thumbprints @($dataTable.Rows | ForEach-Object { $_['Thumbprint'] }))) { $certByThumb[$c.Thumbprint] = $c }
        foreach ($row in $dataTable.Rows) {
            $thumbprint = $row['Thumbprint']
            $cert = $certByThumb["$thumbprint"]
            if ($cert) {
                $encrypted = Protect-RsaMessage -MessageText $PlainPassword -Certificate $cert
                if ($encrypted) {
                    $encryptedBlocks += $encrypted
                }
            }
        }
    }

    if ($encryptedBlocks.Count -eq 0) {
        # Fallback to current certificate
        $cert = Get-PrivateKeyCertificate
        if ($cert) {
            $encrypted = Protect-RsaMessage -MessageText $PlainPassword -Certificate $cert
            if ($encrypted) {
                $encryptedBlocks += $encrypted
            }
        }
    }

    if ($encryptedBlocks.Count -eq 0) {
        Write-Host '❌ Failed to encrypt password for any certificate' -ForegroundColor red
        return $null
    }

    return $encryptedBlocks -join ','
}

function Unprotect-RsaMessage {
    param([string]$MessageSecure)

    if ([string]::IsNullOrEmpty($MessageSecure)) {
        Write-Host '❌ Empty password string' -ForegroundColor red
        return $null
    }

    $encCert = Get-PrivateKeyCertificate
    if ($encCert -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        # Split by comma and try each block
        $blocks = $MessageSecure -split ','
        $lastError = $null
        foreach ($block in $blocks) {
            try {
                $block = $block.Trim()
                if ($block.StartsWith('-----BEGIN CMS-----')) {
                    # Strip PEM header/footer - Decode() expects the raw Base64 body
                    $block = $block -replace '-----BEGIN CMS-----', '' -replace '-----END CMS-----', '' -replace '[\r\n]', ''
                }
                $envCms = [System.Security.Cryptography.Pkcs.EnvelopedCms]::new()
                $envCms.Decode([Convert]::FromBase64String($block))
                # Parameterless Decrypt() locates the matching private key in the user store itself
                $envCms.Decrypt()
                $decrypted = [System.Text.Encoding]::UTF8.GetString($envCms.ContentInfo.Content)
                if ($null -ne $decrypted) {
                    return $decrypted
                }
            } catch {
                # The block may be encrypted for another certificate,
                # or the private key (e.g. on a hardware token) failed transiently - keep the real reason
                $lastError = $_.Exception.Message
            }
        }
        if ($lastError) {
            Write-Host "❌ Decryption error: $lastError" -ForegroundColor DarkGray
            # Drop the cached certificate: the key may be temporarily unavailable (token removed/re-inserted)
            # or the cached object stale - the next call must rescan the certificate store
            $Script:CachedPrivateKeyCert = $null
        }
    } else {
        Write-Host 'No certificate with private key' -ForegroundColor Yellow
    }

    Write-Statusbar 'Cannot decrypt password. No private key found or invalid format' 'red'
    Write-Host '❌ Cannot decrypt password. Check if certificate with private key is available' -ForegroundColor red
    return $null
}
function Get-SelectedUserCredential {
    # Must be initialized: an unset variable would be looked up in parent scopes and could return a stale row
    $selectedItem = $null
    if ($Script:UserDataGridView.SelectedRows.Count -gt 0) {
        $selectedItem = $Script:UserDataGridView.SelectedRows[0].DataBoundItem
    }

    if (-not $selectedItem) {
        Write-Statusbar 'No user selected in the grid.' 'red'
        return $null
    }

    $rawLogin = $selectedItem.Login
    $passwordEnc = $selectedItem.Password

    try {
        $plainPwd = Unprotect-RsaMessage -MessageSecure $passwordEnc
        if ($null -eq $plainPwd) { return $null }
        $securePwd = ConvertTo-SecureString -String $plainPwd -AsPlainText -Force
    } catch {
        Write-Statusbar "❌ Failed to decrypt password: $($_.Exception.Message)" 'red'
        return $null
    }

    $domain = ''
    $login = $rawLogin
    if ($rawLogin -match '^[^\\]+\\[^\\]+$') {
        $domain, $login = $rawLogin -split '\\', 2
    } elseif ($rawLogin -match '^[^@]+@[^@]+$') {
        $login, $domain = $rawLogin -split '@', 2
    }

    return [PSCustomObject]@{
        Domain = $domain
        Login = $login
        Password = $securePwd
        RawLogin = $rawLogin
    }
}

#endregion

#region Credential Manager Wrapper
function Save-NetworkCredentials {
    param(
        [Parameter(Mandatory = $true)][string]$ResourcePath,
        [Parameter(Mandatory = $true)][string]$Username,
        [Parameter(Mandatory = $true)][string]$Password,
        [int]$Type = 1,
        [int]$Persist = 1
    )

    # Create the manager first: if this fails, no unmanaged memory has been allocated yet
    $credManager = New-Object PSCredentialManager.Api.CredentialManager
    $nativeCred = New-Object PSCredentialManager.Common.NativeCredential
    $nativeCred.Flags = 0
    $nativeCred.Type = $Type
    $nativeCred.TargetName = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ResourcePath)
    $nativeCred.UserName = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($Username)

    $passwordBytes = [System.Text.Encoding]::Unicode.GetBytes("$Password`0")
    $passwordPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($passwordBytes.Length)
    [System.Runtime.InteropServices.Marshal]::Copy($passwordBytes, 0, $passwordPtr, $passwordBytes.Length)
    $nativeCred.CredentialBlob = $passwordPtr
    $nativeCred.CredentialBlobSize = $passwordBytes.Length
    $nativeCred.Persist = $Persist
    $nativeCred.AttributeCount = 0

    try {
        $null = $credManager.WriteCred($nativeCred)
        return $true
    } catch {
        Write-Host "❌ Can't save credentials: $($_.Exception.Message)" -ForegroundColor red
        return $false
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($nativeCred.TargetName)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($nativeCred.UserName)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($nativeCred.CredentialBlob)
    }
}

function Remove-NetworkCredentials {
    param([string]$ResourcePath)
    $credManager = New-Object PSCredentialManager.Api.CredentialManager
    try {
        $null = $credManager.DeleteCred($ResourcePath, 1)
        return $true
    } catch {
        Write-Host "❌ $($_.Exception.Message)"
        return $false
    }
}
#endregion

#region Execution & Connection Logic
function Invoke-TargetProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $false)][object[]]$ArgumentList = @(),
        [switch]$Elevated
    )

    $cred = Get-SelectedUserCredential
    if (-not $cred) { return }

    if ($Elevated) {
        $innerCmd = "Start-Process -FilePath `"$FilePath`""
        if ($ArgumentList) {
            $escapedArgs = @()
            foreach ($a in $ArgumentList) {
                # "" is the escape for a quote inside the double-quoted inner command (\" would break the parser)
                $escapedArgs += "`"$(($a -replace '"','""'))`""
            }
            $innerCmd += " -ArgumentList $($escapedArgs -join ' ')"
        }
        $innerCmd += ' -Verb RunAs'
        # -EncodedCommand avoids nested quoting issues ($, backtick, trailing backslash, quotes) on the outer command line
        $outerArgs = "-NoProfile -EncodedCommand $([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($innerCmd)))"

        $fullUser = if ($cred.Domain) { "$($cred.Domain)\$($cred.Login)" } else { $cred.Login }
        $psCred = [pscredential]::new($fullUser, $cred.Password)

        try {
            $null = Start-Process -FilePath 'powershell.exe' -Credential $psCred -ArgumentList $outerArgs -WindowStyle Hidden -PassThru
            Write-Host "🚀 $FilePath launched as $fullUser **elevated**." -ForegroundColor Green
            Write-Statusbar '🚀 Elevated start succeeded.' 'green'
        } catch {
            Write-Statusbar "❌ Error launching elevated process: $($_.Exception.Message)" 'red'
        }
    } else {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.UseShellExecute = $false
        $psi.LoadUserProfile = $true
        # EnvironmentVariables works in both Windows PowerShell 5.1 and PowerShell 7
        $psi.EnvironmentVariables['__COMPAT_LAYER'] = 'RunAsInvoker'
        $psi.Domain = $cred.Domain
        $psi.UserName = $cred.Login
        $psi.Password = $cred.Password
        $psi.FileName = $FilePath

        if ($ArgumentList) {
            $quotedArgs = @()
            foreach ($a in $ArgumentList) {
                if ($a -match '\s|["''`$]') { $quotedArgs += "`"$(($a -replace '"','\"'))`"" } else { $quotedArgs += $a }
            }
            $psi.Arguments = $quotedArgs -join ' '
        }

        try {
            $null = [System.Diagnostics.Process]::Start($psi)
            Write-Host "🚀 $FilePath started as $($cred.RawLogin) (RunAsInvoker)." -ForegroundColor Green
            Write-Statusbar '🚀 Normal start succeeded.' 'green'
        } catch {
            Write-Statusbar "❌ $($_.Exception.Message)" 'red'
        }
    }
}

function Connect-RdpSession {
    param([string]$Server)

    $cred = Get-SelectedUserCredential
    if (-not $cred) { return }

    if (-not $Server) {
        $Server = Show-InputBoxDialog -FormHeader 'RDP Connect' -RequestText 'Server FQDN or IP address:' -ConnectButtonCaption "Connect as $($cred.RawLogin)"
    }

    $universalServerPattern = '^(?:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$)|(?:^(?:(?!-)[a-zA-Z0-9-_]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)|(?:^(?!-)[a-zA-Z0-9-_]{1,63}(?<!-)$)'

    if ($Server -match $universalServerPattern) {
        # Decrypt SecureString and immediately zero the BSTR so the plain password does not linger in memory
        $pwdBSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
        try {
            $plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto($pwdBSTR)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pwdBSTR)
        }

        if (Save-NetworkCredentials -ResourcePath "TERMSRV/$($Server)" -Username $cred.RawLogin -Password $plainPwd -Type 1) {
            Write-Host '✅ Credentials saved for this session.' -ForegroundColor Green
            $RdpSettingsFile = Get-Item $Script:rdpFileFullPath -ErrorAction SilentlyContinue
            $rdpArgs = if ($RdpSettingsFile) { "`"$($RdpSettingsFile.Fullname)`" /v:$($Server)" } else { "/v:$($Server)" }

            $rdpProcess = Start-Process mstsc.exe -ArgumentList $rdpArgs -PassThru
            if ($rdpProcess -and $rdpProcess.Id -gt 0) {
                Write-Statusbar "✅ RDP process with $($Server) started" 'Green'

                # Using Forms.Timer because it works in UI thread
                $timer = New-Object System.Windows.Forms.Timer
                # 30 s instead of 5 s: mstsc may ask for credentials late (certificate prompt, slow logon screen)
                $timer.Interval = 30000

                # Save server to local variable
                $targetServer = $Server

                # Must use GetNewClosure() to capture $targetServer variable inside the script, otherwise it will also be $null
                $tickScript = {
                    try {
                        if (Remove-NetworkCredentials -ResourcePath "TERMSRV/$targetServer") {
                            Write-Host "✅ Credentials for $targetServer removed." -ForegroundColor Green
                        }
                    } catch {
                        Write-Host "❌ Error removing credentials: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    # $this refers to the timer that triggered the event
                    $this.Stop()
                    $this.Dispose()
                }

                $timer.Add_Tick($tickScript.GetNewClosure())
                $timer.Start()
                return $Server
            } else {
                Remove-NetworkCredentials -ResourcePath "TERMSRV/$($Server)"
                Write-Statusbar '❌ Cannot start RDP process' 'red'
            }
        } else {
            Write-Statusbar '❌ Cannot save RDP credentials.' 'red'
        }
    } elseif ($Server) {
        Write-Host "Server name '$Server' is incorrect."
    }
    return $null
}

function Connect-SmbShare {
    param([string]$ServerShare)

    $cred = Get-SelectedUserCredential
    if (-not $cred) { return }

    if (-not $ServerShare) {
        $ServerShare = Show-InputBoxDialog -FormHeader 'SMB Network Connection' -RequestText 'Server share path: (example \\server-1.domain.corp\c$)' -ConnectButtonCaption "Connect as $($cred.RawLogin)"
    }

    $uncPatternExtended = '^\\\\[^\\\/:*?"<>|\r\n]+(\\([^\\\/:*?"<>|\r\n]+))+$'
    if ($ServerShare -and $ServerShare -match $uncPatternExtended) {
        $credential = [pscredential]::new($cred.RawLogin, $cred.Password)
        # Remove a stale temp drive from a previous connection, if any
        $null = Remove-PSDrive -Name TempNetDrv -ErrorAction SilentlyContinue
        try {
            $null = New-PSDrive -Name TempNetDrv -PSProvider FileSystem -Root $ServerShare -Credential $credential -Persist:$false -ErrorAction Stop
            Write-Statusbar "✅ SMB Session to $($ServerShare) open." 'Green'
            Start-Process $ServerShare
            # Keep the drive alive so the authenticated SMB session stays open for Explorer
            return $ServerShare
        } catch {
            Write-Statusbar "❌ Cannot open SMB session: $($_.Exception.Message)" 'red'
            $null = Remove-PSDrive -Name TempNetDrv -ErrorAction SilentlyContinue
        }
    } elseif ($ServerShare) {
        Write-Host "Share path '$ServerShare' is incorrect."
    }
    return $null
}

function Update-HistoryMenu {
    param($MenuItem, [string]$Type)

    $MenuItem.DropDownItems.Clear()
    if ($Script:ConnectionHistory[$Type].Count -gt 0) {
        foreach ($item in $Script:ConnectionHistory[$Type].ToArray()) {
            $newItem = New-Object System.Windows.Forms.ToolStripMenuItem
            $newItem.Text = $item
            $newItem.Tag = $item
            $safeItem = $item -replace "'", "''"
            $handler = if ($Type -eq 'RDP') { "Connect-RdpSession '$safeItem'" } else { "Connect-SmbShare '$safeItem'" }
            $newItem.add_Click([ScriptBlock]::Create($handler))
            $null = $MenuItem.DropDownItems.Add($newItem)
        }
    }
}

function Add-ContextMenuItemFromIni {
    param($ParentMenuItem, $Prefix, $Action)

    # Convert delegate to string to use in handlers
    $actionString = $Action.ToString()

    for ($i = 0; $i -lt 20; $i++) {
        $currCMDVar = Get-Variable -Name "$Prefix-L$($i)" -Scope Script -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value
        if (-not $currCMDVar) { break }
        $MenuCMDArr = $currCMDVar -split ',', 3

        $submenuItem = [System.Windows.Forms.ToolStripMenuItem]::new()
        $submenuItem.Text = $MenuCMDArr[0]

        # Substitute values directly into script string
        $exePath = $MenuCMDArr[1]
        $exeArgs = $MenuCMDArr[2]
        # Escape single quotes so paths with apostrophes stay valid inside the generated script
        $scriptCode = "`$sb = [ScriptBlock]::Create('{0}'); & `$sb '{1}' '{2}'" -f ($actionString -replace "'", "''"), ($exePath -replace "'", "''"), ($exeArgs -replace "'", "''")

        $submenuItem.add_Click([ScriptBlock]::Create($scriptCode))
        $null = $ParentMenuItem.DropDownItems.Add($submenuItem)
    }

    $customItem = [System.Windows.Forms.ToolStripMenuItem]::new()
    $customItem.Text = '...'

    # Code for "..." button (manual file selection)
    $customItemCode = @"
`$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ InitialDirectory = [Environment]::GetFolderPath('Desktop') }
`$FileBrowser.ShowDialog() > `$null
if (`$FileBrowser.Filename) {
    `$fso = New-Object -ComObject Scripting.FileSystemObject
    `$selectedFileName = `$fso.getfile(`$FileBrowser.Filename).ShortPath
    `$sb = [ScriptBlock]::Create('$(($actionString -replace "'", "''"))')
    & `$sb `$selectedFileName
}
"@
    $customItem.add_Click([ScriptBlock]::Create($customItemCode))
    $null = $ParentMenuItem.DropDownItems.Add($customItem)
}
#endregion

#region Dialog UI Functions

function Show-EditDialog {
    param($Login, $Comment, $Password)

    $DialogProps = @{
        ClientSize = New-Object System.Drawing.Size(400, 130)
        FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        Text = 'Edit name and password'
        Font = $Script:FormFont
        # Center over the main window instead of the screen
        StartPosition = 'CenterParent'
    }
    $Dialog = New-Object System.Windows.Forms.Form -Property $DialogProps

    $LabelProps = @{
        AutoSize = $true
        Width = 25
        Height = 10
    }
    $Label1 = New-Object System.Windows.Forms.Label -Property ($LabelProps + @{Text = 'User Name:'; Location = New-Object System.Drawing.Point(5, 10) })
    $Label2 = New-Object System.Windows.Forms.Label -Property ($LabelProps + @{Text = 'Comment:'; Location = New-Object System.Drawing.Point(5, 35) })
    $Label3 = New-Object System.Windows.Forms.Label -Property ($LabelProps + @{Text = 'Password:'; Location = New-Object System.Drawing.Point(5, 60) })
    $Dialog.Controls.Add($Label1); $Dialog.Controls.Add($Label2); $Dialog.Controls.Add($Label3)

    $UserNameTextBox = New-Object System.Windows.Forms.TextBox -Property @{ Width = 250; Left = 130; Top = 10; Text = $Login }
    $CommentTextBox = New-Object System.Windows.Forms.TextBox -Property @{ Width = 250; Left = 130; Top = 35; Text = $Comment }
    $PasswordTextBox = New-Object System.Windows.Forms.TextBox -Property @{ Width = 250; Left = 130; Top = 60; Text = $Password; PasswordChar = '*' }
    $Dialog.Controls.Add($UserNameTextBox); $Dialog.Controls.Add($CommentTextBox); $Dialog.Controls.Add($PasswordTextBox)

    $PasswordTextBox.Add_Enter({ $this.PasswordChar = $null })
    $PasswordTextBox.Add_Leave({ $this.PasswordChar = '*' })

    $OKButton = New-Object System.Windows.Forms.Button -Property @{ Text = 'OK'; Left = 0; Top = 90; Height = 25 }
    $CancelButton = New-Object System.Windows.Forms.Button -Property @{ Text = 'Cancel'; Left = 75; Width = 100; Top = 90; Height = 25 }
    $OKButton.Add_Click({
            # "##" is the reserved Login/Comment separator in the storage format
            if ($UserNameTextBox.Text -match '##') {
                [System.Windows.Forms.MessageBox]::Show("User name must not contain '##' - reserved separator", 'Invalid user name', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            } else {
                $Dialog.DialogResult = [System.Windows.Forms.DialogResult]::OK
            }
        })
    $CancelButton.Add_Click({ $Dialog.DialogResult = [System.Windows.Forms.DialogResult]::Cancel })
    $Dialog.CancelButton = $CancelButton
    $Dialog.Controls.Add($OKButton); $Dialog.Controls.Add($CancelButton)

    $GenPWDButton = New-Object System.Windows.Forms.Button -Property @{ Text = 'Gen.pwd'; Left = 195; Width = 100; Top = 90; Height = 25 }
    $PwLenTextBox = New-Object System.Windows.Forms.TextBox -Property @{ Left = 305; Width = 40; Top = 90; Text = '18' }
    $GenPWDButton.Add_Click({
            # Validate the length box: a non-numeric value would otherwise throw inside the handler
            $pwdLen = 0
            if ([int]::TryParse($PwLenTextBox.Text, [ref]$pwdLen) -and $pwdLen -gt 0) {
                $PasswordTextBox.Text = $CommonObj.NewRandomPassword($pwdLen)
            } else {
                [System.Windows.Forms.MessageBox]::Show('Password length must be a positive number', 'Invalid length', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }
        })
    $Dialog.Controls.Add($GenPWDButton); $Dialog.Controls.Add($PwLenTextBox)

    # Owner makes the dialog modal to the main window and keeps it on top of it
    if ($Dialog.ShowDialog($Script:MainForm) -eq 'OK') {
        return [PSCustomObject]@{
            Login = $UserNameTextBox.Text
            Comment = $CommentTextBox.Text
            Password = $PasswordTextBox.Text
        }
    }
    return $null
}

function Show-InputBoxDialog {
    param($FormHeader, $RequestText, $ConnectButtonCaption)

    $form = New-Object System.Windows.Forms.Form -Property @{
        Font = $Script:FormFont
        Text = $FormHeader
        Size = New-Object Drawing.Size @(300, 180)
        # Center over the main window instead of the screen
        StartPosition = 'CenterParent'
    }

    $label = New-Object System.Windows.Forms.Label -Property @{ Location = New-Object Drawing.Point @(10, 20); Size = New-Object Drawing.Size @(280, 40); Text = $RequestText }
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox -Property @{ Location = New-Object Drawing.Point @(10, 60); Size = New-Object Drawing.Size @(260, 20) }
    $form.Controls.Add($textBox)

    $button = New-Object System.Windows.Forms.Button -Property @{ Location = New-Object System.Drawing.Point @(15, 85); Size = New-Object Drawing.Size @(240, 40); Text = $ConnectButtonCaption; DialogResult = [System.Windows.Forms.DialogResult]::OK }
    $form.AcceptButton = $button
    $form.Controls.Add($button)

    if ($form.ShowDialog($Script:MainForm) -eq [System.Windows.Forms.DialogResult]::OK) {
        return $textBox.Text.Trim()
    }
    return $null
}

function New-SelfSignedEncryptionCertificate {
    param([Parameter(Mandatory = $true)][string]$CommonName)

    # New-SelfSignedCertificate lives in the PKI module - import it explicitly
    # in case command auto-loading is disabled
    Import-Module PKI -ErrorAction SilentlyContinue
    try {
        # DocumentEncryptionCertLegacyCsp issues a certificate with the Document Encryption EKU;
        # the EKU is not strictly required anymore (EnvelopedCms works with any RSA cert),
        # but it is still useful for compatibility with Protect-CmsMessage on other machines.
        # The legacy CSP key format is the most compatible one for CMS encrypt/decrypt
        $newCert = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp `
            -Subject "CN=$CommonName" -FriendlyName $CommonName `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -NotAfter (Get-Date).AddYears(5) -KeyExportPolicy Exportable -ErrorAction Stop
        $CommonObj.LogInfo("Self-signed certificate issued: $($newCert.Subject) [$($newCert.Thumbprint)]")
        Write-Host "✅ Self-signed certificate issued: $($newCert.Subject) [$($newCert.Thumbprint)]" -ForegroundColor Green
        return $newCert.Thumbprint
    } catch {
        Write-Host "❌ Failed to issue self-signed certificate: $($_.Exception.Message)" -ForegroundColor Red
        [System.Windows.Forms.MessageBox]::Show("Failed to issue self-signed certificate: $($_.Exception.Message)", 'Error', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return $null
    }
}

function Select-CertificateGui {
    param([bool]$PrivateKeyOnly = $false)

    $Form = New-Object System.Windows.Forms.Form -Property @{
        ClientSize = New-Object System.Drawing.Size(660, 350)
        Text = 'Please choose the certificate to encrypt passwords with (Enter in Search box applies the filter)'
        Font = $Script:FormFont
    }

    $OKButton = New-Object System.Windows.Forms.Button -Property @{ Location = New-Object System.Drawing.Point(10, 315); Size = New-Object System.Drawing.Size(75, 30); Text = 'OK'; DialogResult = [System.Windows.Forms.DialogResult]::OK }
    $CancelButton = New-Object System.Windows.Forms.Button -Property @{ Location = New-Object System.Drawing.Point(90, 315); Size = New-Object System.Drawing.Size(80, 30); Text = 'Cancel'; DialogResult = [System.Windows.Forms.DialogResult]::Cancel }
    $NewCertButton = New-Object System.Windows.Forms.Button -Property @{ Location = New-Object System.Drawing.Point(180, 315); Size = New-Object System.Drawing.Size(200, 30); Text = 'Issue Self-Signed' }
    # No AcceptButton: Enter must not close the dialog (it is used for search only); Esc still cancels via CancelButton
    $Form.CancelButton = $CancelButton
    $Form.Controls.Add($OKButton); $Form.Controls.Add($CancelButton); $Form.Controls.Add($NewCertButton)

    $SearchTextBox = New-Object System.Windows.Forms.TextBox -Property @{ Location = New-Object System.Drawing.Point(5, 8); Size = New-Object System.Drawing.Size(400, 20) }
    $SearchLabel = New-Object System.Windows.Forms.Label -Property @{ AutoSize = $true; Location = New-Object System.Drawing.Point(415, 11); Text = 'Search + Enter' }
    $Form.Controls.Add($SearchTextBox); $Form.Controls.Add($SearchLabel)
    $CertDataGrid = New-Object System.Windows.Forms.DataGridView -Property @{
        AllowUserToResizeRows = $false; RowHeadersVisible = $false; AllowUserToAddRows = $false
        Location = New-Object Drawing.Point(5, 33); Size = New-Object Drawing.Point(650, 277)
        # Shared grid font
        Font = $Script:GridFont
        ReadOnly = $true; MultiSelect = $false; SelectionMode = 'FullRowSelect'
    }
    $Form.Controls.Add($CertDataGrid)
    $CertDataGrid.Add_MouseDoubleClick({ $Form.DialogResult = [System.Windows.Forms.DialogResult]::OK })
    $CertArrayLST = New-Object System.Collections.ArrayList
    $stores = if ($PrivateKeyOnly) { @('Cert:\CurrentUser\my') } else { @('Cert:\CurrentUser\my', 'Cert:\CurrentUser\AddressBook', 'Cert:\CurrentUser\TrustedPeople') }

    # Shared grid population logic: used on form load and after issuing a self-signed certificate
    $RefreshCertGrid = {
        $CertArrayLST.Clear()
        # Default EKU filter: certificates intended for encryption (email protection, EFS, document encryption)
        $encryptionEkus = @('1.3.6.1.5.5.7.3.4', '1.3.6.1.4.1.311.10.3.4', '1.3.6.1.4.1.311.80.1')
        $searchText = ''
        if ($SearchTextBox.Text) { $searchText = $SearchTextBox.Text.Trim() }
        foreach ($store in $stores) {
            foreach ($cert in (Get-ChildItem $store -ErrorAction SilentlyContinue)) {
                # Any RSA certificate can encrypt via EnvelopedCms, but by default only
                # certificates with an encryption-related EKU are shown
                if ($cert.PublicKey.Oid.FriendlyName -ne 'RSA') { continue }
                # A private key is required only for the storage owner certificate (PrivateKeyOnly mode);
                # recipient certificates may be public-only so the file can be shared with other users
                if ($PrivateKeyOnly -and -not $cert.HasPrivateKey) { continue }
                # The EKU filter is mandatory and cannot be lifted: authentication certificates rotate
                # automatically and would silently lock the user out of the stored passwords,
                # while email/document-encryption certificates are stable
                $ekuOids = @($cert.EnhancedKeyUsageList.ObjectId)
                $hasEncryptionEku = $false
                foreach ($eku in $encryptionEkus) { if ($ekuOids -contains $eku) { $hasEncryptionEku = $true; break } }
                if (-not $hasEncryptionEku) { continue }
                # Computed once: used both for the search haystack and the Name column
                $certDns = Get-CertificateDnsNames $cert
                if ($searchText) {
                    # Case-insensitive search over subject, DNS names and thumbprint (-notlike is case-insensitive)
                    $haystack = "$($cert.Subject) $certDns $($cert.Thumbprint)"
                    if ($haystack -notlike "*$searchText*") { continue }
                }
                # Project to the display columns right away: a raw X509Certificate2 from the Cert: provider
                # carries PSPath/PSParentPath etc., which ConvertToDataTable would turn into extra grid columns
                # Ekus shows the friendly names of all EKUs so the user sees why the certificate is listed
                $null = $CertArrayLST.Add([PSCustomObject]@{
                        Name = $certDns
                        NotBefore = $cert.NotBefore
                        NotAfter = $cert.NotAfter
                        Subject = $cert.Subject
                        Thumbprint = $cert.Thumbprint
                        Ekus = (@($cert.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join ', ')
                    })
            }
        }
        # ConvertToDataTable cannot infer a schema from an empty list - clear the grid so stale rows do not stay visible
        if ($CertArrayLST.Count -gt 0) {
            $CertDataGrid.DataSource = $CommonObj.ConvertToDataTable($CertArrayLST)
            Set-DataGridColumnWidth -DataGridView $CertDataGrid -Widths @(280, 120, 120, 320, 350, 180)
        } else {
            $CertDataGrid.DataSource = $null
        }
    }
    & $RefreshCertGrid
    $SearchTextBox.Add_KeyDown({
            # Enter applies the search filter; the dialog is not bound to an AcceptButton, so Enter never closes it
            if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
                & $RefreshCertGrid
            }
        })

    $NewCertButton.Add_Click({
            # Ask the user for the common name (CN) of the certificate to issue
            $certName = Show-InputBoxDialog -FormHeader 'New Self-Signed Certificate' -RequestText 'Certificate name (CN):' -ConnectButtonCaption 'Create certificate'
            if ([string]::IsNullOrWhiteSpace($certName)) { return }
            # These characters would break the X.500 subject syntax - reject them before issuing
            if ($certName -match '[,+"<>;\\]') {
                [System.Windows.Forms.MessageBox]::Show('Certificate name must not contain: comma, plus, quote, < > ; or backslash', 'Invalid name', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }
            $newThumbprint = New-SelfSignedEncryptionCertificate -CommonName $certName
            if (-not $newThumbprint) { return }
            # Reload the certificate list and preselect the freshly issued certificate
            & $RefreshCertGrid
            foreach ($row in $CertDataGrid.Rows) {
                if ($row.DataBoundItem -and "$($row.DataBoundItem.Thumbprint)" -eq $newThumbprint) {
                    $row.Selected = $true
                    $CertDataGrid.CurrentCell = $row.Cells[0]
                    break
                }
            }
            Write-Statusbar "Self-signed certificate '$certName' issued" 'green'
        })

    [void][System.Windows.Forms.Application]::EnableVisualStyles()
    # Center over the main window (or over the parent dialog when called from another dialog)
    $Form.StartPosition = 'CenterParent'
    if ($Form.ShowDialog($Script:MainForm) -eq 'OK' -and $CertDataGrid.SelectedRows.Count -gt 0) {
        return $CertDataGrid.SelectedRows[0].DataBoundItem.Thumbprint
    }
    return $null
}

#endregion

#region Data Serialization

function Get-SortedDataTable {
    param($DataGridView)
    if ($null -eq $DataGridView.DataSource) { return @() }
    # Return row views through a DataView: a DataTable object itself is not enumerated by the pipeline
    $dataView = New-Object System.Data.DataView($DataGridView.DataSource)
    if ($DataGridView.SortedColumn) {
        $sortDirection = $DataGridView.SortOrder.ToString()
        if ($sortDirection -eq 'Ascending') { $dataView.Sort = "$($DataGridView.SortedColumn.Name) ASC" }
        elseif ($sortDirection -eq 'Descending') { $dataView.Sort = "$($DataGridView.SortedColumn.Name) DESC" }
    }
    return @($dataView)
}

function Initialize-EmptyGrids {
    # Ensure both grids always have a DataTable with a valid schema:
    # clear an existing table or create a new one (ConvertToDataTable cannot infer columns from an empty list)
    if ($Script:CertificateDataGridView.DataSource -is [System.Data.DataTable]) {
        $Script:CertificateDataGridView.DataSource.Clear()
    } else {
        $certTable = New-Object System.Data.DataTable
        foreach ($colName in @('DnsNameList', 'NotBefore', 'NotAfter', 'Subject', 'Thumbprint')) { $null = $certTable.Columns.Add($colName) }
        $Script:CertificateDataGridView.DataSource = $certTable
    }
    if ($Script:UserDataGridView.DataSource -is [System.Data.DataTable]) {
        $Script:UserDataGridView.DataSource.Clear()
    } else {
        $userTable = New-Object System.Data.DataTable
        foreach ($colName in @('Login', 'Comment', 'Password')) { $null = $userTable.Columns.Add($colName) }
        $Script:UserDataGridView.DataSource = $userTable
    }
    Set-DataGridColumnWidth -DataGridView $Script:CertificateDataGridView -Widths @(260, 120, 120, 240, 250)
    Set-DataGridColumnWidth -DataGridView $Script:UserDataGridView -Widths @(240, 260, 0)
}

function Import-PasswordData {
    # Reset grids first: every early return below must leave a valid DataSource,
    # otherwise adding rows later silently does nothing
    Initialize-EmptyGrids
    if (-not (Test-Path $Script:PasswordDataFilePath)) {
        Write-Statusbar 'Empty project created. Right click to edit'
        return
    }

    $cliObj = Import-Clixml $Script:PasswordDataFilePath
    if ($cliObj.Version -ne 1) {
        Write-Statusbar "Cannot load $($Script:PasswordDataFilePath). Version is not supported" 'red'
        return
    }

    $Thumbprints = @($cliObj.Keys)
    if ($Thumbprints.Count -gt 0) {
        $Script:certThumbprint = $Thumbprints[0]
    } else {
        Write-Statusbar 'File contains no certificates (Keys is empty)' 'red'
        $Script:certThumbprint = ''
    }

    $allCerts = Find-CertificatesByThumbprints -Thumbprints $Thumbprints
    # One lookup table instead of a Where-Object scan per thumbprint (first match wins, like Select -First 1)
    $certByThumb = @{}
    foreach ($c in $allCerts) { if (-not $certByThumb.ContainsKey($c.Thumbprint)) { $certByThumb[$c.Thumbprint] = $c } }
    $allCertsLST = New-Object System.Collections.ArrayList

    $allCertsFoundFlag = $true
    foreach ($thumb in $Thumbprints) {
        $foundCert = $certByThumb[$thumb]
        if ($foundCert) {
            # Project the found certificate to the grid columns
            $null = $allCertsLST.Add([PSCustomObject]@{
                    DnsNameList = Get-CertificateDnsNames $foundCert
                    NotBefore = $foundCert.NotBefore
                    NotAfter = $foundCert.NotAfter
                    Subject = $foundCert.Subject
                    Thumbprint = $foundCert.Thumbprint
                })
        } else {
            # Create a stub with correct data types for missing certs
            $null = $allCertsLST.Add([PSCustomObject]@{
                    DnsNameList = '--- Missing Certificate ---'
                    NotBefore = [DateTime]::MinValue
                    NotAfter = [DateTime]::MinValue
                    Subject = "Missing certificate: $thumb"
                    Thumbprint = $thumb
                })
            $allCertsFoundFlag = $false
        }
    }

    if (-not $allCertsFoundFlag) {
        Write-Host '⚠️ Warning! Some certificates were not found.' -ForegroundColor yellow
    }

    # ConvertToDataTable cannot infer a schema from an empty list - keep the table created by Initialize-EmptyGrids
    if ($allCertsLST.Count -gt 0) {
        $Script:CertificateDataGridView.DataSource = $CommonObj.ConvertToDataTable($allCertsLST)
    }
    Set-DataGridColumnWidth -DataGridView $Script:CertificateDataGridView -Widths @(260, 120, 120, 240, 250)

    $decryptedNames = Unprotect-RsaMessage -MessageSecure $cliObj.Names
    if (-not $decryptedNames) {
        Write-Statusbar 'Error decrypting user names. No private key?' 'red'
        return
    }

    $UserArrayLST = New-Object System.Collections.ArrayList
    $namesLines = @($decryptedNames -split '\r\n')
    $pwdsArray = @($cliObj.PWDS)
    # Compare non-empty name lines only: an empty payload or a trailing CRLF yields one blank
    # line and would otherwise raise a false "file corrupted" warning for a valid file
    $nonEmptyNameLines = @($namesLines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($nonEmptyNameLines.Count -ne $pwdsArray.Count) {
        Write-Host "⚠️ Warning: users count ($($nonEmptyNameLines.Count)) does not match passwords count ($($pwdsArray.Count)). The file may be corrupted." -ForegroundColor Yellow
    }
    # Keep the PWDS index in sync with the Names line index; skip blank lines (e.g. a trailing CRLF)
    $i = 0
    foreach ($CMS in $namesLines) {
        $payload = $CMS -split '##', 2
        if (-not [string]::IsNullOrWhiteSpace($payload[0])) {
            $null = $UserArrayLST.Add(([PSCustomObject]@{
                        Login = $payload[0]
                        Comment = $payload[1]
                        Password = $pwdsArray[$i]
                    }))
        }
        $i++
    }

    # ConvertToDataTable cannot infer a schema from an empty list - keep the table created by Initialize-EmptyGrids
    if ($UserArrayLST.Count -gt 0) {
        $Script:UserDataGridView.DataSource = $CommonObj.ConvertToDataTable($UserArrayLST)
    }
    Set-DataGridColumnWidth -DataGridView $Script:UserDataGridView -Widths @(240, 260, 0)

    if (-not (Get-PrivateKeyCertificate)) {
        Write-Statusbar "$($Script:PasswordDataFilePath) loaded... No private key. Decryption impossible" 'red'
    } else {
        Write-Statusbar "$($Script:PasswordDataFilePath) loaded fine!" 'darkgreen'
    }
    return $true
}
#endregion

#region Main GUI
function Show-PasswordManagerGui {
    $FormProps = @{
        ClientSize = New-Object System.Drawing.Size(1000, 700)
        Text = "PWD manager v.$($Script:version)"
        Font = $Script:FormFont
        # Prevent window from being resized smaller than initial size
        MinimumSize = New-Object System.Drawing.Size(1020, 740)
    }
    $MainForm = New-Object System.Windows.Forms.Form -Property $FormProps
    # Remember the main form so child dialogs can be shown relative to it (CenterParent / ShowDialog owner)
    $Script:MainForm = $MainForm

    # --- Left bottom buttons (anchored to bottom and left) ---
    $SaveButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(5, 655); Size = New-Object System.Drawing.Size(70, 40); Text = 'Save XML'; Font = $Script:BoldFont
        Anchor = 'Bottom, Left'
    }
    $SaveButton.Add_Click({
            try {
                Write-Statusbar 'Saving...'
                $saveResult = Export-PasswordData

                if ($saveResult) {
                    $time = (Get-Date).ToString('HH:mm:ss')
                    Write-Statusbar "$Script:PasswordDataFilePath saved $time" 'green'
                    [console]::Beep(1000, 20)
                }
            } catch {
                Write-Statusbar "Error. $($_.Exception.Message)" 'red'
            }
        })
    $MainForm.Controls.Add($SaveButton)

    $LoadButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(85, 660); Size = New-Object System.Drawing.Size(70, 35); Text = "Load`r`nXML"
        Anchor = 'Bottom, Left'
    }
    $LoadButton.Add_Click({
            $dlg = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Title = 'Select password XML file'; Filter = 'XML Files (*.xml)|*.xml|All Files (*.*)|*.*'; InitialDirectory = [Environment]::GetFolderPath('MyDocuments') }
            if ($dlg.ShowDialog($MainForm) -eq [System.Windows.Forms.DialogResult]::OK) {
                $Script:PasswordDataFilePath = $dlg.FileName
                try {
                    # Import-PasswordData writes its own status message; log success to console only
                    if (Import-PasswordData) { Write-Host "✅ Loaded $($Script:PasswordDataFilePath)" -ForegroundColor Green }
                } catch {
                    Write-Statusbar "Error loading: $($_.Exception.Message)" 'red'
                }
            }
        })
    $MainForm.Controls.Add($LoadButton)

    $NewXmlButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(160, 660); Size = New-Object System.Drawing.Size(70, 35); Text = "New`r`nXML"
        Anchor = 'Bottom, Left'
    }
    $NewXmlButton.Add_Click({
            $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
            $folderBrowser.Description = 'Select folder for new password file'
            $folderBrowser.ShowNewFolderButton = $true

            if ($folderBrowser.ShowDialog($MainForm) -eq [System.Windows.Forms.DialogResult]::OK) {
                $folderPath = $folderBrowser.SelectedPath
                $fileName = 'secure_passwords_v1.xml'
                $newFilePath = Join-Path $folderPath $fileName

                if (Test-Path $newFilePath) {
                    $result = [System.Windows.Forms.MessageBox]::Show("File '$fileName' already exists. Overwrite?", 'Confirm Overwrite', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
                    if ($result -ne [System.Windows.Forms.DialogResult]::Yes) { return }
                }

                try {
                    $Script:CachedPrivateKeyCert = $null
                    $Script:CachedPrivateKeyCertKey = $null
                    $Script:certThumbprint = ''
                    Initialize-EmptyGrids
                    $Script:PasswordDataFilePath = $newFilePath
                    # The first certificate of a new file must have a private key, otherwise the file cannot be decrypted later
                    $Thumbprint = Select-CertificateGui -PrivateKeyOnly $true
                    if ($Thumbprint) { Add-CertificateToGrid -Thumbprint $Thumbprint }
                } catch {
                    [System.Windows.Forms.MessageBox]::Show("Error creating new file: $($_.Exception.Message)", 'Error', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                }
            }
        })
    $MainForm.Controls.Add($NewXmlButton)

    $PlusButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(245, 660); Size = New-Object System.Drawing.Size(30, 30); Text = '+'; Font = $Script:SignFont
        Anchor = 'Bottom, Left'
    }
    $PlusButton.Add_Click({
            $result = Show-EditDialog -Login '' -Comment '' -Password ''
            if ($result) {
                $dataTable = $Script:UserDataGridView.DataSource
                if ($dataTable -is [System.Data.DataTable]) {
                    $newRow = $dataTable.NewRow()
                    $newRow['Login'] = $result.Login
                    $newRow['Comment'] = $result.Comment
                    $encryptedPassword = Protect-PasswordForCurrentCertificates -PlainPassword $result.Password
                    if ($encryptedPassword) {
                        $newRow['Password'] = $encryptedPassword
                        $dataTable.Rows.Add($newRow)
                        $Script:UserDataGridView.Refresh()
                        Write-Statusbar 'Password added and encrypted for all certificates' 'green'
                    } else { Write-Statusbar 'Failed to encrypt password' 'red' }
                } else {
                    # Should not happen after Initialize-EmptyGrids, kept as a safety net
                    Write-Statusbar 'User table is not initialized' 'red'
                }
            }
        })
    $MainForm.Controls.Add($PlusButton)

    $minusButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(280, 660); Size = New-Object System.Drawing.Size(30, 30); Text = '-'; Font = $Script:SignFont
        Anchor = 'Bottom, Left'
    }
    $minusButton.Add_Click({
            foreach ($row in $Script:UserDataGridView.SelectedRows) {
                if ($row.DataBoundItem) { $row.DataBoundItem.Delete() }
            }
            $Script:UserDataGridView.Refresh()
        })
    $MainForm.Controls.Add($minusButton)

    # --- Status bar (anchored to bottom, stretches left and right) ---
    $Script:StatusBarTextBox = New-Object System.Windows.Forms.TextBox -Property @{
        Text = 'loading ...'; ReadOnly = $true; AutoSize = $false; Width = 670; Height = 40
        Location = New-Object System.Drawing.Point(320, 655); BackColor = 'white'
        Font = $Script:FormFont
        TextAlign = 'Center'; BorderStyle = 'None'; MultiLine = $true; ForeColor = 'blue'
        Anchor = 'Bottom, Left, Right'
    }
    $MainForm.Controls.Add($Script:StatusBarTextBox)

    # --- Certificate table (anchored to all edges, stretches down and right) ---
    $Script:CertificateDataGridView = New-Object System.Windows.Forms.DataGridView -Property @{
        AllowUserToResizeRows = $false; RowHeadersVisible = $false; AllowUserToAddRows = $false
        Location = New-Object Drawing.Point(510, 5); Size = New-Object Drawing.Size(485, 600)
        # Shared grid font (slightly smaller than the form font)
        Font = $Script:GridFont
        ReadOnly = $true; MultiSelect = $false; SelectionMode = 'FullRowSelect'
        Anchor = 'Top, Bottom, Left, Right'
    }
    $MainForm.Controls.Add($Script:CertificateDataGridView)

    # --- Certificate control buttons (anchored to bottom and right) ---
    $CertPlusButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(515, 615); Size = New-Object System.Drawing.Size(30, 30); Text = '+'; Font = $Script:SignFont
        Anchor = 'Bottom, Right'
    }
    $CertPlusButton.Add_Click({
            $Thumbprint = Select-CertificateGui
            if ($Thumbprint) { Add-CertificateToGrid -Thumbprint $Thumbprint }
        })
    $MainForm.Controls.Add($CertPlusButton)

    $CertMinusButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(550, 615); Size = New-Object System.Drawing.Size(30, 30); Text = '-'; Font = $Script:SignFont
        Anchor = 'Bottom, Right'
    }
    $CertMinusButton.Add_Click({
            foreach ($row in $Script:CertificateDataGridView.SelectedRows) {
                if ($row.DataBoundItem) { $row.DataBoundItem.Delete() }
            }
            $Script:CertificateDataGridView.Refresh()
        })
    $MainForm.Controls.Add($CertMinusButton)

    # --- User table (anchored to top, bottom and left, stretches only down) ---
    $Script:UserDataGridView = New-Object System.Windows.Forms.DataGridView -Property @{
        AllowUserToResizeRows = $false; RowHeadersVisible = $false; AllowUserToAddRows = $false
        Location = New-Object Drawing.Point(5, 5); Size = New-Object Drawing.Size(500, 640)
        # Shared grid font
        Font = $Script:GridFont
        ReadOnly = $true; MultiSelect = $false; SelectionMode = 'FullRowSelect'
        Anchor = 'Top, Bottom, Left'
    }
    $MainForm.Controls.Add($Script:UserDataGridView)

    # --- Context menu ---
    $contextMenuStrip = [System.Windows.Forms.ContextMenuStrip]@{ Font = $Script:FormFont }
    $Script:UserDataGridView.Add_CellMouseDown({
            # Right-click must select the row under the cursor before the menu opens,
            # otherwise menu actions would target a previously selected row (or none)
            if ($_.Button -eq [System.Windows.Forms.MouseButtons]::Right -and $_.RowIndex -ge 0) {
                $row = $Script:UserDataGridView.Rows[$_.RowIndex]
                if ($_.ColumnIndex -ge 0 -and $Script:UserDataGridView.Columns[$_.ColumnIndex].Visible) {
                    $Script:UserDataGridView.CurrentCell = $row.Cells[$_.ColumnIndex]
                }
                $row.Selected = $true
            }
        })
    $Script:UserDataGridView.Add_MouseClick({
            if ($_.Button -eq [System.Windows.Forms.MouseButtons]::Right) { $contextMenuStrip.Show([System.Windows.Forms.Cursor]::Position) }
        })

    $toolStripItemEdit = [System.Windows.Forms.ToolStripMenuItem]@{ Text = 'Edit' }
    $toolStripItemEdit.Add_Click({
            if ($Script:UserDataGridView.SelectedRows.Count -eq 0) { Write-Statusbar 'No user selected in the grid.' 'red'; return }
            $selectedItem = $Script:UserDataGridView.SelectedRows[0].DataBoundItem
            if (-not $selectedItem) { return }

            $plainPwd = Unprotect-RsaMessage -MessageSecure $selectedItem.Password

            if ($null -eq $plainPwd -and -not [string]::IsNullOrEmpty($selectedItem.Password)) {
                [System.Windows.Forms.MessageBox]::Show('Cannot decrypt current password. Editing blocked. Private key missing or invalid.', 'Error', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                return
            }

            $result = Show-EditDialog -Login $selectedItem.Login -Comment $selectedItem.Comment -Password $plainPwd
            if ($result) {
                $encryptedPassword = Protect-PasswordForCurrentCertificates -PlainPassword $result.Password
                if ($encryptedPassword) {
                    $selectedItem.Password = $encryptedPassword
                    $selectedItem.Comment = $result.Comment
                    $selectedItem.Login = $result.Login
                    $Script:UserDataGridView.Refresh()
                    Write-Statusbar 'Password updated and encrypted for all certificates' 'green'
                } else { Write-Statusbar 'Failed to encrypt password' 'red' }
            }
        })
    $contextMenuStrip.Items.Add($toolStripItemEdit) > $null

    $menuItemNormal = [System.Windows.Forms.ToolStripMenuItem]@{ Text = 'Run As Invoker' }
    $contextMenuStrip.Items.Add($menuItemNormal) > $null
    Add-ContextMenuItemFromIni -ParentMenuItem $menuItemNormal -Prefix 'INI-RunAsInvoker' -Action { param($f, $a) Invoke-TargetProcess -FilePath $f -ArgumentList $a }

    $menuItemElevated = [System.Windows.Forms.ToolStripMenuItem]@{ Text = 'Run ELEVATED' }
    $contextMenuStrip.Items.Add($menuItemElevated) > $null
    Add-ContextMenuItemFromIni -ParentMenuItem $menuItemElevated -Prefix 'INI-RunElevated' -Action { param($f, $a) Invoke-TargetProcess -FilePath $f -ArgumentList $a -Elevated }

    $RDPConnectTS = [System.Windows.Forms.ToolStripMenuItem]@{ Text = 'RDP connect as user'; Enabled = $Script:PSCredentialManagerDllLoaded }
    $contextMenuStrip.Items.Add($RDPConnectTS) > $null
    for ($i = 0; $i -lt 10; $i++) {
        $currCMDVar = Get-Variable -Name "INI-RDPConnectAsUser-L$($i)" -Scope Script -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value
        if (-not $currCMDVar) { break }
        $Script:ConnectionHistory.RDP.Enqueue($currCMDVar)
    }
    Update-HistoryMenu -MenuItem $RDPConnectTS -Type 'RDP'
    $RDPConnectTS.Add_Click({
            $result = Connect-RdpSession
            if ($result) {
                # Rebuild the queue without the existing entry so the menu shows no duplicates
                $dedupQueue = New-Object System.Collections.Queue
                while ($Script:ConnectionHistory.RDP.Count -gt 0) { $oldItem = $Script:ConnectionHistory.RDP.Dequeue(); if ($oldItem -ne $result) { $dedupQueue.Enqueue($oldItem) } }
                $Script:ConnectionHistory.RDP = $dedupQueue
                $Script:ConnectionHistory.RDP.Enqueue($result)
                while ($Script:ConnectionHistory.RDP.Count -gt 10) { $Script:ConnectionHistory.RDP.Dequeue() }
                Update-HistoryMenu -MenuItem $RDPConnectTS -Type 'RDP'
            }
        })

    $SMBConnectTS = [System.Windows.Forms.ToolStripMenuItem]@{ Text = 'SMB connect as user' }
    $contextMenuStrip.Items.Add($SMBConnectTS) > $null
    for ($i = 0; $i -lt 10; $i++) {
        $currCMDVar = Get-Variable -Name "INI-SMBConnectAsUser-L$($i)" -Scope Script -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value
        if (-not $currCMDVar) { break }
        $Script:ConnectionHistory.SMB.Enqueue($currCMDVar)
    }
    Update-HistoryMenu -MenuItem $SMBConnectTS -Type 'SMB'
    $SMBConnectTS.Add_Click({
            $result = Connect-SmbShare
            if ($result) {
                # Rebuild the queue without the existing entry so the menu shows no duplicates
                $dedupQueue = New-Object System.Collections.Queue
                while ($Script:ConnectionHistory.SMB.Count -gt 0) { $oldItem = $Script:ConnectionHistory.SMB.Dequeue(); if ($oldItem -ne $result) { $dedupQueue.Enqueue($oldItem) } }
                $Script:ConnectionHistory.SMB = $dedupQueue
                $Script:ConnectionHistory.SMB.Enqueue($result)
                while ($Script:ConnectionHistory.SMB.Count -gt 10) { $Script:ConnectionHistory.SMB.Dequeue() }
                Update-HistoryMenu -MenuItem $SMBConnectTS -Type 'SMB'
            }
        })

    $CpyUserNameTS = [System.Windows.Forms.ToolStripMenuItem]@{ Text = 'Copy user name' }
    $CpyUserNameTS.Add_Click({
            if ($Script:UserDataGridView.SelectedRows.Count -eq 0) { Write-Statusbar 'No user selected in the grid.' 'red'; return }
            $selectedItem = $Script:UserDataGridView.SelectedRows[0].DataBoundItem
            if (-not $selectedItem) { Write-Statusbar 'No user selected in the grid.' 'red'; return }
            try {
                Set-Clipboard -Value $selectedItem.Login -ErrorAction Stop
                Write-Statusbar 'User name copied to clipboard' 'green'
            } catch {
                Write-Statusbar "❌ Clipboard is busy, user name NOT copied: $($_.Exception.Message)" 'red'
            }
        })
    $contextMenuStrip.Items.Add($CpyUserNameTS) > $null

    $CpyPSWDTS = [System.Windows.Forms.ToolStripMenuItem]@{ Text = 'Copy password' }
    $CpyPSWDTS.Add_Click({
            if ($Script:UserDataGridView.SelectedRows.Count -eq 0) { Write-Statusbar 'No user selected in the grid.' 'red'; return }
            $selectedItem = $Script:UserDataGridView.SelectedRows[0].DataBoundItem
            if (-not $selectedItem) { Write-Statusbar 'No user selected in the grid.' 'red'; return }
            $plainPwd = $null
            # The first decryption after a long idle can fail transiently (hardware token waking up) - retry once
            foreach ($attempt in 1..2) {
                $plainPwd = Unprotect-RsaMessage -MessageSecure $selectedItem.Password
                if ($null -ne $plainPwd) { break }
                if ($attempt -eq 1) { Start-Sleep -Milliseconds 300 }
            }
            if ($null -eq $plainPwd) { Write-Statusbar "❌ Cannot decrypt password for $($selectedItem.Login)" 'red'; return }
            # The clipboard can be transiently busy (e.g. right after session unlock) - retry several times
            $copied = $false
            $lastError = $null
            foreach ($attempt in 1..5) {
                try {
                    Set-Clipboard -Value $plainPwd -ErrorAction Stop
                    $copied = $true
                    break
                } catch {
                    $lastError = $_.Exception.Message
                    Start-Sleep -Milliseconds 200
                }
            }
            if (-not $copied) { Write-Statusbar "❌ Clipboard is busy, password NOT copied: $lastError" 'red'; return }
            Write-Statusbar "Password of $($selectedItem.Login) copied. Clipboard clears in 30 sec." 'green'
            # Stop the previous clear timer so a stale timer cannot wipe a fresh copy of the same password
            if ($Script:PwdClearTimer) { $Script:PwdClearTimer.Stop(); $Script:PwdClearTimer.Dispose(); $Script:PwdClearTimer = $null }
            # Auto-clear the clipboard after 30 seconds unless the user copied something else
            $clearTimer = New-Object System.Windows.Forms.Timer
            $clearTimer.Interval = 30000
            $clearScript = {
                try {
                    # -ceq: case-sensitive compare; TrimEnd drops the newline some PowerShell versions append
                    if (("$(Get-Clipboard -Raw)").TrimEnd("`r", "`n") -ceq $plainPwd) {
                        Set-Clipboard -Value ''
                        # Notify the user: otherwise the stale "copied" message stays in the status bar
                        Write-Statusbar "Clipboard cleared (password of $($selectedItem.Login))" 'darkgray'
                    }
                } catch {
                    # Clipboard busy at clear time - skip clearing, the timer must still stop
                } finally {
                    $this.Stop(); $this.Dispose()
                    if ($Script:PwdClearTimer -eq $this) { $Script:PwdClearTimer = $null }
                }
            }
            $clearTimer.Add_Tick($clearScript.GetNewClosure())
            $Script:PwdClearTimer = $clearTimer
            $clearTimer.Start()
        })
    $contextMenuStrip.Items.Add($CpyPSWDTS) > $null

    # --- Load data ---
    try {
        Import-PasswordData
    } catch {
        Write-Statusbar "Error loading password data: $($_.Exception.Message)" 'red'
    }

    if ($Script:certThumbprint -eq '') {
        $Script:certThumbprint = Select-CertificateGui -PrivateKeyOnly $true
        Add-CertificateToGrid -Thumbprint $Script:certThumbprint
    }

    if ($null -eq $Script:certThumbprint) {
        Write-Host '❌ No certificate selected. Exit.' -ForegroundColor red
    } elseif ($Script:certThumbprint.Length -gt 20) {
        $MainForm.ShowDialog() | Out-Null
    }
}

function Add-CertificateToGrid {
    param([string]$Thumbprint)

    if (-not $Thumbprint) { return }
    $certificate = Find-CertificateByThumbprint -Thumbprints $Thumbprint
    if (-not $certificate) { return }

    # Manual cache reset in addition to the keyed cache: covers re-adding the same thumbprint
    # (e.g. after re-inserting a token), which alone does not change the cache key
    $Script:CachedPrivateKeyCert = $null
    $Script:certThumbprint = $Thumbprint
    $dataTable = $Script:CertificateDataGridView.DataSource
    if ($dataTable -is [System.Data.DataTable]) {
        $newRow = $dataTable.NewRow()
        $newRow['DnsNameList'] = Get-CertificateDnsNames $certificate
        $newRow['NotBefore'] = $certificate.NotBefore
        $newRow['NotAfter'] = $certificate.NotAfter
        $newRow['Subject'] = $certificate.Subject
        $newRow['Thumbprint'] = $certificate.Thumbprint
        $dataTable.Rows.Add($newRow)
        $Script:CertificateDataGridView.Refresh()
    } else {
        $Script:CertificateDataGridView.DataSource = $CommonObj.ConvertToDataTable(($certificate | Select-Object @{Name = 'DnsNameList'; Expression = { Get-CertificateDnsNames $_ } }, @{Name = 'NotBefore'; Expression = { $_.NotBefore } }, @{Name = 'NotAfter'; Expression = { $_.NotAfter } }, Subject, Thumbprint))
        Set-DataGridColumnWidth -DataGridView $Script:CertificateDataGridView -Widths @(260, 120, 120, 240, 250)
    }
}
function Export-PasswordData {
    $passwordsXML = [PSCustomObject]@{
        Version = 1
        Keys = @()
        Names = ''
        PWDS = @()
    }

    # 1. Get sorted lists of certificates and users from tables
    $certListSorted = Get-SortedDataTable -DataGridView $Script:CertificateDataGridView
    $userListSorted = Get-SortedDataTable -DataGridView $Script:UserDataGridView

    # Filter empty thumbprints and logins (ignore empty strings in tables)
    $targetThumbprints = @($certListSorted | Select-Object -ExpandProperty Thumbprint | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Select-Object -Unique)
    $targetUsers = @($userListSorted | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Login) })

    if ($targetThumbprints.Count -eq 0) {
        Write-Statusbar '❌ No certificates selected. Cannot save.' 'red'
        return $false
    }

    $droppedCount = @($userListSorted).Count - $targetUsers.Count
    if ($droppedCount -gt 0) {
        Write-Host "⚠️ Warning: $droppedCount row(s) with an empty Login will NOT be saved." -ForegroundColor Yellow
    }
    if ($targetUsers.Count -eq 0) {
        # Data-loss guard: an empty list would silently overwrite an existing file that still holds users
        # (e.g. after a failed import when the private key was unavailable)
        if (Test-Path -LiteralPath $Script:PasswordDataFilePath) {
            $answer = [System.Windows.Forms.MessageBox]::Show("The user list is empty. Saving will REPLACE the existing file '$Script:PasswordDataFilePath' (a .bak copy is kept). Continue?", 'Confirm saving an empty list', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) {
                Write-Statusbar 'Saving cancelled: the user list is empty' 'red'
                return $false
            }
        }
        Write-Statusbar 'Warning: No users in the list. Saving empty template...' 'darkgray'
    }

    # 2. Search for certificates in the system
    $passwordsXML.Keys = $targetThumbprints
    $foundCerts = Find-CertificatesByThumbprints -Thumbprints $targetThumbprints
    # One lookup table instead of a Where-Object scan per thumbprint (first match wins)
    $certByThumb = @{}
    foreach ($c in $foundCerts) { if (-not $certByThumb.ContainsKey($c.Thumbprint)) { $certByThumb[$c.Thumbprint] = $c } }

    # Reorder certificates to match the thumbprint order: Keys[i] must correspond to block i in Names and PWDS
    $targetCerts = @()
    foreach ($thumb in $targetThumbprints) {
        $cert = $certByThumb[$thumb]
        if ($cert) { $targetCerts += $cert }
    }

    # CRITICAL CHECK: If fewer certificates found than in grid
    if ($targetCerts.Count -lt $targetThumbprints.Count) {
        Write-Statusbar '❌ CRITICAL: Some certificates are missing (token not inserted?). Save ABORTED.' 'red'
        return $false
    }

    # 3. Prepare data (Login##Comment) for encryption.
    # Line breaks inside Login/Comment would break the CRLF-separated format, so they are replaced
    $payloadArray = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $targetUsers) {
        $safeLogin = $row.Login -replace '[\r\n]+', ''
        $safeComment = $row.Comment -replace '[\r\n]+', ' '
        $payloadArray.Add("$($safeLogin)##$($safeComment)")
    }
    $namesPayload = $payloadArray -join "`r`n"

    # 4. Encrypt user names for all certificates
    $namesCms = [System.Collections.Generic.List[string]]::new()
    foreach ($cert in $targetCerts) {
        $encryptedNames = Protect-RsaMessage -MessageText $namesPayload -Certificate $cert
        if ($encryptedNames) {
            $namesCms.Add($encryptedNames)
        } else {
            Write-Statusbar "❌ Failed to encrypt names for cert: $($cert.Thumbprint). Save ABORTED." 'red'
            return $false
        }
    }
    $passwordsXML.Names = $namesCms -join ','

    # 5. Password processing - always decrypt to memory and re-encrypt from scratch
    # List instead of += : avoids a full-array copy on every user row (O(n^2) in total)
    $pwdList = [System.Collections.Generic.List[string]]::new()

    foreach ($userRow in $targetUsers) {
        # Cast to a string: DBNull (e.g. after an incomplete import) passes IsNullOrEmpty and aborts the save
        $existingPassword = "$($userRow['Password'])"
        $plainPwd = ''

        if (-not [string]::IsNullOrEmpty($existingPassword)) {
            $plainPwd = Unprotect-RsaMessage -MessageSecure $existingPassword
            if ($null -eq $plainPwd) {
                Write-Statusbar "❌ CRITICAL: Cannot decrypt password for user '$($userRow['Login'])'. Save ABORTED." 'red'
                return $false
            }
        }

        $pwdCms = [System.Collections.Generic.List[string]]::new()
        foreach ($cert in $targetCerts) {
            $encryptedPwd = Protect-RsaMessage -MessageText $plainPwd -Certificate $cert
            if ($encryptedPwd) {
                $pwdCms.Add($encryptedPwd)
            } else {
                Write-Statusbar "❌ Failed to encrypt password for cert: $($cert.Thumbprint). Save ABORTED." 'red'
                return $false
            }
        }

        $pwdList.Add([string]($pwdCms -join ','))
    }
    $passwordsXML.PWDS = $pwdList.ToArray()

    # 6. Save to file
    try {
        if (Test-Path $Script:PasswordDataFilePath) {
            # Stop on backup failure: writing the new file without a backup risks data loss
            Copy-Item $Script:PasswordDataFilePath "$($Script:PasswordDataFilePath).bak" -Force -ErrorAction Stop
        }

        # Write to a temp file first: a failed write must not corrupt the existing data file
        $tempExportFile = "$($Script:PasswordDataFilePath).tmp"
        $passwordsXML | Export-Clixml $tempExportFile -Force
        Move-Item -LiteralPath $tempExportFile -Destination $Script:PasswordDataFilePath -Force
        Write-Statusbar "✅ $($Script:PasswordDataFilePath) saved successfully!" 'green'
        return $true
    } catch {
        Write-Statusbar "❌ Error saving file: $($_.Exception.Message)" 'red'
        return $false
    }
}
Write-Host "Password manager v.$($Script:version)."
Show-PasswordManagerGui