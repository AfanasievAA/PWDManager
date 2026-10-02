Param(
[Parameter(Mandatory=$false, Position=1)]
    [string]$PasswordDataFileName = $null
)
$Script:version = "1.11 (01 Oct 2026)"
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
..EXAMPLE
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

# Load Common Functions
Try {
    . "$Script:ScriptRootFolderRunPath\inc\Common_Functions.ps1"
} Catch {
    Write-Error "Error loading Common_Functions.ps1: $_"
    Exit 1
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

 $Script:iniFileFullPath = Get-SettingsFilePath "pwd_manager.ini"
 $Script:rdpFileFullPath = Get-SettingsFilePath "RDPSettings.rdp"
# A file name passed as a script parameter overrides the default search
if ([string]::IsNullOrWhiteSpace($PasswordDataFileName)) {
    $Script:PasswordDataFilePath = Get-SettingsFilePath "secure_passwords_v1.xml"
} else {
    $Script:PasswordDataFilePath = $PasswordDataFileName
}
# Load INI Configuration
 $CommonObj.LogInfo("Loading pwd_manager.ini...")
# ReadINIFileIfChanged: $true = file was (re)read, $false = unchanged since the last read, $null = file not found
 $iniFileIsRead = $Script:CommonObj.ReadINIFileIfChanged($Script:iniFileFullPath)
if ($true -eq $iniFileIsRead) {
    $CommonObj.LogInfo("pwd_manager.ini was loaded.", "-Fore DarkGray")
} elseif ($false -eq $iniFileIsRead) {
    $CommonObj.LogInfo("pwd_manager.ini unchanged since the last read, using cached settings.")
} else {
    $CommonObj.LogInfo("pwd_manager.ini not found, default settings are used.")
}


# Inline C# replacement for PSCredentialManager.Common.dll and PSCredentialManager.Api.dll.
# The code wraps the native Windows Credential Manager API (advapi32.dll), eliminating external DLL dependencies entirely.
 $Script:PSCredentialManagerDllLoaded = $false
Try {
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
    Write-Host "❌ PSCredentialManager inline compilation failed! RDP connections will not be available"
    Write-Host $_.Exception.Message -ForegroundColor DarkGray
}

Add-Type -AssemblyName System.Windows.Forms -ErrorAction stop
[void][System.Windows.Forms.Application]::EnableVisualStyles()

 $Script:certThumbprint = ""
 $Script:StatusBarTextBox = $null
 $Script:CachedPrivateKeyCert = $null
 $Script:ConnectionHistory = @{
    RDP = New-Object System.Collections.Queue
    SMB = New-Object System.Collections.Queue
}

#region Helper Functions

function Write-Statusbar {
    param([string]$Text, [string]$Color = "blue")
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
        return "No DNS Names"
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
    # Force cache reset when requesting new search
    $Script:CachedPrivateKeyCert = $null
    
    [array]$thumbprints = $null
    if ($Script:CertificateDataGridView -and $Script:CertificateDataGridView.DataSource) {
        # Enumerate DefaultView: piping a DataTable itself does not enumerate its rows
        $thumbprints = @($Script:CertificateDataGridView.DataSource.DefaultView | Select-Object -ExpandProperty Thumbprint)
    }
    if (-not $thumbprints -and $Script:certThumbprint) {
        $thumbprints = @($Script:certThumbprint)
    }

    if ($thumbprints) {
        $Script:CachedPrivateKeyCert = Find-CertificateByThumbprint -Thumbprints $thumbprints -HasPrivateKey $true
        if (-not $Script:CachedPrivateKeyCert) {
            Write-Statusbar "No private key found for the selected certificate" "red"
        }
        return $Script:CachedPrivateKeyCert
    }
    Write-Statusbar "No certificate thumbprints available" "red"
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
        Write-Host "❌ No certificate provided for encryption" -ForegroundColor red
        return $null 
    }

    $Content = Protect-CmsMessage -To $certToUse -Content $MessageText
    $Content = $Content -replace "[\r\n]", "" -Replace "-----BEGIN CMS-----", "" -Replace "-----END CMS-----", ""
    return $Content
}
function Protect-PasswordForCurrentCertificates {
    param([string]$PlainPassword)
    
    $encryptedBlocks = @()
    
    # Get all certificates from the grid
    if ($Script:CertificateDataGridView.DataSource -is [System.Data.DataTable]) {
        $dataTable = $Script:CertificateDataGridView.DataSource
        foreach ($row in $dataTable.Rows) {
            $thumbprint = $row["Thumbprint"]
            $cert = Find-CertificateByThumbprint -Thumbprints $thumbprint
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
        Write-Host "❌ Failed to encrypt password for any certificate" -ForegroundColor red
        return $null
    }
    
    return $encryptedBlocks -join ','
}

function Unprotect-RsaMessage {
    param([string]$MessageSecure)

    if ([string]::IsNullOrEmpty($MessageSecure)) {
        Write-Host "❌ Empty password string" -ForegroundColor red
        return $null
    }

    $encCert = Get-PrivateKeyCertificate
    if ($encCert -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        # Split by comma and try each block
        $blocks = $MessageSecure -split ","
        foreach ($block in $blocks) {
            Try {
                $block = $block.Trim()
                if (-not $block.StartsWith("-----BEGIN CMS-----")) {
                    $block = "-----BEGIN CMS-----$block-----END CMS-----"
                }
                $decrypted = UnProtect-CmsMessage -To $encCert -Content $block -ErrorAction Stop
                if ($null -ne $decrypted) {
                    return $decrypted
                }
            } Catch {
                # The block is encrypted for another certificate - keep trying the remaining blocks
            }
        }
    } else {
        Write-Host "No certificate with private key" -ForegroundColor Yellow
    }
    
    Write-Statusbar "Cannot decrypt password. No private key found or invalid format" "red"
    Write-Host "❌ Cannot decrypt password. Check if certificate with private key is available" -ForegroundColor red
    return $null
}
function Get-SelectedUserCredential {
    if ($Script:UserDataGridView.SelectedRows.Count -gt 0) {
        $selectedItem = $Script:UserDataGridView.SelectedRows[0].DataBoundItem
    }
    
    if (-not $selectedItem) {
        Write-Statusbar "No user selected in the grid." "red"
        return $null
    }
    
    $rawLogin = $selectedItem.Login
    $passwordEnc = $selectedItem.Password
    
    try {
        $plainPwd = Unprotect-RsaMessage -MessageSecure $passwordEnc
        if ($null -eq $plainPwd) { return $null }
        $securePwd = ConvertTo-SecureString -String $plainPwd -AsPlainText -Force
    } catch {
        Write-Statusbar "❌ Failed to decrypt password: $($_.Exception.Message)" "red"
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
        Domain   = $domain
        Login    = $login
        Password = $securePwd
        RawLogin = $rawLogin
    }
}

#endregion

#region Credential Manager Wrapper
function Save-NetworkCredentials {
    param(
        [Parameter(Mandatory=$true)][string]$ResourcePath,
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][string]$Password,
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
                $escapedArgs += "`"$(($a -replace '"','\"'))`""
            }
            $innerCmd += " -ArgumentList $($escapedArgs -join ' ')"
        }
        $innerCmd += " -Verb RunAs"
        $escapedInner = $innerCmd -replace '"','\"'
        $outerArgs = "-NoProfile -Command `"$escapedInner`""
        
        $fullUser = if ($cred.Domain) { "$($cred.Domain)\$($cred.Login)" } else { $cred.Login }
        $psCred = [pscredential]::new($fullUser, $cred.Password)
        
        try {
            $null = Start-Process -FilePath "powershell.exe" -Credential $psCred -ArgumentList $outerArgs -WindowStyle Hidden -PassThru
            Write-Host "🚀 $FilePath launched as $fullUser **elevated**." -ForegroundColor Green
            Write-Statusbar "🚀 Elevated start succeeded." "green"
        } catch {
            Write-Statusbar "❌ Error launching elevated process: $($_.Exception.Message)" "red"
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
            Write-Statusbar "🚀 Normal start succeeded." "green"
        } catch {
            Write-Statusbar "❌ $($_.Exception.Message)" "red"
        }
    }
}

function Connect-RdpSession {
    param([string]$Server)
    
    $cred = Get-SelectedUserCredential
    if (-not $cred) { return }
    
    if (-Not $Server) {
        $Server = Show-InputBoxDialog -FormHeader "RDP Connect" -RequestText "Server FQDN or IP address:" -ConnectButtonCaption "Connect as $($cred.RawLogin)"
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
            Write-Host "✅ Credentials saved for this session." -ForegroundColor Green
            $RdpSettingsFile = Get-Item $Script:rdpFileFullPath -ErrorAction SilentlyContinue
            $rdpArgs = if ($RdpSettingsFile) { "$($RdpSettingsFile.Fullname) /v:$($Server)" } else { "/v:$($Server)" }
            
            $rdpProcess = Start-Process mstsc.exe -ArgumentList $rdpArgs -PassThru
            if ($rdpProcess -and $rdpProcess.Id -gt 0) {
                Write-Statusbar "✅ RDP process with $($Server) started" "Green"
                
                # Using Forms.Timer because it works in UI thread
                $timer = New-Object System.Windows.Forms.Timer
                $timer.Interval = 5000
                
                # Save server to local variable
                $targetServer = $Server
                
                # Must use GetNewClosure() to capture $targetServer variable inside the script, otherwise it will also be $null
                $tickScript = {
                    Try {
                        if (Remove-NetworkCredentials -ResourcePath "TERMSRV/$targetServer") {
                            Write-Host "✅ Credentials for $targetServer removed." -ForegroundColor Green
                        }
                    } Catch { 
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
                Write-Statusbar "❌ Cannot start RDP process" "red"
            }
        } else {
            Write-Statusbar "❌ Cannot save RDP credentials." "red"
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
    
    if (-Not $ServerShare) {
        $ServerShare = Show-InputBoxDialog -FormHeader "SMB Network Connection" -RequestText "Server share path: (example \\server-1.domain.corp\c$)" -ConnectButtonCaption "Connect as $($cred.RawLogin)"
    }
    
    $uncPatternExtended = '^\\\\[^\\\/:*?"<>|\r\n]+(\\([^\\\/:*?"<>|\r\n]+))+$'
    if ($ServerShare -and $ServerShare -match $uncPatternExtended) {
        $credential = [pscredential]::new($cred.RawLogin, $cred.Password)
        # Remove a stale temp drive from a previous connection, if any
        $null = Remove-PSDrive -Name TempNetDrv -ErrorAction SilentlyContinue
        try {
            $null = New-PSDrive -Name TempNetDrv -PSProvider FileSystem -Root $ServerShare -Credential $credential -Persist:$false -ErrorAction Stop
            Write-Statusbar "✅ SMB Session to $($ServerShare) open." "Green"
            Start-Process $ServerShare
            # Keep the drive alive so the authenticated SMB session stays open for Explorer
            return $ServerShare
        } Catch {
            Write-Statusbar "❌ Cannot open SMB session: $($_.Exception.Message)" "red"
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
        if (-Not $currCMDVar) { break }
        $MenuCMDArr = $currCMDVar -split ",", 3
        
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
    `$sb = [ScriptBlock]::Create('$actionString')
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
        Font = New-Object System.Drawing.Font("Lucida Console",10,[System.Drawing.FontStyle]::Regular)
    }
    $Dialog = New-Object System.Windows.Forms.Form -Property $DialogProps
    
    $LabelProps = @{
        AutoSize = $true
        Width = 25
        Height = 10
    }
    $Label1 = New-Object System.Windows.Forms.Label -Property ($LabelProps + @{Text="User Name:"; Location=New-Object System.Drawing.Point(5,10)})
    $Label2 = New-Object System.Windows.Forms.Label -Property ($LabelProps + @{Text="Comment:"; Location=New-Object System.Drawing.Point(5,35)})
    $Label3 = New-Object System.Windows.Forms.Label -Property ($LabelProps + @{Text="Password:"; Location=New-Object System.Drawing.Point(5,60)})
    $Dialog.Controls.Add($Label1); $Dialog.Controls.Add($Label2); $Dialog.Controls.Add($Label3)
    
    $UserNameTextBox = New-Object System.Windows.Forms.TextBox -Property @{ Width=250; Left=130; Top=10; Text=$Login }
    $CommentTextBox = New-Object System.Windows.Forms.TextBox -Property @{ Width=250; Left=130; Top=35; Text=$Comment }
    $PasswordTextBox = New-Object System.Windows.Forms.TextBox -Property @{ Width=250; Left=130; Top=60; Text=$Password; PasswordChar="*" }
    $Dialog.Controls.Add($UserNameTextBox); $Dialog.Controls.Add($CommentTextBox); $Dialog.Controls.Add($PasswordTextBox)
    
    $PasswordTextBox.Add_Enter({ $this.PasswordChar = $null })
    $PasswordTextBox.Add_Leave({ $this.PasswordChar = '*' })
    
    $OKButton = New-Object System.Windows.Forms.Button -Property @{ Text="OK"; Left=0; Top=90; Height=25 }
    $CancelButton = New-Object System.Windows.Forms.Button -Property @{ Text="Cancel"; Left=75; Width=100; Top=90; Height=25 }
    $OKButton.Add_Click({
        # "##" is the reserved Login/Comment separator in the storage format
        if ($UserNameTextBox.Text -match '##') {
            [System.Windows.Forms.MessageBox]::Show("User name must not contain '##' - reserved separator", "Invalid user name", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        } else {
            $Dialog.DialogResult = [System.Windows.Forms.DialogResult]::OK
        }
    })
    $CancelButton.Add_Click({ $Dialog.DialogResult = [System.Windows.Forms.DialogResult]::Cancel })
    $Dialog.CancelButton = $CancelButton
    $Dialog.Controls.Add($OKButton); $Dialog.Controls.Add($CancelButton)
    
    $GenPWDButton = New-Object System.Windows.Forms.Button -Property @{ Text="Gen.pwd"; Left=195; Width=100; Top=90; Height=25 }
    $PwLenTextBox = New-Object System.Windows.Forms.TextBox -Property @{ Left=305; Width=40; Top=90; Text="18" }
    $GenPWDButton.Add_Click({
        # Validate the length box: a non-numeric value would otherwise throw inside the handler
        $pwdLen = 0
        if ([int]::TryParse($PwLenTextBox.Text, [ref]$pwdLen) -and $pwdLen -gt 0) {
            $PasswordTextBox.Text = $CommonObj.NewRandomPassword($pwdLen)
        } else {
            [System.Windows.Forms.MessageBox]::Show("Password length must be a positive number", "Invalid length", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        }
    })
    $Dialog.Controls.Add($GenPWDButton); $Dialog.Controls.Add($PwLenTextBox)
    
    if ($Dialog.ShowDialog() -eq "OK") {
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
        Font = New-Object System.Drawing.Font("Lucida Console",10,[System.Drawing.FontStyle]::Regular)
        Text = $FormHeader
        Size = New-Object Drawing.Size @(300,180)
        StartPosition = "WindowsDefaultLocation"
    }
    
    $label = New-Object System.Windows.Forms.Label -Property @{ Location=New-Object Drawing.Point @(10,20); Size=New-Object Drawing.Size @(280,40); Text=$RequestText }
    $form.Controls.Add($label)
    
    $textBox = New-Object System.Windows.Forms.TextBox -Property @{ Location=New-Object Drawing.Point @(10,60); Size=New-Object Drawing.Size @(260,20) }
    $form.Controls.Add($textBox)
    
    $button = New-Object System.Windows.Forms.Button -Property @{ Location=New-Object System.Drawing.Point @(15,85); Size=New-Object Drawing.Size @(240,40); Text=$ConnectButtonCaption; DialogResult=[System.Windows.Forms.DialogResult]::OK }
    $form.AcceptButton = $button
    $form.Controls.Add($button)
    
    if ($form.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $textBox.Text.Trim()
    }
    return $null
}

function Select-CertificateGui {
    param([bool]$PrivateKeyOnly = $false)
    
    $Form = New-Object System.Windows.Forms.Form -Property @{
        ClientSize = New-Object System.Drawing.Size(660, 350)
        Text = 'Please choose the certificate to encrypt passwords with'
        Font = New-Object System.Drawing.Font("Lucida Console",10,[System.Drawing.FontStyle]::Regular)
    }
    
    $OKButton = New-Object System.Windows.Forms.Button -Property @{ Location=New-Object System.Drawing.Point(10,315); Size=New-Object System.Drawing.Size(75,30); Text='OK'; DialogResult=[System.Windows.Forms.DialogResult]::OK }
    $CancelButton = New-Object System.Windows.Forms.Button -Property @{ Location=New-Object System.Drawing.Point(90,315); Size=New-Object System.Drawing.Size(80,30); Text='Cancel'; DialogResult=[System.Windows.Forms.DialogResult]::Cancel }
    $Form.AcceptButton = $OKButton; $Form.CancelButton = $CancelButton
    $Form.Controls.Add($OKButton); $Form.Controls.Add($CancelButton)
    
    $CertDataGrid = New-Object System.Windows.Forms.DataGridView -Property @{
        AllowUserToResizeRows = $false; RowHeadersVisible = $false; AllowUserToAddRows = $false
        Location = New-Object Drawing.Point(5,5); Size = New-Object Drawing.Point(650,305)
        ReadOnly = $true; MultiSelect = $false; SelectionMode = "FullRowSelect"
    }
    $Form.Controls.Add($CertDataGrid)
    $CertDataGrid.Add_MouseDoubleClick({ $Form.DialogResult = [System.Windows.Forms.DialogResult]::OK })
    
    $CertArrayLST = New-Object System.Collections.ArrayList
    $stores = if ($PrivateKeyOnly) { @("Cert:\CurrentUser\my") } else { @("Cert:\CurrentUser\my", "Cert:\CurrentUser\AddressBook", "Cert:\CurrentUser\TrustedPeople") }
    
    foreach ($store in $stores) {
        $certsFound = Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object {
            $_.EnhancedKeyUsageList.ObjectId -like "1.3.6.1.4.1.311.80.1" -and (-not $PrivateKeyOnly -or $_.HasPrivateKey)
        } | Select-Object @{Name='Name'; Expression={Get-CertificateDnsNames $_}}, NotBefore, NotAfter, Subject, Thumbprint
        
        if ($certsFound) {
            if ($certsFound.Count -gt 1) { $CertArrayLST.AddRange($certsFound) } else { $CertArrayLST.Add($certsFound) }
        }
    }
    
    $CertDataGrid.DataSource = $CommonObj.ConvertToDataTable($CertArrayLST)
    Set-DataGridColumnWidth -DataGridView $CertDataGrid -Widths @(280,120,120,320,350)
    
    [void][System.Windows.Forms.Application]::EnableVisualStyles()
    if ($Form.ShowDialog() -eq "OK" -and $CertDataGrid.SelectedRows.Count -gt 0) {
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
        foreach ($colName in @('DnsNameList','NotBefore','NotAfter','Subject','Thumbprint')) { $null = $certTable.Columns.Add($colName) }
        $Script:CertificateDataGridView.DataSource = $certTable
    }
    if ($Script:UserDataGridView.DataSource -is [System.Data.DataTable]) {
        $Script:UserDataGridView.DataSource.Clear()
    } else {
        $userTable = New-Object System.Data.DataTable
        foreach ($colName in @('Login','Comment','Password')) { $null = $userTable.Columns.Add($colName) }
        $Script:UserDataGridView.DataSource = $userTable
    }
    Set-DataGridColumnWidth -DataGridView $Script:CertificateDataGridView -Widths @(260,120,120,240,250)
    Set-DataGridColumnWidth -DataGridView $Script:UserDataGridView -Widths @(220,250,0)
}

function Import-PasswordData {
    # Reset grids first: every early return below must leave a valid DataSource,
    # otherwise adding rows later silently does nothing
    Initialize-EmptyGrids
    if (-not (Test-Path $Script:PasswordDataFilePath)) {
        Write-Statusbar "Empty project created. Right click to edit"
        return
    }
    
    $cliObj = Import-Clixml $Script:PasswordDataFilePath
    if ($cliObj.Version -ne 1) {
        Write-Statusbar "Cannot load $($Script:PasswordDataFilePath). Version is not supported" "red"
        return
    }
    
    $Thumbprints = @($cliObj.Keys)
    if ($Thumbprints.Count -gt 0) {
        $Script:certThumbprint = $Thumbprints[0]
    } else {
        Write-Statusbar "File contains no certificates (Keys is empty)" "red"
        $Script:certThumbprint = ""
    }
    
    $allCerts = Find-CertificatesByThumbprints -Thumbprints $Thumbprints
    $allCertsLST = New-Object System.Collections.ArrayList
    
    $allCertsFoundFlag = $true
    foreach ($thumb in $Thumbprints) {
        # Search for certificate in found array
        $foundCert = $allCerts | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object @{Name='DnsNameList'; Expression={Get-CertificateDnsNames $_}}, @{Name='NotBefore'; Expression={$_.NotBefore}}, @{Name='NotAfter'; Expression={$_.NotAfter}}, Subject, Thumbprint -First 1
        if ($foundCert) {
            $null = $allCertsLST.Add($foundCert)
        } else {
            # Create a stub with correct data types for missing certs
            $null = $allCertsLST.Add([PSCustomObject]@{
                DnsNameList = "--- Missing Certificate ---"
                NotBefore   = [DateTime]::MinValue
                NotAfter    = [DateTime]::MinValue
                Subject     = "Missing certificate: $thumb"
                Thumbprint  = $thumb
            })
            $allCertsFoundFlag = $false
        }
    }    
    
    if (-Not $allCertsFoundFlag) {
        Write-Host "⚠️ Warning! Some certificates were not found." -ForegroundColor yellow
    }
    
    # ConvertToDataTable cannot infer a schema from an empty list - keep the table created by Initialize-EmptyGrids
    if ($allCertsLST.Count -gt 0) {
        $Script:CertificateDataGridView.DataSource = $CommonObj.ConvertToDataTable($allCertsLST)
    }
    Set-DataGridColumnWidth -DataGridView $Script:CertificateDataGridView -Widths @(260,120,120,240,250)
    
    $decryptedNames = Unprotect-RsaMessage -MessageSecure $cliObj.Names
    if (-not $decryptedNames) {
        Write-Statusbar "Error decrypting user names. No private key?" "red"
        return
    }
    
    $UserArrayLST = New-Object System.Collections.ArrayList
    $namesLines = @($decryptedNames -split "\r\n")
    $pwdsArray = @($cliObj.PWDS)
    if ($namesLines.Count -ne $pwdsArray.Count) {
        Write-Host "⚠️ Warning: users count ($($namesLines.Count)) does not match passwords count ($($pwdsArray.Count)). The file may be corrupted." -ForegroundColor Yellow
    }
    # Keep the PWDS index in sync with the Names line index; skip blank lines (e.g. a trailing CRLF)
    $i = 0
    foreach ($CMS in $namesLines) {
        $payload = $CMS -split "##", 2
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
    Set-DataGridColumnWidth -DataGridView $Script:UserDataGridView -Widths @(220,250,0)
    
    if (-not (Get-PrivateKeyCertificate)) {
        Write-Statusbar "$($Script:PasswordDataFilePath) loaded... No private key. Decryption impossible" "red"
    } else {
        Write-Statusbar "$($Script:PasswordDataFilePath) loaded fine!" "darkgreen"
    }
    return $true
}
#endregion

#region Main GUI
function Show-PasswordManagerGui {
    $FormProps = @{
        ClientSize = New-Object System.Drawing.Size(800, 560)
        Text = "PWD manager v.$($Script:version)"
        Font = New-Object System.Drawing.Font("Lucida Console",10,[System.Drawing.FontStyle]::Regular)
        # Prevent window from being resized smaller than initial size
        MinimumSize = New-Object System.Drawing.Size(820, 600)
    }
    $MainForm = New-Object System.Windows.Forms.Form -Property $FormProps
    
    # --- Left bottom buttons (anchored to bottom and left) ---
    $SaveButton = New-Object System.Windows.Forms.Button -Property @{ 
        Location=New-Object System.Drawing.Point(5,515); Size=New-Object System.Drawing.Size(70,40); Text="Save XML"; Font=New-Object System.Drawing.Font("Lucida Console",10,[System.Drawing.FontStyle]::Bold)
        Anchor = 'Bottom, Left'
    }
    $SaveButton.Add_Click({
        Try {
            Write-Statusbar "Saving..."
            $saveResult = Export-PasswordData

            if ($saveResult) {
                $time = (Get-Date).ToString('HH:mm:ss')
                Write-Statusbar "$Script:PasswordDataFilePath saved $time" "green"
                [console]::Beep(1000,20)
            } 
        } Catch {
            Write-Statusbar "Error. $($_.Exception.Message)" "red"
        }
    })
    $MainForm.Controls.Add($SaveButton)
        
    $LoadButton = New-Object System.Windows.Forms.Button -Property @{ 
        Location=New-Object System.Drawing.Point(80,520); Size=New-Object System.Drawing.Size(70,35); Text="Load`r`nXML"
        Anchor = 'Bottom, Left'
    }
    $LoadButton.Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Title='Select password XML file'; Filter='XML Files (*.xml)|*.xml|All Files (*.*)|*.*'; InitialDirectory=[Environment]::GetFolderPath('MyDocuments') }
        if($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){
            $Script:PasswordDataFilePath = $dlg.FileName
            try {
                # Import-PasswordData writes its own status message; log success to console only
                if (Import-PasswordData) { Write-Host "✅ Loaded $($Script:PasswordDataFilePath)" -ForegroundColor Green }
            } catch {
                Write-Statusbar "Error loading: $($_.Exception.Message)" "red"
            }
        }
    })
    $MainForm.Controls.Add($LoadButton)
    
    $NewXmlButton = New-Object System.Windows.Forms.Button -Property @{ 
        Location=New-Object System.Drawing.Point(155,520); Size=New-Object System.Drawing.Size(70,35); Text="New`r`nXML"
        Anchor = 'Bottom, Left'
    }
    $NewXmlButton.Add_Click({
        $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowser.Description = "Select folder for new password file"
        $folderBrowser.ShowNewFolderButton = $true
        
        if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $folderPath = $folderBrowser.SelectedPath
            $fileName = "secure_passwords_v1.xml"
            $newFilePath = Join-Path $folderPath $fileName
            
            if (Test-Path $newFilePath) {
                $result = [System.Windows.Forms.MessageBox]::Show("File '$fileName' already exists. Overwrite?", "Confirm Overwrite", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
                if ($result -ne [System.Windows.Forms.DialogResult]::Yes) { return }
            }
            
            try {
                $Script:CachedPrivateKeyCert = $null
                $Script:certThumbprint = ""
                Initialize-EmptyGrids
                $Script:PasswordDataFilePath = $newFilePath
                $Thumbprint = Select-CertificateGui
                if ($Thumbprint) { Add-CertificateToGrid -Thumbprint $Thumbprint }
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Error creating new file: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    })
    $MainForm.Controls.Add($NewXmlButton)
    
    $PlusButton = New-Object System.Windows.Forms.Button -Property @{ 
        Location=New-Object System.Drawing.Point(245,520); Size=New-Object System.Drawing.Size(30,30); Text='+'; Font=New-Object System.Drawing.Font("Lucida Console",16,[System.Drawing.FontStyle]::Bold)
        Anchor = 'Bottom, Left'
    }
    $PlusButton.Add_Click({
        $result = Show-EditDialog -Login "" -Comment "" -Password ""
        if ($result) {
            $dataTable = $Script:UserDataGridView.DataSource
            if ($dataTable -is [System.Data.DataTable]) {
                $newRow = $dataTable.NewRow()
                $newRow["Login"] = $result.Login
                $newRow["Comment"] = $result.Comment
                $encryptedPassword = Protect-PasswordForCurrentCertificates -PlainPassword $result.Password
                if ($encryptedPassword) {
                    $newRow["Password"] = $encryptedPassword
                    $dataTable.Rows.Add($newRow)
                    $Script:UserDataGridView.Refresh()
                    Write-Statusbar "Password added and encrypted for all certificates" "green"
                } else { Write-Statusbar "Failed to encrypt password" "red" }
            } else {
                # Should not happen after Initialize-EmptyGrids, kept as a safety net
                Write-Statusbar "User table is not initialized" "red"
            }
        }
    })
    $MainForm.Controls.Add($PlusButton)
    
    $minusButton = New-Object System.Windows.Forms.Button -Property @{ 
        Location=New-Object System.Drawing.Point(280,520); Size=New-Object System.Drawing.Size(30,30); Text='-'; Font=New-Object System.Drawing.Font("Lucida Console",16,[System.Drawing.FontStyle]::Bold)
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
        Text = "loading ..."; ReadOnly = $true; AutoSize = $false; Width = 470; Height = 40
        Location = New-Object System.Drawing.Point(320,515); BackColor = 'white'
        Font = New-Object System.Drawing.Font("Courier New",10,[System.Drawing.FontStyle]::Regular)
        TextAlign = 'Center'; BorderStyle = 'None'; MultiLine = $true; ForeColor = 'blue'
        Anchor = 'Bottom, Left, Right'
    }
    $MainForm.Controls.Add($Script:StatusBarTextBox)
    
    # --- Certificate table (anchored to all edges, stretches down and right) ---
    $Script:CertificateDataGridView = New-Object System.Windows.Forms.DataGridView -Property @{
        AllowUserToResizeRows = $false; RowHeadersVisible = $false; AllowUserToAddRows = $false
        Location = New-Object Drawing.Point(435,5); Size = New-Object Drawing.Size(360,475)
        ReadOnly = $true; MultiSelect = $false; SelectionMode = "FullRowSelect"
        Anchor = 'Top, Bottom, Left, Right'
    }
    $MainForm.Controls.Add($Script:CertificateDataGridView)
    
    # --- Certificate control buttons (anchored to bottom and right) ---
    $CertPlusButton = New-Object System.Windows.Forms.Button -Property @{ 
        Location=New-Object System.Drawing.Point(440,480); Size=New-Object System.Drawing.Size(30,30); Text='+'; Font=New-Object System.Drawing.Font("Lucida Console",16,[System.Drawing.FontStyle]::Bold)
        Anchor = 'Bottom, Right'
    }
    $CertPlusButton.Add_Click({
        $Thumbprint = Select-CertificateGui
        if ($Thumbprint) { Add-CertificateToGrid -Thumbprint $Thumbprint }
    })
    $MainForm.Controls.Add($CertPlusButton)
    
    $CertMinusButton = New-Object System.Windows.Forms.Button -Property @{ 
        Location=New-Object System.Drawing.Point(470,480); Size=New-Object System.Drawing.Size(30,30); Text='-'; Font=New-Object System.Drawing.Font("Lucida Console",16,[System.Drawing.FontStyle]::Bold)
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
        Location = New-Object Drawing.Point(5,5); Size = New-Object Drawing.Size(430,505)
        ReadOnly = $true; MultiSelect = $false; SelectionMode = "FullRowSelect"
        Anchor = 'Top, Bottom, Left'
    }
    $MainForm.Controls.Add($Script:UserDataGridView)
    
    # --- Context menu ---
    $contextMenuStrip = [System.Windows.Forms.ContextMenuStrip]@{ Font = New-Object System.Drawing.Font("Courier New",10,[System.Drawing.FontStyle]::Regular) }
    $Script:UserDataGridView.Add_MouseClick({
        if ($_.Button -eq [System.Windows.Forms.MouseButtons]::Right){ $contextMenuStrip.Show([System.Windows.Forms.Cursor]::Position) }
    })
    
    $toolStripItemEdit = [System.Windows.Forms.ToolStripMenuItem]@{ Text = "Edit" }
    $toolStripItemEdit.Add_Click({
        if ($Script:UserDataGridView.SelectedRows.Count -eq 0) { return }
        $selectedItem = $Script:UserDataGridView.SelectedRows[0].DataBoundItem
        if (-not $selectedItem) { return }

        $plainPwd = Unprotect-RsaMessage -MessageSecure $selectedItem.Password
        
        if ($null -eq $plainPwd -and -not [string]::IsNullOrEmpty($selectedItem.Password)) {
            [System.Windows.Forms.MessageBox]::Show("Cannot decrypt current password. Editing blocked. Private key missing or invalid.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
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
                Write-Statusbar "Password updated and encrypted for all certificates" "green"
            } else { Write-Statusbar "Failed to encrypt password" "red" }
        }
    })
    $contextMenuStrip.Items.Add($toolStripItemEdit) > $null
    
    $menuItemNormal = [System.Windows.Forms.ToolStripMenuItem]@{ Text = 'Run As Invoker' }
    $contextMenuStrip.Items.Add($menuItemNormal) > $null
    Add-ContextMenuItemFromIni -ParentMenuItem $menuItemNormal -Prefix "INI-RunAsInvoker" -Action { param($f, $a) Invoke-TargetProcess -FilePath $f -ArgumentList $a }
    
    $menuItemElevated = [System.Windows.Forms.ToolStripMenuItem]@{ Text = 'Run ELEVATED' }
    $contextMenuStrip.Items.Add($menuItemElevated) > $null
    Add-ContextMenuItemFromIni -ParentMenuItem $menuItemElevated -Prefix "INI-RunElevated" -Action { param($f, $a) Invoke-TargetProcess -FilePath $f -ArgumentList $a -Elevated }
    
    $RDPConnectTS = [System.Windows.Forms.ToolStripMenuItem]@{ Text = "RDP connect as user"; Enabled = $Script:PSCredentialManagerDllLoaded }
    $contextMenuStrip.Items.Add($RDPConnectTS) > $null
    for ($i=0; $i -lt 10; $i++) {
        $currCMDVar = Get-Variable -Name "INI-RDPConnectAsUser-L$($i)" -Scope Script -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value
        if (-Not $currCMDVar) { break }
        $Script:ConnectionHistory.RDP.Enqueue($currCMDVar)
    }
    Update-HistoryMenu -MenuItem $RDPConnectTS -Type 'RDP'
    $RDPConnectTS.Add_Click({
        $result = Connect-RdpSession
        if ($result) {
            $Script:ConnectionHistory.RDP.Enqueue($result)
            while ($Script:ConnectionHistory.RDP.Count -gt 10) { $Script:ConnectionHistory.RDP.Dequeue() }
            Update-HistoryMenu -MenuItem $RDPConnectTS -Type 'RDP'
        }
    })
    
    $SMBConnectTS = [System.Windows.Forms.ToolStripMenuItem]@{ Text = "SMB connect as user" }
    $contextMenuStrip.Items.Add($SMBConnectTS) > $null
    for ($i=0; $i -lt 10; $i++) {
        $currCMDVar = Get-Variable -Name "INI-SMBConnectAsUser-L$($i)" -Scope Script -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Value
        if (-Not $currCMDVar) { break }
        $Script:ConnectionHistory.SMB.Enqueue($currCMDVar)
    }
    Update-HistoryMenu -MenuItem $SMBConnectTS -Type 'SMB'
    $SMBConnectTS.Add_Click({
        $result = Connect-SmbShare
        if ($result) {
            $Script:ConnectionHistory.SMB.Enqueue($result)
            while ($Script:ConnectionHistory.SMB.Count -gt 10) { $Script:ConnectionHistory.SMB.Dequeue() }
            Update-HistoryMenu -MenuItem $SMBConnectTS -Type 'SMB'
        }
    })
    
    $CpyUserNameTS = [System.Windows.Forms.ToolStripMenuItem]@{ Text = "Copy user name" }
    $CpyUserNameTS.Add_Click({
        if ($Script:UserDataGridView.SelectedRows.Count -eq 0) { return }
        $selectedItem = $Script:UserDataGridView.SelectedRows[0].DataBoundItem
        if ($selectedItem) { Set-Clipboard -Value $selectedItem.Login }
    })
    $contextMenuStrip.Items.Add($CpyUserNameTS) > $null
    
    $CpyPSWDTS = [System.Windows.Forms.ToolStripMenuItem]@{ Text = "Copy password" }
    $CpyPSWDTS.Add_Click({
        if ($Script:UserDataGridView.SelectedRows.Count -eq 0) { return }
        $selectedItem = $Script:UserDataGridView.SelectedRows[0].DataBoundItem
        if ($selectedItem) {
            $plainPwd = Unprotect-RsaMessage -MessageSecure $selectedItem.Password
            if ($null -ne $plainPwd) {
                Set-Clipboard -Value $plainPwd
                # Auto-clear the clipboard after 30 seconds unless the user copied something else
                $clearTimer = New-Object System.Windows.Forms.Timer
                $clearTimer.Interval = 30000
                $clearScript = { if ((Get-Clipboard -Raw) -eq $plainPwd) { Set-Clipboard -Value '' }; $this.Stop(); $this.Dispose() }
                $clearTimer.Add_Tick($clearScript.GetNewClosure())
                $clearTimer.Start()
            }
        }
    })
    $contextMenuStrip.Items.Add($CpyPSWDTS) > $null
    
    # --- Load data ---
    Try {
        Import-PasswordData
    } Catch {
        Write-Statusbar "Error loading password data: $($_.Exception.Message)" "red"
    }
    
    if ($Script:certThumbprint -eq "") {
        $Script:certThumbprint = Select-CertificateGui -PrivateKeyOnly $true
        Add-CertificateToGrid -Thumbprint $Script:certThumbprint
    }
    
    if ($null -eq $Script:certThumbprint) {
        Write-Host "❌ No certificate selected. Exit." -ForegroundColor red
    } elseif ($Script:certThumbprint.Length -gt 20) {
        $MainForm.ShowDialog() | Out-Null
    }
}

function Add-CertificateToGrid {
    param([string]$Thumbprint)
    
    if (-not $Thumbprint) { return }
    $certificate = Find-CertificateByThumbprint -Thumbprints $Thumbprint
    if (-not $certificate) { return }
    
    # Reset cache when adding new certificate
    $Script:CachedPrivateKeyCert = $null
    $Script:certThumbprint = $Thumbprint
    $dataTable = $Script:CertificateDataGridView.DataSource
    if ($dataTable -is [System.Data.DataTable]) {
        $newRow = $dataTable.NewRow()
        $newRow["DnsNameList"] = Get-CertificateDnsNames $certificate
        $newRow["NotBefore"] = $certificate.NotBefore
        $newRow["NotAfter"] = $certificate.NotAfter
        $newRow["Subject"] = $certificate.Subject
        $newRow["Thumbprint"] = $certificate.Thumbprint
        $dataTable.Rows.Add($newRow)
        $Script:CertificateDataGridView.Refresh()
    } else {
        $Script:CertificateDataGridView.DataSource = $CommonObj.ConvertToDataTable(($certificate | Select-Object @{Name='DnsNameList'; Expression={Get-CertificateDnsNames $_}}, @{Name='NotBefore'; Expression={$_.NotBefore}}, @{Name='NotAfter'; Expression={$_.NotAfter}}, Subject, Thumbprint))
        Set-DataGridColumnWidth -DataGridView $Script:CertificateDataGridView -Widths @(260,120,120,240,250)
    }
}
function Export-PasswordData {
    $passwordsXML = [PSCustomObject]@{
        Version = 1
        Keys    = @()
        Names   = ""
        PWDS    = @()
    }

    # 1. Get sorted lists of certificates and users from tables
    $certListSorted = Get-SortedDataTable -DataGridView $Script:CertificateDataGridView
    $userListSorted = Get-SortedDataTable -DataGridView $Script:UserDataGridView
    
    # Filter empty thumbprints and logins (ignore empty strings in tables)
    $targetThumbprints = @($certListSorted | Select-Object -ExpandProperty Thumbprint | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } | Select-Object -Unique)
    $targetUsers = @($userListSorted | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Login) })
    
    if ($targetThumbprints.Count -eq 0) {
        Write-Statusbar "❌ No certificates selected. Cannot save." "red"
        return $false
    }

    $droppedCount = @($userListSorted).Count - $targetUsers.Count
    if ($droppedCount -gt 0) {
        Write-Host "⚠️ Warning: $droppedCount row(s) with an empty Login will NOT be saved." -ForegroundColor Yellow
    }
    if ($targetUsers.Count -eq 0) {
        Write-Statusbar "Warning: No users in the list. Saving empty template..." "darkgray"
    }

    # 2. Search for certificates in the system
    $passwordsXML.Keys = $targetThumbprints
    $foundCerts = Find-CertificatesByThumbprints -Thumbprints $targetThumbprints
    
    # Reorder certificates to match the thumbprint order: Keys[i] must correspond to block i in Names and PWDS
    $targetCerts = @()
    foreach ($thumb in $targetThumbprints) {
        $cert = $foundCerts | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
        if ($cert) { $targetCerts += $cert }
    }
    
    # CRITICAL CHECK: If fewer certificates found than in grid
    if ($targetCerts.Count -lt $targetThumbprints.Count) {
        Write-Statusbar "❌ CRITICAL: Some certificates are missing (token not inserted?). Save ABORTED." "red"
        return $false
    }

    # 3. Prepare data (Login##Comment) for encryption.
    # Line breaks inside Login/Comment would break the CRLF-separated format, so they are replaced
    $payloadArray = @()
    foreach ($row in $targetUsers) {
        $safeLogin = $row.Login -replace "[\r\n]+", ''
        $safeComment = $row.Comment -replace "[\r\n]+", ' '
        $payloadArray += "$($safeLogin)##$($safeComment)"
    }
    $namesPayload = $payloadArray -join "`r`n"

    # 4. Encrypt user names for all certificates
    $namesCms = @()
    foreach ($cert in $targetCerts) {
        $encryptedNames = Protect-RsaMessage -MessageText $namesPayload -Certificate $cert
        if ($encryptedNames) {
            $namesCms += $encryptedNames
        } else {
            Write-Statusbar "❌ Failed to encrypt names for cert: $($cert.Thumbprint). Save ABORTED." "red"
            return $false
        }
    }
    $passwordsXML.Names = $namesCms -join ','

    # 5. Password processing - always decrypt to memory and re-encrypt from scratch
    $passwordsXML.PWDS = @()
    
    foreach ($userRow in $targetUsers) {
        $existingPassword = $userRow["Password"]
        $plainPwd = ""
        
        if (-not [string]::IsNullOrEmpty($existingPassword)) {
            $plainPwd = Unprotect-RsaMessage -MessageSecure $existingPassword
            if ($null -eq $plainPwd) {
                Write-Statusbar "❌ CRITICAL: Cannot decrypt password for user '$($userRow["Login"])'. Save ABORTED." "red"
                return $false
            }
        }
        
        $pwdCms = @()
        foreach ($cert in $targetCerts) {
            $encryptedPwd = Protect-RsaMessage -MessageText $plainPwd -Certificate $cert
            if ($encryptedPwd) {
                $pwdCms += $encryptedPwd
            } else {
                Write-Statusbar "❌ Failed to encrypt password for cert: $($cert.Thumbprint). Save ABORTED." "red"
                return $false
            }
        }
        
        $passwordsXML.PWDS += ($pwdCms -join ',')
    }

    # 6. Save to file
    try {
        if (Test-Path $Script:PasswordDataFilePath) {
            # Stop on backup failure: writing the new file without a backup risks data loss
            Copy-Item $Script:PasswordDataFilePath "$($Script:PasswordDataFilePath).bak" -Force -ErrorAction Stop
        }
        
        $passwordsXML | Export-Clixml $Script:PasswordDataFilePath -Force
        Write-Statusbar "✅ $($Script:PasswordDataFilePath) saved successfully!" "green"
        return $true
    } catch {
        Write-Statusbar "❌ Error saving file: $($_.Exception.Message)" "red"
        return $false
    }
}
Write-Host "Password manager v.$($Script:version)."
Show-PasswordManagerGui