<#
.SYNOPSIS
Common utility functions for PowerShell scripting with logging, INI file handling,security operations, string manipulation, and system interaction.

.PROPERTIES
[string] LogFileName - Path template for log files
[bool] WriteToLogFile - Enable/disable log file writing
[string] UserName - Current user name
[string] UserDomain - Current user domain
[string] UserDomainFQDN - Fully qualified domain name
[string] HostName - Host machine name
[datetime] StartUpDateTime - Class instantiation timestamp
[string] ScriptPath - Script directory path
[int] CurrentDebugLevel - Current debug verbosity level (1-10)

.CONSTRUCTOR
CommonClass() - Initializes class with user info, host details, regex patterns, and transliteration map

.METHODS - LOGGING
[void] ProcessLogMessage([string]$MessageType, [string]$InputText, [string]$Parameters, [int]$DebugLevel)
- Core logging method with duplicate suppression and formatting
Returns: void

[void] LogInfo($InputText, $Parameters = "")
- Informational messages with optional color parameters
Returns: void

[void] LogWarning($InputText, $Parameters = "")
- Warning messages with deduplication
Returns: void

[void] LogDebug($InputText, [int]$Level = 1)
- Debug messages filtered by CurrentDebugLevel
Returns: void
.METHODS - INI FILE HANDLING
[void] ReadINIFile($FileName)
- Loads INI settings into script-scope variables (INI-Section-Name)
Returns: void

[Nullable[bool]] ReadINIFileIfChanged($FileName)
- Reloads INI only if file changed since last read
Returns: $true (reloaded), $false (not changed), $null (file missing)
.METHODS - STRING MANIPULATION
[string] FilterUnprintableChars([string]$InputString, [bool]$MultiLine = $false)
- Removes control characters from strings
Returns: Cleaned string

[string] ExtractPrintableCharsOnly([string]$InputString)
- Replaces non-printable characters with spaces
Returns: Plain text string

[string] FilterQuotes([string]$InputString)
- Removes single/double quotes from string
Returns: String without quotes

[string] FilterNonAsciiChars([string]$InputString)
- Removes non-ASCII characters
Returns: ASCII-only string

[string] FilterSpaces([string]$InputString)
- Removes all whitespace characters
Returns: String without spaces

[string] MatchEmailInText([string]$InputString)
- Extracts first email address from text
Returns: Email string or $null

[bool] TestEmailAddress([string]$InputString)
- Validates email format
Returns: $true if valid email
.METHODS - PASSWORD & SECURITY
[string] NewRandomPassword([uint16]$Minimum_Length, [uint16]$Maximum_Length)
- Generates cryptographically random password
Returns: Random password string

[bool] IsAdministrator()
- Checks if current user has admin privileges
Returns: $true if administrator

[bool] IsCertificatePrivateKeyExportable([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
- Tests if certificate private key can be exported
Returns: $true if exportable

[System.Security.SecureString] PlainTextToSecureString([string]$plainString)
- Converts plain text to SecureString
Returns: SecureString

[string] SecureStringToPlainText([System.Security.SecureString]$SecureString)
- Converts SecureString back to plain text (use with caution)
Returns: Plain text string
.METHODS - DATA CONVERSION
[System.Data.DataTable] ConvertToDataTable($InputObject, [System.Data.DataTable]$OutputTable, [switch]$RetainColumns, [switch]$FilterWMIProperties)
- Converts objects to DataTable (10x faster than standard)
Returns: DataTable

[string] ConvertToBase64String([string]$inputText)
- UTF8 string to Base64
Returns: Base64 string

[string] ConvertFromBase64String([string]$inputText)
- Base64 to UTF8 string
Returns: Original string or $null

[string] ConvertToCliXMLString($inputText)
- Object to CliXML string
Returns: Serialized XML string

[object] ConvertFromCliXMLString([string]$inputText)
- CliXML string to object
Returns: Deserialized object

[byte[]] Hex2Bytes([string]$HexString)
- Hexadecimal string to byte array
Returns: Byte array or $null

[string] Bytes2Hex([byte[]]$BytesArr)
- Byte array to hexadecimal string
Returns: Hex string

[string] Bytes2CRC32Hex([byte[]]$BytesArr)
- Computes CRC32 checksum of byte array
Returns: 8-character hex CRC32
.METHODS - FILE SYSTEM
[void] EnsureFolderWithPermissions([string]$FolderPath, $SID, [bool]$AllowWrite = $false)
- Creates folder with specific SID permissions
Returns: void

[string] JoinPathBlockingTraversal([string]$basePath, [string]$fileName)
- Safe path combination preventing directory traversal
Returns: Full path or $null
.METHODS - SYSTEM MONITORING
[void] GetTiming([bool]$ResetTimer)
- Performance timing with lap functionality
Returns: void

[pscustomobject] GetProcessMetrics([string]$operation, $process)
- Returns process memory/CPU metrics
Returns: PSCustomObject with metrics

[int] GetUserIdleSeconds()
- Detects user idle time (keyboard/mouse)
Returns: Idle seconds (64-bit safe)
.METHODS - UI INTERACTION
[object] ShowMessageBoxTimeout([string]$Text, [string]$Caption, [object]$Buttons, [string]$Icon, [string]$DefaultButton, [int]$TimeoutSeconds)
- Displays message box with auto-timeout
Returns: DialogResult (OK, Yes, No, Cancel, etc.)

.METHODS - TRANSLITERATION
[string] ToLatinTransliteration([string]$Text)
- Converts Cyrillic/European characters to Latin
Returns: Transliterated string

.METHODS - USER MANAGEMENT
[bool] TestLocalGroupMembership([string]$GroupName)
- Tests current user membership in local group
Returns: $true if member

.NOTES
  Version:        1.15
  Author:         Andrew Afanasiev
  Date:           02.10.2026
  Contacts:       AfanasievAA@yandex.ru
#>
<#
LLM Contract 

# legend: *=has shorter overloads, {a,b}=variant group, <x>=substituted token, ?=optional, =def=default, !=throws, @=metadata, #=phase, .main=top-level body, @export=exported  
# types: s=string i=int b=bool o=obj a=array a<T>=typed array d=datetime r=regex ss=SecureString u=uint ul=ulong dict=Dictionary  

CommonClass: manage logging and utilities  

P.BadParamsChars(a<char>): illegal parameter characters  
P.LogFileName(s): base log file name  
P.{WriteToLogFile,isPS7OrNewer,IdleStateInitialized,NativeMethodsAdded,UserAPITypesAdded,IdleNativeTypesAdded}(b): internal state flags  
P.UserName(s): current user name  
P.UserDomain(s): current user domain  
P.UserDomainFQDN(s): user domain FQDN  
P.HostName(s): host computer name  
P.StartUpDateTime(d): script start time  
P.ScriptPath(o): script directory path  
P.LastDebugMessage(s): previous debug text  
P.LastErrorMessage(s): previous error text  
P.LastWarningMessage(s): previous warning text  
P.LastInfoMessage(s): previous info text  
P.LastErrorLevel(i): last error severity  
P.dupDebugCount(i): debug duplicate counter  
P.dupWarningCount(i): warning duplicate counter  
P.dupInfoCount(i): info duplicate counter  
P.CurrentDebugLevel(i): current debug verbosity  
P.INIFileLoadedTime(o): INI load timestamp  
P.TimeMeasureStart(o): timing start point  
P.TimeMeasureLap(o): timing lap point  
P.TimeMeasureTotalSec(o): total elapsed seconds  
P.TimeMeasureLapSec(o): lap elapsed seconds  
P.Crc32Managed(o): CRC32 implementation type  
P.UserAPITypesAdded(b): API types loaded flag  
P._UserAPIType(o): User API type holder  
P.CurrentUserIdentity(o): current Windows identity  
P.commentRG(r): comment line regex  
P.sectionRG(r): INI section regex  
P.varnameRG(r): variable assignment regex  
P.VarMultiLineStartRG(r): multiline start regex  
P.VarMultiLineEndRG(r): end regex  
.LastInfoTime): last info  
P.LastTime(d): last timestamp  
PDebugTime(d last debug timestampP.MultiLineRegex(r): multiline separator regex  
P.UnprintableCharsRegex(r): non-printable chars regex  
P.plainTextOnlyRegEx(r): plain-text regex  
P.QuotesRegex(r): quotes removal regex  
P.NonAsciiCharsRegex(r): non-ASCII chars regex  
P.SpacesRegex(r): whitespace regex  
P.EmailRG(r): email detection regex  
P.NonHEXSymbols(r): non-hex symbols regex  
P.IntPatternRG(r): integer pattern regex  
P.DoublePatternRG(r): floating-point pattern regex  
P.MultiSpacesRegex(r): multiple spaces regex  
P.TranslitMap(dict): character transliteration table  
P.PasswordCharCodes(o): password character pool  
P.LastInputInfo(o): last input info struct  
P.IdleReconstructedLastInput64(u): reconstructed idle timestamp  
P.IdlePrevLastTick32(u): previous idle tick  
P.NativeMethodsAdded(b): native methods loaded flag  
P._NativeMethodsType(o): native methods type holder  
P.CachedLogFileName(s): cached log filename  
P.LogStreamWriter(o): stream writer for log  

M.ProcessLogMessage(s=MessageType,s=InputText,s=Parameters?,i=DebugLevel?)*: log message with optional formatting  
M.LogInfo(s=InputText,s=Parameters?)*: write informational log entry  
M.LogWarning(s=InputText,s=Parameters?)*: write warning log entry  
M.LogDebug(s=InputText,i=Level?=1)*: write debug log entry  
M.ReadINIFile(s=FileName)*: load INI settings into script variables  
M.ReadINIFileIfChanged(s=FileName)*: reload INI if modified  
M.FilterUnprintableChars(s=InputString,b=MultiLine?=false)*: strip non-printable characters  
M.ExtractPrintableCharsOnly(s=InputString)*: keep only printable characters  
M.FilterQuotes(s=InputString)*: remove quotation marks  
M.FilterNonAsciiChars(s=InputString)*: discard non-ASCII characters  
M.FilterSpaces(s=InputString)*: normalize whitespace  
M.MatchEmailInText(s=InputString)*: extract email address from text  
M.TestEmailAddress(s=InputString)*: validate email format  
M.NewRandomPassword(u=Minimum_Length,u=Maximum_Length?)*: generate random password  
M.GetTiming(b=ResetTimer=false)* start or record checkpoint  
MToDataTable=InputObject,oOutputTable?,=Retain?,b=WMIProperties?)* -> o: transform objects into DataTable  
M.ConvertToBase64String(s=inputText)* -> s: encode string to Base64  
M.ConvertFromBase64String(s=inputText)* -> s: decode Base64 to string  
M.ConvertToCliXMLString(o=inputText)* -> s: serialize object to CLI-XML  
M.ConvertFromCliXMLString(s=inputText)* -> o: deserialize CLI-XML to object  
M.Hex2Bytes(s=HexString)* -> a<byte>: convert HEX string to byte array  
M.Bytes2Hex(a<byte> BytesArr)* -> s: format bytes as HEX string  
M.Bytes2CRC32Hex(a<byte> BytesArr)* -> s: compute CRC32 hex digest  
M.IsAdministrator()*: check if current user is admin  
M.IsCertificatePrivateKeyExportable(o=Certificate)*: verify certificate key exportability  
M.EnsureFolderWithPermissions(s=FolderPath,o=SID?,b=AllowWrite?=false)*: create folder and set ACL  
M.GetProcessMetrics(s=operation?,o=process?)* -> o: collect process performance data  
M.GetUserIdleSeconds()* -> i: retrieve user idle time in seconds  
M.JoinPathBlockingTraversal(s=basePath,s=fileName)* -> s: combine paths securely  
M.GetUserNameFormat(i=format)* -> s: obtain formatted user name  
M.ResolveCurrentUser()*: resolve current user details  
M.TestLocalGroupMembership(s=GroupName)*: verify local group membership  
M.ShowMessageBoxTimeout(s=Text,s=Caption?,o=Buttons?,s=Icon?,s=DefaultButton?,i=TimeoutSeconds?)* -> o: display timed message box  
M.PlainTextToSecureString(s=plainString)* -> ss: convert plain text to SecureString  
M.SecureStringToPlainText(ss=SecureString)* -> s: convert SecureString to plain text  
M.ToLatinTransliteration(s=Text)* -> s: transliterate text to Latin characters
#>
class CommonClass {
    static [char[]]$BadParamsChars = """';`0".ToCharArray()
    [string]$LogFileName = "logs\FunctionLog"
    [bool]$WriteToLogFile = $false
    [string]$UserName = $null
    [string]$UserDomain = $null
    [string]$UserDomainFQDN = $null
    [string]$HostName = $null
    [datetime]$StartUpDateTime = [System.Datetime]::Now
    $ScriptPath = $null
    [string]$LastDebugMessage = ""
    [string]$LastErrorMessage = ""
    [string]$LastWarningMessage = ""
    [string]$LastInfoMessage = ""
    [int]$LastErrorLevel = 0
    [int]$dupDebugCount = 0
    [int]$dupWarningCount = 0
    [int]$dupInfoCount = 0
    [int]$CurrentDebugLevel = 0
    $INIFileLoadedTime = $null
    $TimeMeasureStart = $null
    $TimeMeasureLap = $null
    $TimeMeasureTotalSec = $null
    $TimeMeasureLapSec = $null
    $Crc32Managed = $null
    hidden [bool]$UserAPITypesAdded
    hidden [type]$_UserAPIType

    $CurrentUserIdentity = $null
    hidden [regex]$commentRG = $null
    hidden [regex]$sectionRG = $null
    hidden [regex]$varnameRG = $null
    hidden [regex]$VarMultiLineStartRG = $null
    hidden [regex]$VarMultiLineEndRG = $null
    [bool]$isPS7OrNewer = $PSVersionTable.PSVersion.Major -ge 7
    [datetime]$LastInfoTime = [datetime]::MinValue
    [datetime]$LastWarningTime = [datetime]::MinValue
    [datetime]$LastDebugTime = [datetime]::MinValue
    [regex]$MultiLineRegex = $null
    [regex]$UnprintableCharsRegex = $null
    [regex]$plainTextOnlyRegEx = $null
    [regex]$QuotesRegex = $null
    [regex]$NonAsciiCharsRegex = $null
    [regex]$SpacesRegex = $null
    [regex]$EmailRG = $null
    [regex]$NonHEXSymbols = $null
    # Flag if types are already added
    hidden [bool] $IdleNativeTypesAdded = $false
    hidden $_IdleNativeType = $null
    hidden $_IdleNativeLASTINPUTINFOType = $null
    $PasswordCharCodes = $null
    $LastInputInfo = $null
    hidden [System.UInt64]$IdleReconstructedLastInput64 = 0
    hidden [uint32]$IdlePrevLastTick32 = 0
    hidden [bool]$IdleStateInitialized = $false
    hidden [bool]$NativeMethodsAdded = $false
    hidden $_NativeMethodsType = $null    
    hidden [string]$CachedLogFileName = $null
    hidden [System.IO.StreamWriter]$LogStreamWriter = $null
    hidden $FromHexStringMethod = $null
    [regex]$IntPatternRG = $null
    [regex]$DoublePatternRG = $null
    [regex]$MultiSpacesRegex = $null
    hidden [System.Collections.Generic.Dictionary[char, string]] $TranslitMap
    CommonClass() {
        if ($null -eq (Get-Variable MyInvocation -Scope 0).Value.MyCommand.Path) {
            $this.ScriptPath = (Get-Location).Path
        } else {
            $this.ScriptPath = Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path
        }
        $this.CurrentUserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $this.ResolveCurrentUser()
        if (-Not $this.UserName) {
            $parts = $this.CurrentUserIdentity.Name.Split('\', 2)
            $this.UserName = $parts[1]
            $this.UserDomain = $parts[0]
            $this.UserDomainFQDN = $env:USERDNSDOMAIN -replace '[\\/:*?"<>|]', '_' 
        }
        $this.MultiLineRegex = [regex]::new("(\`r\`n){2,}", [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.UnprintableCharsRegex = [regex]::new('[\p{C}&&[^\r\n]]', [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.plainTextOnlyRegEx = [regex]::new('\p{C}+', [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.QuotesRegex = [regex]::new("['""]", [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.NonAsciiCharsRegex = [regex]::new("[^\x20-\x7E]", [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.SpacesRegex = [regex]::new("\s", [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.MultiSpacesRegex = [regex]::new("\s{2,}", [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.IntPatternRG = [regex]::new("^-?\d+$", [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.DoublePatternRG = [regex]::new("^-?\d+\.\d+$", [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.EmailRG = [regex]::new('[a-z0-9!#\$%&''*+/=^_`{|}~-]+(?:\.[a-z0-9!#\$%&''*+/=^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', [System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $this.NonHEXSymbols = [regex]::new('[^0-9A-Fa-f]', [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.HostName =  ([System.Net.Dns]::GetHostEntry([string]"localhost").HostName)
        $this.commentRG = [regex]::new("^\s*#", [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.sectionRG = [regex]::new("^\s*\[([\w\d_]{2,})\]", [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.varnameRG = [regex]::new("^\s*([\w\d_]{2,})\s*=\s*(.*)$", [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.VarMultiLineStartRG = [regex]::new("^\s*([\w\d_]{2,})\s*=\s*@""", [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.VarMultiLineEndRG = [regex]::new("^\s*""@\s*$", [System.Text.RegularExpressions.RegexOptions]::Compiled)
        $this.TranslitMap = [System.Collections.Generic.Dictionary[char, string]]::new()
        # Transliteration table (GOST 7.79-2000, system B)
        $map = $this.TranslitMap
        $map.Add('а', 'a'); $map.Add('б', 'b'); $map.Add('в', 'v'); $map.Add('г', 'g'); $map.Add('д', 'd')
        $map.Add('е', 'e'); $map.Add('ё', 'e'); $map.Add('ж', 'zh'); $map.Add('з', 'z'); $map.Add('и', 'i')
        $map.Add('й', 'i'); $map.Add('к', 'k'); $map.Add('л', 'l'); $map.Add('м', 'm'); $map.Add('н', 'n')
        $map.Add('о', 'o'); $map.Add('п', 'p'); $map.Add('р', 'r'); $map.Add('с', 's'); $map.Add('т', 't')
        $map.Add('у', 'u'); $map.Add('ф', 'f'); $map.Add('х', 'kh'); $map.Add('ц', 'ts'); $map.Add('ч', 'ch')
        $map.Add('ш', 'sh'); $map.Add('щ', 'shch'); $map.Add('ъ', ''); $map.Add('ы', 'y'); $map.Add('ь', '')
        $map.Add('э', 'e'); $map.Add('ю', 'iu'); $map.Add('я', 'ia')
        # --- Addition: Top popular European languages ---
        # German
        $map.Add('ä', 'ae'); $map.Add('ö', 'oe'); $map.Add('ü', 'ue'); $map.Add('ß', 'ss')
        # French, Spanish, Italian, Portuguese (diacritics)
        $map.Add('à', 'a'); $map.Add('á', 'a'); $map.Add('â', 'a'); $map.Add('ã', 'a')
        $map.Add('è', 'e'); $map.Add('é', 'e'); $map.Add('ê', 'e'); $map.Add('ë', 'e')
        $map.Add('ì', 'i'); $map.Add('í', 'i'); $map.Add('î', 'i'); $map.Add('ï', 'i')
        $map.Add('ò', 'o'); $map.Add('ó', 'o'); $map.Add('ô', 'o'); $map.Add('õ', 'o')
        $map.Add('ù', 'u'); $map.Add('ú', 'u'); $map.Add('û', 'u')
        $map.Add('ç', 'c')
        $map.Add('ñ', 'n')
        $map.Add('ý', 'y'); $map.Add('ÿ', 'y')
        # Scandinavian (Swedish, Norwegian, Danish)
        $map.Add('å', 'a'); $map.Add('æ', 'ae'); $map.Add('ø', 'o')
        # Polish, Czech, Slovak
        $map.Add('ą', 'a'); $map.Add('ć', 'c'); $map.Add('ę', 'e'); $map.Add('ł', 'l')
        $map.Add('ń', 'n'); $map.Add('ś', 's'); $map.Add('ź', 'z'); $map.Add('ż', 'z')
        $map.Add('č', 'c'); $map.Add('ď', 'd'); $map.Add('ě', 'e'); $map.Add('ň', 'n')
        $map.Add('ř', 'r'); $map.Add('š', 's'); $map.Add('ť', 't'); $map.Add('ů', 'u')
        $map.Add('ž', 'z')
        # Turkish
        $map.Add('ğ', 'g'); $map.Add('ı', 'i'); $map.Add('ş', 's')
    }

    [void] ProcessLogMessage([string]$MessageType, [string]$InputText, [string]$Parameters = "", [int]$DebugLevel = 1) {
        $LCLLogFileName = $null
        $writeHostParams = $null
        $isDuplicate = $false
        $currentTime = $null
        $isMultiline = $false
        $filteredText = $null
        $finalText = $null
        $timestamp = $null
        $logEntry = $null
        $paramParts = $null
        $colorName = $null
        $logOnly = $false

        if ($MessageType -eq "Debug" -and $this.CurrentDebugLevel -lt $DebugLevel) {
            return
        }

        if ($Parameters -and $Parameters.IndexOfAny([CommonClass]::BadParamsChars) -ge 0) {
            $Parameters = ""
        }

        $isMultiline = $Parameters -and $Parameters.Contains("multiline")

        $filteredText = if ($isMultiline) {
            $this.FilterUnprintableChars($InputText, $true)
        } else {
            $this.FilterUnprintableChars($InputText)
        }

        $filteredText = $filteredText.Replace('"', '`"')

        $currentTime = [DateTime]::Now

        switch ($MessageType) {
            "Info" {
                $isDuplicate = $filteredText -eq $this.LastInfoMessage
                if ($isDuplicate) {
                    $this.dupInfoCount++
                } else {
                    $this.LastInfoMessage = $filteredText
                    $this.dupInfoCount = 0
                    $this.LastInfoTime = $currentTime
                }
            }
            "Warning" {
                if ($this.LastWarningTime -gt [datetime]::MinValue -and ($currentTime - $this.LastWarningTime).TotalMinutes -gt 10) {
                    # Reset duplicate tracking after 10 minutes to re-alert admins
                    $this.dupWarningCount = 0
                    $this.LastWarningMessage = $null
                }

                $isDuplicate = $filteredText -eq $this.LastWarningMessage
                if ($isDuplicate) {
                    $this.dupWarningCount++
                } else {
                    $this.LastWarningMessage = $filteredText
                    $this.dupWarningCount = 0
                    $this.LastWarningTime = $currentTime
                }
            }
            "Debug" {
                $isDuplicate = $filteredText -eq $this.LastDebugMessage
                if ($isDuplicate) {
                    $this.dupDebugCount++
                } else {
                    $this.LastDebugMessage = $filteredText
                    $this.dupDebugCount = 0
                    $this.LastDebugTime = $currentTime
                }
            }
        }

        if ($isDuplicate) {
            switch ($MessageType) {
                "Info" {
                    if ($this.LastInfoTime -and ($currentTime - $this.LastInfoTime).TotalSeconds -le 5) {
                        return
                    }
                    if ($this.dupInfoCount -ge 2) {
                        if ($this.dupInfoCount -eq 2) {
                            $filteredText = "Duplicate log messages detected. Further logging of this message suppressed."
                        } else {
                            return
                        }
                    }
                }
                "Warning" {
                    if ($this.LastWarningTime -and ($currentTime - $this.LastWarningTime).TotalSeconds -le 5) {
                        return
                    }
                    if ($this.dupWarningCount -ge 2) {
                        if ($this.dupWarningCount -eq 2) {
                            $filteredText = "Duplicate log messages detected. Further logging of this message suppressed."
                        } else {
                            return
                        }
                    }
                }
                "Debug" {
                    if ($this.LastDebugTime -and ($currentTime - $this.LastDebugTime).TotalSeconds -le 5) {
                        return
                    }
                    if ($this.dupDebugCount -ge 2) {
                        if ($this.dupDebugCount -eq 2) {
                            $filteredText = "Duplicate log messages detected. Further logging of this message suppressed."
                        } else {
                            return
                        }
                    }
                }
            }
        }

        $finalText = $filteredText

        $writeHostParams = @{}
        $logOnly = $false

        if ($Parameters) {
            $paramParts = $Parameters -split '\s+'
            for ($i = 0; $i -lt $paramParts.Length; $i++) {
                $currentParam = $paramParts[$i]

                if (($currentParam -eq "-Fore" -or $currentParam -eq "-ForegroundColor") -and $i -lt ($paramParts.Length - 1)) {
                    $colorName = $paramParts[$i + 1]
                    try {
                        $writeHostParams.ForegroundColor = [ConsoleColor]$colorName
                        $i++
                    } catch {
                    }
                }
                elseif (($currentParam -eq "-Back" -or $currentParam -eq "-BackgroundColor") -and $i -lt ($paramParts.Length - 1)) {
                    $colorName = $paramParts[$i + 1]
                    try {
                        $writeHostParams.BackgroundColor = [ConsoleColor]$colorName
                        $i++
                    } catch {
                    }
                }
                elseif ($currentParam -eq "-NoNewline") {
                    $writeHostParams.NoNewline = $true
                }
                elseif ($currentParam -eq "LogOnly") {
                    $logOnly = $true
                }
            }
        }

        if (-not $logOnly) {
            switch ($MessageType) {
                "Info" { Write-Host $finalText @writeHostParams }
                "Warning" { Write-Warning $finalText }
                "Debug" { Write-Host $finalText @writeHostParams }
            }
        }

        if ($this.WriteToLogFile) {
            $timestamp = [System.DateTime]::Now.ToString("yyyy-MM-dd HH-mm")            
            if (-not $this.CachedLogFileName) {
                $this.CachedLogFileName = "$($this.LogFileName)_$($this.StartUpDateTime.toString('yyyy-MM-dd_HH-mm'))_$($this.UserName).log"
            }
            $LCLLogFileName = $this.CachedLogFileName

            $logEntry = if ($MessageType -eq "Warning") {
                "$timestamp WARNING! $finalText"
            } else {
                "$timestamp $finalText"
            }
            [System.IO.File]::AppendAllText($LCLLogFileName, "$logEntry`r`n", [System.Text.Encoding]::UTF8)
        }
    }
    [void] ProcessLogMessage([string]$MessageType, [string]$InputText, [string]$Parameters = "") {
        $this.ProcessLogMessage($MessageType, $InputText, $Parameters, 1)
    }
    [void] ProcessLogMessage([string]$MessageType, [string]$InputText) {
        $this.ProcessLogMessage($MessageType, $InputText, "", 1)
    }
    <#
    .SYNOPSIS
        Writes an informational message to console and/or log file.
    .DESCRIPTION
        Outputs informational messages with optional formatting parameters. Supports color coding,
        duplicate message suppression, and log-only mode.
    .PARAMETER InputText
        The message text to display. Can be a string or array (will be joined with newlines).
    .PARAMETER Parameters
        Optional formatting parameters as a space-separated string. Supported values:
        - "-Fore COLOR"    - Sets foreground color (e.g., "-Fore GREEN", "-Fore CYAN")
        - "-Back COLOR"    - Sets background color (e.g., "-Back BLACK", "-Back RED")  
        - "LogOnly"        - Writes only to log file, not to console
        - "multiline"      - Preserves multiline formatting in log file
        
        Color options: Black, DarkBlue, DarkGreen, DarkCyan, DarkRed, DarkMagenta, 
        DarkYellow, Gray, DarkGray, Blue, Green, Cyan, Red, Magenta, Yellow, White.
    .EXAMPLE
        $CommonObj.LogInfo("Operation completed successfully", "-Fore GREEN")
    .EXAMPLE  
        $CommonObj.LogInfo("User profile loaded", "LogOnly")
    .EXAMPLE
        $CommonObj.LogInfo("Multi-line`r`ncontent", "multiline -Fore CYAN")
    #>
    [void] LogInfo($InputText, $Parameters = "") {
        $this.ProcessLogMessage("Info", $InputText, $Parameters)
    }
    [void] LogInfo($InputText) {
        $this.ProcessLogMessage("Info", $InputText, $null)
    }
    <#
    .SYNOPSIS
        Writes a warning message to console and/or log file.
    .DESCRIPTION
        Outputs warning messages with yellow/orange coloring by default. Supports the same
        parameters as LogInfo but warnings have distinct visual styling in console.
    .PARAMETER InputText
        The warning message text to display.
    .PARAMETER Parameters
        Optional parameters (same as LogInfo but color parameters may be overridden
        by the default warning styling in some consoles).
    .EXAMPLE
        $CommonObj.LogWarning("Certificate expiration approaching")
    .EXAMPLE
        $CommonObj.LogWarning("Low disk space", "LogOnly")
    .NOTES
        Warning messages automatically include "WARNING!" prefix in log files and
        use system warning formatting in console.
    #>
    [void] LogWarning($InputText, $Parameters = "") {
        $this.ProcessLogMessage("Warning", $InputText, $Parameters)
    }
    [void] LogWarning($InputText) {
        $this.ProcessLogMessage("Warning", $InputText, $null)
    }
    <#
    .SYNOPSIS
        Writes a debug message to console and/or log file based on debug level.
    .DESCRIPTION
        Outputs debug messages that can be filtered by debug level. Useful for development
        and troubleshooting. Messages are only displayed if CurrentDebugLevel >= specified level.
    .PARAMETER InputText
        The debug message text to display.
    .PARAMETER Level
        The debug level (1-10). Message is only shown if CurrentDebugLevel >= Level.
        Default is 1 (basic debugging).
    .EXAMPLE
        $CommonObj.LogDebug("Entering function X", 1)  # Basic debug
    .EXAMPLE
        $CommonObj.LogDebug("Detailed variable dump", 3)  # Verbose debug
    .EXAMPLE
        $CommonObj.LogDebug("API response received", 2) -Fore MAGENTA  # Colored debug
    .NOTES
        Debug level filtering allows controlling verbosity without modifying code.
        Set $CommonObj.CurrentDebugLevel to control which messages are displayed.
    #>
    [void] LogDebug($InputText, $Level = 1) {
        $this.ProcessLogMessage("Debug", $InputText, "", $Level)
    }
    [void] LogDebug($InputText) {
        $this.LogDebug($InputText, 1)
    }
    # This function will load all settings from INI file into script scope variables
    # Version 2026.08.04
    # Example:
    # General]
    # DebugLevel=1
    # [SMTPServer]
    # Login=Security-Center
    # From=Security-Center@eurosib-hydro.ru
    # Will be loaded as ${script:INI-General-DebugLevel} and ${script:INI-SMTPServer-Login} and ${script:INI-SMTPServer-FROM} variables 
    # Those will be avaailable to any procedure in script
    # Multiline are supported
    #    ParameterMultiline=@"
    #    Some text
    #    Some text again
    #    "@
    [void] ReadINIFile($FileName) {
        if (-not (Test-Path $FileName)) {
            $this.LogInfo("INI file not found: $FileName")
            return
        }
        
        $section = "default"
        $varCount = 0
        $multiLineReading = $false
        $paramName = $null
        $varValue = [System.Text.StringBuilder]::new()

        # Lazy enumeration of lines - highly memory efficient for large INI files
        $content = [System.IO.File]::ReadLines($FileName)

        foreach ($textLine in $content) {
            # Use direct .NET methods for trimming to avoid PS overhead
            $trimmedLine = $textLine.Trim()

            if ($multiLineReading) {
                if ($this.VarMultiLineEndRG.IsMatch($trimmedLine)) {
                    $multiLineReading = $false
                    $value = $varValue.ToString()
                    $scriptVarName = "INI-$section-$paramName"

                    Set-Variable -Name $scriptVarName -Value $value -Scope Script
                    $this.LogDebug("$scriptVarName = $value", 2)
                    $varCount++

                    $null = $varValue.Clear()
                    $paramName = $null
                } else {
                    $null = $varValue.AppendLine($textLine)
                }
                continue
            }

            if ([string]::IsNullOrWhiteSpace($trimmedLine) -or $this.commentRG.IsMatch($trimmedLine)) {
                continue
            }

            $sectionMatch = $this.sectionRG.Match($trimmedLine)
            if ($sectionMatch.Success) {
                $section = $sectionMatch.Groups[1].Value
                # Clean up previous variables from the same section.
                # Exact prefix match instead of a wildcard: "INI-SMB-*" would also match "INI-SMBConnectAsUser-L0"
                $sectionPrefix = "INI-$section-"
                Get-Variable -Scope Script -ErrorAction SilentlyContinue | Where-Object { $_.Name.StartsWith($sectionPrefix, [System.StringComparison]::OrdinalIgnoreCase) } | ForEach-Object {
                    Remove-Variable -Name $_.Name -Scope Script -Force -ErrorAction SilentlyContinue
                }                
                continue
            }

            $multilineMatch = $this.VarMultiLineStartRG.Match($trimmedLine)
            if ($multilineMatch.Success) {
                $multiLineReading = $true
                $paramName = $multilineMatch.Groups[1].Value
                continue
            }

            $varMatch = $this.varnameRG.Match($trimmedLine)
            if ($varMatch.Success) {
                $paramName = $varMatch.Groups[1].Value
                $value = $varMatch.Groups[2].Value.Trim()

                # Smart typing: convert to int or double if applicable
                if ($this.IntPatternRG.IsMatch($value)) {
                    $value = [int]$value
                } elseif ($this.DoublePatternRG.IsMatch($value)) {
                    $value = [double]$value
                }

                # Type guard: a non-numeric string like "abc" would otherwise pass "$value -gt 0" in PowerShell
                if ($paramName -eq "DebugLevel" -and $value -is [int] -and $value -gt 0) {
                    $this.CurrentDebugLevel = $value
                }

                $scriptVarName = "INI-$section-$paramName"
                Set-Variable -Name $scriptVarName -Value $value -Scope Script
                $this.LogDebug("$scriptVarName = $value", 2)
                $varCount++
            }
        }

        # Warn about an unterminated multiline value: its content is silently discarded otherwise
        if ($multiLineReading) {
            $this.LogWarning("INI file ($FileName): multiline value '$paramName' has no end marker, value discarded")
        }
        $this.LogInfo("$varCount settings from INI file ($FileName) loaded.")
    }
    
    # Checks if a INI file is changed and reads settings from it
    # Returns $true if the file was (re)read, $false if unchanged since the last read, $null if the file was not found
    [Nullable[bool]] ReadINIFileIfChanged($FileName) {
        $INI_LastWriteTime = (Get-Item $FileName -ErrorAction SilentlyContinue).LastWriteTime
        if ($null -eq $INI_LastWriteTime) {
            return $null
        } elseif ($null -eq $this.INIFileLoadedTime -or $this.INIFileLoadedTime -lt $INI_LastWriteTime) {
            $this.ReadINIFile($FileName)
            $this.INIFileLoadedTime = $INI_LastWriteTime
            return $true
        } else {
            return $false
        }
    }
    [string] FilterUnprintableChars([string]$InputString, [bool]$MultiLine = $false) {
        if ($MultiLine) {
            return $this.MultiLineRegex.Replace(($this.UnprintableCharsRegex.Replace($InputString, "")), "`r`n")
        } else {
            return $this.UnprintableCharsRegex.Replace($InputString, "")
        }
    }
    [string] FilterUnprintableChars([string]$InputString) {
        return $this.FilterUnprintableChars($InputString, $false)
    }
    # Returns plain text of any string replacing other symbols with spaces
    [string] ExtractPrintableCharsOnly([string]$InputString) {
        $tmp = $null

        $tmp = $this.plainTextOnlyRegEx.Replace($InputString, ' ')
        $tmp = $this.MultiSpacesRegex.Replace($tmp, ' ')
        return $tmp.Trim()
    }
    [string] FilterQuotes([string]$InputString) {
        return $this.QuotesRegex.Replace($InputString, "")
    }
    [string] FilterNonAsciiChars([string]$InputString) {
        return $this.NonAsciiCharsRegex.Replace($InputString, "")
    }
    [string] FilterSpaces([string]$InputString) {
        return $this.SpacesRegex.Replace($InputString, "")
    }
    # Matches Email in text and returns it if found. If not - returns null
    [string] MatchEmailInText([string]$InputString) {
        $resultEmail = $null

        $resultEmail = $this.EmailRG.Match($InputString)
        if ($resultEmail.success -ne $true) {
            return $null
        }
        return ($resultEmail.Value)
    }
    [bool] TestEmailAddress([string]$InputString) {
        if ([string]::IsNullOrWhiteSpace($InputString)) {
            return $false
        }
        if ($InputString -eq $this.MatchEmailInText($InputString)) {
            return $true
        } else {
            return $false
        }
    }
    # Random password generator with aproximate length calculated from specified minimum and maximum length
    # Excluded capital letter S, O, 0 enc
    [string] NewRandomPassword([uint16]$Minimum_Length, [uint16]$Maximum_Length) {
        [uint16]$Current_Length = 0
        if ($Maximum_Length -gt $Minimum_Length -and $Maximum_Length -gt 1) {
            $Current_Length = Get-Random -Minimum $Minimum_Length -Maximum $Maximum_Length
        } else {
            $Current_Length = $Minimum_Length
        }

        # Lazy-initialized once and reused across all subsequent calls
        if (-not $this.PasswordCharCodes) {
            $this.PasswordCharCodes = 49..57 + 65..72 + 74..78 + 80..82 + 84..90 + 97..104 + 106 + 107 + 109 + 110 + 112..122 + 33 + 35 + 36 + 38 + 43 + 45
        }

        [int]$poolSize = $this.PasswordCharCodes.Length
        $sb = [System.Text.StringBuilder]::new($Current_Length)

        if ($this.isPS7OrNewer) {
            # PS7+: Use fast cryptographic GetInt32
            for ([uint16]$i = 0; $i -lt $Current_Length; $i++) {
                $randomIndex = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32($poolSize)
                $null = $sb.Append([char]$this.PasswordCharCodes[$randomIndex])
            }
        } else {
            # PS5.1: Fallback to byte array generation (single RNG call for the whole password)
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $randomBytes = New-Object byte[] (4 * $Current_Length)
            $rng.GetBytes($randomBytes)
            $rng.Dispose()
            for ([uint16]$i = 0; $i -lt $Current_Length; $i++) {
                $randomIndex = [BitConverter]::ToUInt32($randomBytes, 4 * $i) % $poolSize
                $null = $sb.Append([char]$this.PasswordCharCodes[$randomIndex])
            }
        }
        return $sb.ToString()
    }

    [string] NewRandomPassword([uint16]$Minimum_Length) {
        return $this.NewRandomPassword($Minimum_Length, $Minimum_Length)
    }

    [string] NewRandomPassword() {
        return $this.NewRandomPassword(16, 16)
    }
    [void] GetTiming([bool]$ResetTimer) {
        if ($null -eq $this.TimeMeasureStart -or $ResetTimer) {
            $this.TimeMeasureStart = [System.Datetime]::Now
            $this.TimeMeasureLap = $null
        } elseif ($null -eq $this.TimeMeasureLap) {
            $this.TimeMeasureTotalSec = [math]::Round((([System.Datetime]::Now - $this.TimeMeasureStart).TotalSeconds), 2)
            $this.TimeMeasureLap = [System.Datetime]::Now
        } else {
            $now = [System.Datetime]::Now
            $this.TimeMeasureTotalSec = [math]::Round((($now - $this.TimeMeasureStart).TotalSeconds), 2)
            $this.TimeMeasureLapSec = [math]::Round((($now - $this.TimeMeasureLap).TotalSeconds), 2)
            $this.TimeMeasureLap = $now
        }
    }
    [void] GetTiming() {
        $this.GetTiming($false)
    }
	<#
		.SYNOPSIS
			Converts objects into a DataTable. 
            Version by Andrew Afanasiev. 10 times faster.
		.DESCRIPTION
			Converts objects into a DataTable, which are used for DataBinding.
		.PARAMETER  InputObject
			The input to convert into a DataTable.
		.PARAMETER  Table
			The DataTable you wish to load the input into.
		.PARAMETER RetainColumns
			This switch tells the function to keep the DataTable's existing columns.
		.PARAMETER FilterWMIProperties
			This switch removes WMI properties that start with an underline.
		.EXAMPLE
			$DataTable = $CommonObj.ConvertToDataTable((Get-Process))
	#>
    [System.Data.DataTable] ConvertToDataTable($InputObject, [System.Data.DataTable]$OutputTable, [switch]$RetainColumns, [switch]$FilterWMIProperties) {
        if (-Not $InputObject) { return $null }
        if ($null -eq $OutputTable) { $OutputTable = New-Object System.Data.DataTable }
        
        if ($InputObject -is [System.Data.DataTable]) {
            $OutputTable = $InputObject
        } else {
            if (-not $RetainColumns -or $OutputTable.Columns.Count -eq 0) {
                $OutputTable.Clear()
                $object = $null
                foreach ($item in $InputObject) {
                    if ($null -ne $item) { $object = $item; break }
                }
                if ($null -eq $object) { return $null }

                # Get all the properties in order to create the columns
                foreach ($prop in $object.PSObject.Get_Properties()) {
                    if (-not $FilterWMIProperties -or -not $prop.Name.StartsWith('__')) {
                        $type = $null
                        if ($null -ne $prop.Value) {
                            try { $type = $prop.Value.GetType() } catch { }
                        }
                        if ($null -ne $type) {
                            $null = $OutputTable.Columns.Add($prop.Name, $type)
                        } else {
                            $null = $OutputTable.Columns.Add($prop.Name)
                        }
                    }
                }
                if ($object -is [System.Data.DataRow]) {
                    foreach ($item in $InputObject) { $null = $OutputTable.Rows.Add($item) }
                    return $OutputTable
                }
            } else {
                $OutputTable.Rows.Clear()
            }

            $readBlock = $null
            $blockCreated = $false

            foreach ($item in $InputObject) {
                $row = $OutputTable.NewRow()
                if ($item) {
                    if (-not $blockCreated) {
                        # Create a compiled ScriptBlock instead of Invoke-Expression
                        # Wrap property names in single quotes to prevent injection
                        $sb = [System.Text.StringBuilder]::new()
                        foreach ($prop in $item.PSObject.Get_Properties()) {
                            if ($OutputTable.Columns.Contains($prop.Name)) {
                                $safeName = $prop.Name -replace "'", "''"
                                $null = $sb.AppendLine("if (`$null -ne `$item.'$safeName') { `$row.Item('$safeName') = `$item.'$safeName' }")
                            }
                        }
                        $readBlock = [ScriptBlock]::Create($sb.ToString())
                        $blockCreated = $true
                    }
                    # Execute the compiled block. 
                    # Using & $readBlock is fast and inherits current scope variables ($item, $row)
                    & $readBlock
                }
                $null = $OutputTable.Rows.Add($row)
            }
        }
        return $OutputTable
    }
    [System.Data.DataTable] ConvertToDataTable($InputObject, [System.Data.DataTable]$OutputTable, [switch]$RetainColumns) {
        return $this.ConvertToDataTable($InputObject, $OutputTable, $RetainColumns, $null)
    }    
    [System.Data.DataTable] ConvertToDataTable($InputObject, [System.Data.DataTable]$OutputTable) {
        return $this.ConvertToDataTable($InputObject, $OutputTable, $null, $null)
    }    
    [System.Data.DataTable] ConvertToDataTable($InputObject) {
        return $this.ConvertToDataTable($InputObject, $null, $null, $null)
    }    
    # Converts UTF8 string to a base64 encoded form
    [string] ConvertToBase64String([string]$inputText) {
        return [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($inputText))
    }
    # Converts back base64 encoded to a UTF8 string
    [string] ConvertFromBase64String([string]$inputText) {
        Try {
            return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($inputText))
        } Catch { }
        return $null
    }
    # Converts any object to a Cli XML String
    [string] ConvertToCliXMLString($inputText) {
        return [System.Management.Automation.PSSerializer]::Serialize($inputText)
    }
    # Converts back base64 encoded to a UTF8 string
    # Converts any CliXML String to an object
    [object] ConvertFromCliXMLString([string]$inputText) {
        Try {
            return [System.Management.Automation.PSSerializer]::DeSerialize($inputText)
        } Catch { }
        return $null
    }
    # Converts any HEX String to a byte array. $null returned if input not a hex string
    [byte[]] Hex2Bytes([string]$HexString) {
        $cleanHex = $this.NonHEXSymbols.Replace($HexString, "")
        if ($cleanHex.Length % 2 -ne 0) { return $null }
        try {
            # .NET 5+ FromHexString method if available; reflection result is cached
            if (-not $this.FromHexStringMethod) {
                $this.FromHexStringMethod = [System.Convert].GetMethod("FromHexString", [Type[]]@([string]))
            }
            if ($this.FromHexStringMethod) {
                return $this.FromHexStringMethod.Invoke($null, @($cleanHex))
            }
            # Fallback if no .NET 5+
            $arr = New-Object byte[] ($cleanHex.Length / 2)
            for ($i = 0; $i -lt $cleanHex.Length; $i += 2) {
                $arr[$i / 2] = [System.Convert]::ToByte($cleanHex.Substring($i, 2), 16)
            }
            return $arr
        } Catch {
            return $null
        }
    }
    # Converts any HEX String to a byte array. $null returned if input not a hex string
    [string] Bytes2Hex([byte[]]$BytesArr) {
        return ([System.BitConverter]::ToString($BytesArr))
    }
    # Computes CRC32 of any input byte array
    [string] Bytes2CRC32Hex([byte[]]$BytesArr) {
        if ($BytesArr.Count -eq 0) { return "00000000" }

        # Resolve type dynamically at runtime to bypass parser errors in PS 5.1; result cached
        $crcType = $this.Crc32Managed
        
        if (-not $crcType) {
            Add-Type -TypeDefinition @"
                using System;
                public static class SafeManagedCrc32 {
                    private static readonly uint[] Table;
                    
                    static SafeManagedCrc32() {
                        Table = new uint[256];
                        uint polynomial = 0xEDB88320;
                        for (uint i = 0; i < 256; i++) {
                            uint crc = i;
                            for (int j = 0; j < 8; j++) {
                                crc = (crc & 1) == 1 ? (crc >> 1) ^ polynomial : crc >> 1;
                            }
                            Table[i] = crc;
                        }
                    }
                    
                    public static uint Compute(byte[] bytes) {
                        uint crc = 0xFFFFFFFF;
                        foreach (byte b in bytes) {
                            crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
                        }
                        return crc ^ 0xFFFFFFFF;
                    }
                }
"@
            # Re-evaluate type after Add-Type
            $crcType = 'SafeManagedCrc32' -as [type]
        }
        
        # Store and use the Type object directly
        $this.Crc32Managed = $crcType
        return $this.Crc32Managed::Compute($BytesArr).ToString("X8")
    }
    # Determine if current user has administrator role and returns true or false
    [bool] IsAdministrator() {
        if ($this.CurrentUserIdentity -is [System.Security.Claims.ClaimsIdentity]) {
            return ([System.Security.Principal.WindowsPrincipal]::new($this.CurrentUserIdentity)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        } else {
            return $false
        }
    }
    # Checks if cpecified ceritifcate is exportable
    [bool] IsCertificatePrivateKeyExportable([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
        $cngKey = $null
        if (-not $Certificate.HasPrivateKey) { return $false }
        if ($this.isPs7OrNewer) {
            $cngKey = $Certificate.PrivateKey.Key
            return ($cngKey -and $cngKey.ExportPolicy.HasFlag([System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport))
        } else {
            return $Certificate.PrivateKey.CspKeyContainerInfo.Exportable
        }
    }
    #  Creates the target directory if it does not exist and applies a read (or read-write) ACE for the supplied SID. Errors are written to $this.ErrorLevel / $this.ErrorText.
    [void] EnsureFolderWithPermissions([string]$FolderPath, $SID, $AllowWrite = $false) {
        $acl = $null
        $sidObject = $null
        $rights = $null
        $accessRule = $null
        $writeBits = $null
        $exists = $null
        $rule = $null
        $sameSid = $null
        $sameRight = $null
        $isAllow = $null
        $isWriteNowAllowed = $null

        try {
            if (-not [System.IO.Directory]::Exists($FolderPath)) {
                Write-Host "Creating directory: $FolderPath"
                $null = New-Item -Path $FolderPath -ItemType Directory -Force
            }
            # If $SID is $null there is nothing to do - just exit cleanly.
            if ($null -eq $SID) { return }
            $acl = Get-Acl -Path $FolderPath
            $sidObject = New-Object System.Security.Principal.SecurityIdentifier($SID)
            # Base rights - always read & execute
            $rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
            # Add Modify rights when requested
            if ($AllowWrite) {
                $rights = $rights -bor [System.Security.AccessControl.FileSystemRights]::Modify
            }
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sidObject,
                $rights,
                'ContainerInherit, ObjectInherit',
                'None',
                'Allow'
            )
            #  Determine whether an identical rule already exists
            $writeBits = [System.Security.AccessControl.FileSystemRights]::Write -bor [System.Security.AccessControl.FileSystemRights]::Delete -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
            $exists = $false
            foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                $sameSid = $rule.IdentityReference.Value -eq $SID
                $sameRight = (($rule.FileSystemRights -band $rights) -eq $rights)
                $isAllow = $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
                # Does the rule already grant (or deny) write permissions?
                $isWriteNowAllowed = -not (($rule.FileSystemRights -band $writeBits) -eq 0)
                if ($sameSid -and $sameRight -and $isAllow -and $isWriteNowAllowed -eq $AllowWrite) {
                    # Exact rule already present - nothing to do.
                    $exists = $true
                    break
                }
                elseif ($sameSid -and $sameRight -and $isAllow) {
                    # A rule for the same SID/rights exists but its write flag does NOT match the requested state - remove it so we can add the correct one.
                    $acl.RemoveAccessRule($rule) | Out-Null
                }
            }
            #  Add the rule only if it wasn't found
            if (-not $exists) {
                $acl.AddAccessRule($accessRule)
                Set-Acl -Path $FolderPath -AclObject $acl
                Write-Host "Read$(if ($AllowWrite) {" and write"}) permissions for $($FolderPath) granted for SID: $SID"
            }
        } catch {
            Write-Error "Failed to ensure folder '$FolderPath' with permissions: $($_.Exception.Message)"
        }
    }
    [void] EnsureFolderWithPermissions([string]$FolderPath, $SID) {
        $this.EnsureFolderWithPermissions($FolderPath, $SID, $false)
    }
    # Get memory and CPU metrics of the process. Default - current process
    [pscustomobject] GetProcessMetrics([string]$operation, $process) {
        $process.Refresh()
        return [pscustomobject]@{
            Operation          = $operation
            Timestamp          = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            ProcessId          = $process.Id
            Handles            = $process.HandleCount
            ThreadCount        = $process.Threads.Count
            WorkingSet_KB      = [math]::Round($process.WorkingSet64 / 1KB, 2)
            PrivateMemory_KB   = [math]::Round($process.PrivateMemorySize64 / 1KB, 2)
            VirtualMemory_KB   = [math]::Round($process.VirtualMemorySize64 / 1KB, 2)
            PagedMemory_KB     = [math]::Round($process.PagedMemorySize64 / 1KB, 2)
            CPU_s              = [math]::Round($process.TotalProcessorTime.TotalSeconds, 3)
            GC_TotalMemory_KB  = [math]::Round([GC]::GetTotalMemory($false) / 1KB, 2)
            GC_Gen0Collections = [GC]::CollectionCount(0)
            GC_Gen1Collections = [GC]::CollectionCount(1)
            GC_Gen2Collections = [GC]::CollectionCount(2)
        }
    }
    
    [pscustomobject] GetProcessMetrics([string]$operation) {
        $process = [System.Diagnostics.Process]::GetCurrentProcess()
        return $this.GetProcessMetrics($operation, $process)
    }
    [pscustomobject] GetProcessMetrics() {
        $process = [System.Diagnostics.Process]::GetCurrentProcess()
        return $this.GetProcessMetrics("not specified", $process)
    }
    # Returns number of seconds current user is IDLE (not using mouse/keyboard) in seconds
    [int] GetUserIdleSeconds() {
        # Bypass PS 5.1 parser error: use '-as [type]' instead of hardcoding [IdleNative] which doesn't exist at parse time.
        $idleType = $this._IdleNativeType
        if (-not $idleType) {
            # Define Win32 API wrappers. GetTickCount64 is 64-bit and never wraps. GetLastInputInfo is 32-bit and wraps every 49.7 days.
            Add-Type @"
                using System;
                using System.Runtime.InteropServices;
                public static class IdleNative {
                    [StructLayout(LayoutKind.Sequential)]
                    public struct LASTINPUTINFO {
                        public uint cbSize;
                        public uint dwTime;
                    }
                    [DllImport("user32.dll")]
                    public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
                    [DllImport("kernel32.dll")]
                    public static extern ulong GetTickCount64();
                }
"@
            $idleType = 'IdleNative' -as [type]
        }
        # Cache resolved types once; reused on subsequent calls.
        $this._IdleNativeType = $idleType
        if (-not $this._IdleNativeLASTINPUTINFOType) {
            $this._IdleNativeLASTINPUTINFOType = 'IdleNative+LASTINPUTINFO' -as [type]
        }
        # Initialize the struct if it doesn't exist. Explicit [Type] cast prevents "ambiguous overload" error with Activator.CreateInstance.
        if (-not $this.LastInputInfo -or ($this.LastInputInfo -isnot $this._IdleNativeLASTINPUTINFOType)) {
            $this.LastInputInfo = [Activator]::CreateInstance([Type]$this._IdleNativeLASTINPUTINFOType)
            $this.LastInputInfo.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($this.LastInputInfo)
        }
        # CRITICAL: Copy struct to a local variable. Class properties box value types. Passing a boxed property via [ref] updates a temporary copy, leaving the property unchanged.
        $localInputInfo = $this.LastInputInfo
        # Call Win32 API. It will correctly update the local variable's dwTime.
        if (-not $this._IdleNativeType::GetLastInputInfo([ref]$localInputInfo)) {
            throw "GetLastInputInfo API call failed"
        }
        # Get current 64-bit system uptime in milliseconds.
        $tick64 = $this._IdleNativeType::GetTickCount64()
        # Extract the 32-bit last input time from the updated local struct.
        $lastTick32 = $localInputInfo.dwTime
        # Stateful reconstruction: only recalculate the 64-bit timestamp if this is the first run OR new user input is detected.
        if (-not $this.IdleStateInitialized -or $lastTick32 -ne $this.IdlePrevLastTick32) {
            # Extract the lower 32 bits of the 64-bit uptime to match the scale of the 32-bit dwTime.
            $current32 = $tick64 % ([uint32]::MaxValue + 1)
            if ($current32 -ge $lastTick32) {
                # Standard case: No 32-bit overflow occurred between the input event and now.
                $this.IdleReconstructedLastInput64 = $tick64 - ($current32 - $lastTick32)
            } else {
                # Overflow case: The 32-bit counter wrapped around since the last input. Add a full 2^32 cycle to compensate mathematically.
                $this.IdleReconstructedLastInput64 = $tick64 - ( ([uint32]::MaxValue + 1) - $lastTick32 + $current32 )
            }
            # Cache the 32-bit tick to detect future input changes.
            $this.IdlePrevLastTick32 = $lastTick32
            $this.IdleStateInitialized = $true
        }
        # Calculate idle time purely in 64-bit math. This completely avoids the 49.7-day wrap-around limit.
        $idleMs = $tick64 - $this.IdleReconstructedLastInput64
        # Return whole seconds. Using Floor to avoid rounding up fractional milliseconds.
        return [math]::Floor($idleMs / 1000)
    }
    # Safe Join-Path excluding traversal exploit and hacks
    [string] JoinPathBlockingTraversal([string]$basePath, [string]$fileName) {
        if ([string]::IsNullOrWhiteSpace($fileName)) { return $null }
        $normalizedBase = [System.IO.Path]::GetFullPath($basePath)
        $combinedPath = [System.IO.Path]::Combine($normalizedBase, $fileName)
        $resolvedPath = [System.IO.Path]::GetFullPath($combinedPath)
        $normalizedBaseWithSlash = $normalizedBase.TrimEnd('\') + '\'
        if (-not $resolvedPath.StartsWith($normalizedBaseWithSlash, [System.StringComparison]::OrdinalIgnoreCase)) {
            $this.LogWarning("JPBPT1", "Error! Path traversal technique detected")
            return $null
        }
        return $resolvedPath
    }
    hidden [string] GetUserNameFormat([int]$format) {
        if (-not $this.UserAPITypesAdded) {
            Add-Type @"
                using System;
                using System.Runtime.InteropServices;
                using System.Text;
                public static class UserAPI {
                    [DllImport("secur32.dll", CharSet = CharSet.Auto)]
                    public static extern int GetUserNameEx(int nameFormat, StringBuilder userName, ref int userNameSize);
                }
"@
            $this._UserAPIType = [type]"UserAPI"
            $this.UserAPITypesAdded = $true
        }

        $size = 1024
        $buffer = [System.Text.StringBuilder]::new($size)
        if ($this._UserAPIType::GetUserNameEx($format, $buffer, [ref]$size) -ne 0) {
            return $buffer.ToString()
        }
        return $null
    }
    # Resolving user name, domain, etc through API
    [void] ResolveCurrentUser() {
        # 2 = NameSamCompatible, 12 = NameDnsDomain
        # Others:
        # 1 - NameFullyQualifiedDN - Fully Qualified Distinguished Name
        # 3 - NameDisplay - Display User Name in AD
        # 6 - NameUniqueId - Uniquie GUIID
        # 7 - NameCanonical - Canonical Name
        # 8 - NameUserPrincipal) - User Principal Name (UPN)
        $samCompatible = $this.GetUserNameFormat(2)
        $domainFQDN = $this.GetUserNameFormat(12)

        if ($samCompatible) {
            $parts = $samCompatible.Split('\', 2)
            if ($parts.Count -eq 2) {
                $this.UserDomain = $parts[0]
                $this.UserName = $parts[1]
            }
        }
        if ($domainFQDN) {
            $parts = $domainFQDN.Split('\', 2)
            if ($parts.Count -eq 2) {
                $this.UserDomainFQDN = $parts[0]
            }
        }
    }
    # Test current user membership in local group
    [bool] TestLocalGroupMembership([string]$GroupName) {
        try {
            $members = Get-LocalGroupMember -Name $GroupName
            $currentUser = $this.CurrentUserIdentity.Name
            return $members.Name -contains $currentUser
        }
        catch {
            return $false
        }
    }
    <#
    .SYNOPSIS
        Displays a message box with automatic timeout closing
    .DESCRIPTION
        Shows a dialog box with a message that automatically closes after the specified time. Used to display errors, warnings, and confirmation requests in the user interface.
    .PARAMETER Text
        The message text to display. Can contain line breaks (`r`n)
    .PARAMETER Caption
        The message box window title
    .PARAMETER Buttons
        Button type: "OK", "YesNo", "RetryCancel", "AbortRetryIgnore", etc.
    .PARAMETER Icon
        Icon type: "Stop", "Question", "Exclamation", "Information", "Error"
    .PARAMETER DefaultButton
        Default button: "Button1", "Button2", "Button3"
    .PARAMETER TimeoutSeconds
        Time in seconds before automatic window closing.
        0 = no timeout (waits for user action)
    .EXAMPLE
        $result = ShowMessageBoxTimeout "Operation completed" "Success" "OK" "Information" "Button1" 5
    .EXAMPLE
        $confirm = ShowMessageBoxTimeout "Confirm action" "Confirmation" "YesNo" "Question" "Button2" 15
    .OUTPUTS
        Returns user's selection: "OK", "Yes", "No", "Cancel", "Retry", "Abort", "Ignore", "Timeout"
    #>
    [object] ShowMessageBoxTimeout(
        [string] $Text, 
        [string] $Caption, 
        [object]$Buttons, 
        [string]$Icon, 
        [string]$DefaultButton, 
        [int]$TimeoutSeconds
    ) {
        # Bypass PS parser errors: Load WinForms assembly dynamically if it's not loaded yet
        if (-not ('System.Windows.Forms.DialogResult' -as [type])) {
            Add-Type -AssemblyName System.Windows.Forms
        }
        # Resolve enum types at runtime to avoid parser errors
        $drType = 'System.Windows.Forms.DialogResult' -as [type]
        $btnType = 'System.Windows.Forms.MessageBoxButtons' -as [type]
        
        # Safely parse the $Buttons input (can be string, int, or enum) into the actual enum
        $ButtonsEnum = [System.Enum]::Parse($btnType, [string]$Buttons, $true)

        # Bypass PS 5.1 parser error: use '-as [type]' for NativeMethods
        $nativeType = 'NativeMethods' -as [type]
        
        if (-not $nativeType) {
            Add-Type @'
                using System;
                using System.Runtime.InteropServices;

                public static class NativeMethods
                {
                    // Unicode version of MessageBoxTimeout - returns the pressed-button code
                    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                    public static extern int MessageBoxTimeout(
                        IntPtr hWnd,          // Owner window handle (0 = no owner)
                        string lpText,        // Message text
                        string lpCaption,     // Window title
                        uint   uType,         // Combination of MB_ flags (buttons, icons, default button)
                        ushort wLanguageId,   // Language (0 = LANG_NEUTRAL)
                        uint   dwMilliseconds // Timeout in ms (0 = no timeout)
                    );
                }
'@
            $nativeType = 'NativeMethods' -as [type]
        }

        # Ensure instance property is populated for THIS instance regardless of Add-Type execution
        $this._NativeMethodsType = $nativeType

        # Build the uType flag for the WinAPI call (buttons + icon + default button)
        $mbButtons = @{
            OK               = 0x00000000
            OKCancel         = 0x00000001
            AbortRetryIgnore = 0x00000002
            YesNoCancel      = 0x00000003
            YesNo            = 0x00000004
            RetryCancel      = 0x00000005
        }

        $mbIcons = @{
            None        = 0x00000000
            Hand        = 0x00000010   # Stop / Error
            Question    = 0x00000020
            Exclamation = 0x00000030   # Warning
            Asterisk    = 0x00000040   # Information
        }

        $mbDefBtn = @{
            Button1 = 0x00000000
            Button2 = 0x00000100
            Button3 = 0x00000200
            Button4 = 0x00000300
        }

        # Convert the resolved enum to string to look up the corresponding WinAPI constant
        $buttonFlag = $mbButtons[[string]$ButtonsEnum]
        
        $iconFlag   = switch ($Icon) {
            'Stop'        { $mbIcons['Hand']        }
            'Error'       { $mbIcons['Hand']        }
            'Question'    { $mbIcons['Question']    }
            'Exclamation' { $mbIcons['Exclamation'] }
            'Warning'     { $mbIcons['Exclamation'] }
            'Information' { $mbIcons['Asterisk']    }
            default       { $mbIcons['None']        }
        }
        
        $defBtnFlag = $mbDefBtn[[string]$DefaultButton]

        $uType = $buttonFlag -bor $iconFlag -bor $defBtnFlag

        # Convert timeout from seconds to milliseconds (0 = infinite)
        $dwMs = if ($TimeoutSeconds -gt 0) { [uint32]($TimeoutSeconds * 1000) } else { 0 }

        # Call the native API using the resolved Type object
        $result = $this._NativeMethodsType::MessageBoxTimeout(
            [IntPtr]::Zero,   # No owner window - the message box appears on top
            $Text,
            $Caption,
            $uType,
            0,                 # LANG_NEUTRAL
            $dwMs
        )

        # Translate the WinAPI return code to the .NET DialogResult enum dynamically
        switch ($result) {
            1 { return $drType::OK }
            2 { return $drType::Cancel }
            3 { return $drType::Abort }
            4 { return $drType::Retry }
            5 { return $drType::Ignore }
            6 { return $drType::Yes }
            7 { return $drType::No }
            default { return $drType::None }
        }
        return $null
    }
    [object] ShowMessageBoxTimeout  ($Text) {
        return $this.ShowMessageBoxTimeout($Text, 'Info message', 'OK', 'Information', 'Button1', 0)
    }
    [object] ShowMessageBoxTimeout  ($Text, $Caption) {
        return $this.ShowMessageBoxTimeout($Text, $Caption, 'OK', 'Information', 'Button1', 0)
    }
    [object] ShowMessageBoxTimeout  ($Text, $Caption, $Buttons) {
        return $this.ShowMessageBoxTimeout($Text, $Caption, $Buttons, 'Information', 'Button1', 0)
    }
    [object] ShowMessageBoxTimeout  ($Text, $Caption, $Buttons, $Icon) {
        return $this.ShowMessageBoxTimeout($Text, $Caption, $Buttons, $Icon, 'Button1', 0)
    }
    [System.Security.SecureString] PlainTextToSecureString([string]$plainString) {
        return (ConvertTo-SecureString -String $plainString -AsPlainText -Force)
    }
    [string] SecureStringToPlainText([System.Security.SecureString]$SecureString) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        } finally {
            # Erasing BSTRE buffer to prevent unencrypted leak
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) | Out-Null
        }
    }
    [string] ToLatinTransliteration([string]$Text) {
        if ([string]::IsNullOrEmpty($Text)) {
            return $Text
        }

        $map = $this.TranslitMap
        $result = [System.Text.StringBuilder]::new($Text.Length * 2)
        $len = $Text.Length
        
        # Using a for loop and .Chars($i) is the fastest way to retrieve a System.Char in PowerShell
        for ($i = 0; $i -lt $len; $i++) {
            $char = $Text.Chars($i)
            $lowerChar = [char]::ToLowerInvariant($char)
            $translit = $null
            
            if ($map.TryGetValue($lowerChar, [ref]$translit)) {
                if ($translit.Length -gt 0) {
                    if ([char]::IsUpper($char)) {
                        # Access the first character via .Chars(0) to explicitly get a char type
                        $null = $result.Append([char]::ToUpperInvariant($translit.Chars(0)))
                        if ($translit.Length -gt 1) {
                            $null = $result.Append($translit, 1, $translit.Length - 1)
                        }
                    } else {
                        $null = $result.Append($translit)
                    }
                }
            } else {
                $null = $result.Append($char)
            }
        }
        
        return $result.ToString()
    }
}
# Create instance for backward compatibility
Remove-Variable -Name 'CommonObj' -Scope Script -Force -ErrorAction SilentlyContinue
$Script:CommonObj = [CommonClass]::new()
