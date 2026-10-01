# 🔐 Secure Password Storage Manager

**Version:** 1.10 (01 Oct 2026)
<img width="1002" height="739" alt="image" src="https://github.com/user-attachments/assets/5ca98cb2-edeb-44b1-8ad4-11692cbe9b15" />

A PowerShell-based GUI password manager that creates and manages password storage using **RSA encryption** via certificates (CMS/PKCS#7). It is recommended to use hardware **smartcards or tokens** for maximum security.

## ✨ Features

- 🖥️ **GUI interface** — just run the script and enjoy
- 🔒 **RSA / CMS encryption** — every password is encrypted with the public keys of *all* certificates in the storage; any matching private key (smartcard, token, or software cert) can decrypt
- 💳 **Multi-certificate support** — add/remove recipient certificates; ideal for team access or key rotation
- 🖥️ **RDP connections** — one-click remote desktop login as the selected user
  - Built on an **embedded C# wrapper** (compiled at runtime via `Add-Type`) over the native **Windows Credential Manager API** (`advapi32.dll`)
  - **No external `PSCredentialManager` DLLs required**
- 📁 **SMB connections** — open network shares (`\\server\share`) with the selected user's credentials
- 🚀 **Run As Invoker / Run Elevated** — launch any executable under the selected user account (configurable via INI)
- 📋 **Clipboard with auto-clear** — copied passwords are wiped from the clipboard after 30 seconds
- 🧮 **Built-in password generator** with configurable length
- 🕘 **Connection history** — recent RDP/SMB targets are kept in quick-access menus
- 💾 **Automatic backup** — a `.bak` copy is created before every save

## 📋 Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- `inc\Common_Functions.ps1` (required helper library, placed next to the script)
- A certificate with the **Document Encryption** EKU (`1.3.6.1.4.1.311.80.1`) — smartcard/token recommended

## 🚀 Usage

### GUI

.\pwd_manager.cmd

Optionally specify a custom password data file:

```powershell
.\pwd_manager.ps1  -PasswordDataFileName "C:\path\to\secure_passwords_v1.xml"
```

### Non-GUI consumption

The script's help block contains a ready-to-use `Get-SecureUserCredentials` function that decrypts passwords for multiple users from the secure XML storage and returns a **hashtable of `PSCredential` objects**:

```powershell
$script:passwordDataFileName = "secure_passwords_v1.xml"

$users = @("admin", "user1", "domain\service_account")
$creds = Get-SecureUserCredentials -userNames $users

$adminCreds = $creds["admin"]
$user1Creds = $creds["user1"]
```

See the `.EXAMPLE` section in the script header for the full function source.

## ⚙️ Configuration Files

Files are searched in this order: current PowerShell location → process current directory → script folder.

| File | Purpose |
|---|---|
| `pwd_manager.ini` | Main settings; defines context-menu commands (`INI-RunAsInvoker-L0..19`, `INI-RunElevated-L0..19`, `INI-RDPConnectAsUser-L0..9`, `INI-SMBConnectAsUser-L0..9`) |
| `RDPSettings.rdp` | Base `.rdp` settings used for RDP connections (optional) |
| `secure_passwords_v1.xml` | Encrypted password storage (can be overridden via `-PasswordDataFileName`) |

## 📄 Storage Format

The XML file (v1) contains:

- **Keys** — thumbprints of all recipient certificates
- **Names** — a single CMS-encrypted block holding all `Login##Comment` lines (separated by CRLF), encrypted once per certificate (comma-joined)
- **PWDS** — one comma-joined set of CMS blocks per user, one block per certificate

The **`##`** sequence is a reserved separator and may not appear in user names.

## 🛡️ Security Design

- Passwords never leave the machine in plaintext — they are decrypted only in memory, right before use
- During RDP login, the decrypted password is written to Windows Credential Manager, the session starts, and the credential is **automatically removed 5 seconds later**
- Decrypted `SecureString` contents are zeroed (`ZeroFreeBSTR`) immediately after use
- Saving **aborts** if any certificate is missing or any password cannot be decrypted/re-encrypted — no partially-corrupted storage is written
- When saving, all passwords are fully re-encrypted for the current certificate set

## 📝 Notes

- Certificates without the Document Encryption EKU are not offered for selection
- Missing certificates (e.g., disconnected token) are shown as `--- Missing Certificate ---` in the grid
- The GUI blocks editing of a password that cannot be decrypted (private key missing)

