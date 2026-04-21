# Windows Defender Upload Scanner for Native PHP

This guide shows how to use **Microsoft Defender Antivirus** in **native PHP on Windows** to scan uploaded files **before saving them**, following the same idea as a ClamAV upload scanner.

It includes:

- a Defender health check
- file upload form and handler
- scan-before-save logic
- block-on-detection behavior
- sample PHP files you can copy and run

---

## What this does

Flow:

1. Check whether Microsoft Defender looks healthy
2. Let the user upload a file
3. Scan the uploaded temporary file using Defender
4. If clean, save the file into `uploads/`
5. If infected, block the upload
6. Show scan result and health status in the page

Microsoft documents the key PowerShell cmdlets used for this workflow:

- `Get-MpComputerStatus` for Defender status
- `Update-MpSignature` to update security intelligence
- `Start-MpScan` to trigger quick, full, or custom scans
- `Get-MpThreatDetection` to review detections/remediation history

---

## Requirements

- Windows with **Microsoft Defender Antivirus** available
- PHP running on Windows
- `powershell.exe` accessible to PHP
- `exec()` enabled in PHP
- Defender signatures updated
- Defender not fully disabled by another antivirus product or policy

> If another antivirus product takes over protection, Microsoft Defender might be in passive mode or not active for scanning.

---

## Recommended manual checks first

Open **PowerShell as Administrator** and run:

```powershell
Get-MpComputerStatus
Update-MpSignature
Start-MpScan -ScanType QuickScan
Get-MpThreatDetection
```

These commands help confirm that Defender is available and working before you test the PHP code.

---

## Project structure

```text
windows-defender-test/
├── WindowsDefenderScanner.php
├── upload.php
└── uploads/
```

Create the `uploads` folder manually if you want, or let the PHP sample create it automatically.

---
## File 1: [`WindowsDefenderScanner.php`](windows-defender-test/WindowsDefenderScanner.php)
---

## File 2: [`upload.php`](windows-defender-test/upload.php)

---

## How to run it

### Option 1: PHP built-in server

Open Command Prompt or PowerShell in the project folder:

```bash
php -S localhost:8000
```

Then open:

```text
http://localhost:8000/upload.php
```

### Option 2: XAMPP

Put the folder in:

```text
C:\xampp\htdocs\windows-defender-test\
```

Then open:

```text
http://localhost/windows-defender-test/upload.php
```

---

## How the scan logic works

The PHP class does this:

1. calls `Get-MpComputerStatus`
2. checks whether Defender service and real-time protection appear active
3. when a file is uploaded, calls:

```powershell
Start-MpScan -ScanType CustomScan -ScanPath "<path-to-file>"
```

4. reads `Get-MpThreatDetection`
5. tries to match the threat record to the uploaded file path
6. blocks the upload if a matching detection is found

---

## Important limitation

This is a **practical sample**, but `Get-MpThreatDetection` is a **history view**, not a guaranteed single-file transaction log. In most simple tests it works well enough for demo or internal use, but for production you should do more verification and logging around the scan window.

Good production improvements include:

- quarantine folder
- audit log table
- stricter file validation
- extension whitelist
- MIME validation
- file size limits
- save only after clean result is confirmed
- admin-only access for test pages

---

## Optional: Update Defender signatures from PHP

You can call this before running tests:

```php
$scanner = new WindowsDefenderScanner();
$result = $scanner->updateSignatures();
print_r($result);
```

---

## Optional manual command-line tool

Microsoft also documents `MpCmdRun.exe` as a supported command-line tool for managing Defender. It is useful for automation and troubleshooting, but for PHP integration the PowerShell cmdlets are usually easier to parse and maintain.

---

## Troubleshooting

### 1. `powershell.exe` not found
Make sure PHP can execute PowerShell and that `exec()` is not disabled.

### 2. Health shows unhealthy
Run:

```powershell
Get-MpComputerStatus
```

Check these values:

- `AMServiceEnabled`
- `AntivirusEnabled`
- `RealTimeProtectionEnabled`
- `AMRunningMode`

### 3. Signatures are old
Run:

```powershell
Update-MpSignature
```

### 4. No detection appears
Try the EICAR test file in a controlled test environment. Also check Windows Security > Protection history.

### 5. Another antivirus is installed
Microsoft Defender may not be the active antivirus engine.

---

## Security reminder

Do not expose this test page publicly in production without additional controls. Restrict access, validate file types, and log all scan results.

---

## References

- Microsoft documents the PowerShell Defender cmdlets and their intended uses, including `Get-MpComputerStatus`, `Update-MpSignature`, `Start-MpScan`, and `Get-MpThreatDetection`.
- Microsoft documents `Start-MpScan` custom scans with `-ScanPath` for files or folders.
- Microsoft documents Defender running modes and notes that status can be reviewed with `Get-MpComputerStatus`.
- Microsoft documents `MpCmdRun.exe` as a supported command-line tool for managing Defender.

