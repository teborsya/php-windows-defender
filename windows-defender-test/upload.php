<?php

require_once __DIR__ . '/WindowsDefenderScanner.php';

$scanner = new WindowsDefenderScanner();
$health = $scanner->healthCheck();

$message = '';
$messageType = '';
$scanDetails = null;

$uploadDir = __DIR__ . '/uploads';
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if ($health['status'] !== 'healthy') {
        $message = 'Upload blocked because Microsoft Defender is not healthy or not active.';
        $messageType = 'error';
    } elseif (!isset($_FILES['file'])) {
        $message = 'No file uploaded.';
        $messageType = 'error';
    } elseif ($_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        $message = 'Upload failed with error code: ' . $_FILES['file']['error'];
        $messageType = 'error';
    } else {
        $originalName = $_FILES['file']['name'];
        $tmpPath = $_FILES['file']['tmp_name'];
        $safeName = time() . '_' . preg_replace('/[^A-Za-z0-9_\.-]/', '_', basename($originalName));
        $destination = $uploadDir . DIRECTORY_SEPARATOR . $safeName;

        $scanResult = $scanner->scan($tmpPath);
        $scanDetails = $scanResult;

        if ($scanResult['status'] === 'clean') {
            if (move_uploaded_file($tmpPath, $destination)) {
                $message = 'Upload successful. File is clean and saved as: ' . htmlspecialchars($safeName);
                $messageType = 'success';
            } else {
                $message = 'File is clean but could not be moved to uploads folder.';
                $messageType = 'error';
            }
        } elseif ($scanResult['status'] === 'infected') {
            $message = 'Upload blocked. Threat detected: ' . htmlspecialchars($scanResult['virus'] ?? 'Unknown threat');
            $messageType = 'infected';
            @unlink($tmpPath);
        } else {
            $message = 'Scan error: ' . htmlspecialchars($scanResult['message'] ?? 'Unknown error');
            $messageType = 'error';
        }
    }
}

function h($value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
}

function yesNo($value): string
{
    return $value ? 'Yes' : 'No';
}

$details = $health['details'] ?? [];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Defender Upload Test</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f7fb; padding: 40px; color: #1e293b; }
        .container { max-width: 960px; margin: auto; background: #fff; padding: 24px; border-radius: 14px; box-shadow: 0 10px 30px rgba(0,0,0,.08); }
        .section { background: #f8fafc; border: 1px solid #dbe3ea; padding: 18px; border-radius: 10px; margin-top: 18px; }
        .msg { padding: 12px 15px; border-radius: 8px; margin-top: 18px; }
        .success { background: #e8f8ee; color: #166534; }
        .infected { background: #fdecec; color: #b42318; }
        .error { background: #fff4e5; color: #92400e; }
        .healthy { background: #ecfdf5; color: #065f46; padding: 12px 15px; border-radius: 8px; margin-top: 18px; }
        .unhealthy { background: #fef2f2; color: #991b1b; padding: 12px 15px; border-radius: 8px; margin-top: 18px; }
        code { background: #eef2f7; padding: 2px 6px; border-radius: 4px; }
        pre { white-space: pre-wrap; word-wrap: break-word; background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 8px; overflow-x: auto; }
        button { background: #2563eb; color: #fff; border: none; padding: 10px 18px; border-radius: 8px; cursor: pointer; }
        button:hover { background: #1d4ed8; }
        input[type=file] { margin-bottom: 12px; }
    </style>
</head>
<body>
<div class="container">
    <h1>Windows Defender File Upload Test</h1>
    <p>This sample scans the uploaded file with Microsoft Defender before saving it.</p>

    <div class="section">
        <h2>Before You Upload</h2>
        <ul>
            <li>Make sure you are running this on <strong>Windows</strong>.</li>
            <li>Make sure <strong>Microsoft Defender Antivirus</strong> is installed and active.</li>
            <li>Make sure signatures are up to date.</li>
            <li>Make sure PHP can call <code>powershell.exe</code> using <code>exec()</code>.</li>
            <li>If another antivirus product disables Defender scanning, this sample may not work as expected.</li>
        </ul>

        <h3>Recommended PowerShell checks</h3>
        <pre>Get-MpComputerStatus
Update-MpSignature
Start-MpScan -ScanType QuickScan
Get-MpThreatDetection</pre>
    </div>

    <div class="<?= $health['status'] === 'healthy' ? 'healthy' : 'unhealthy' ?>">
        <strong>Defender Health:</strong> <?= h(strtoupper($health['status'])) ?><br>
        <?= h($health['message'] ?? '') ?>
    </div>

    <div class="section">
        <h2>Health Details</h2>
        <p><strong>AM service enabled:</strong> <?= h(yesNo($details['AMServiceEnabled'] ?? false)) ?></p>
        <p><strong>Antivirus enabled:</strong> <?= h(yesNo($details['AntivirusEnabled'] ?? false)) ?></p>
        <p><strong>Real-time protection enabled:</strong> <?= h(yesNo($details['RealTimeProtectionEnabled'] ?? false)) ?></p>
        <p><strong>Running mode:</strong> <?= h($details['AMRunningMode'] ?? 'Unknown') ?></p>
        <p><strong>Signature version:</strong> <?= h($details['AntivirusSignatureVersion'] ?? 'Unknown') ?></p>
        <p><strong>Product version:</strong> <?= h($details['AMProductVersion'] ?? 'Unknown') ?></p>
        <p><strong>Quick scan age:</strong> <?= h($details['QuickScanAge'] ?? 'Unknown') ?></p>
        <p><strong>Full scan age:</strong> <?= h($details['FullScanAge'] ?? 'Unknown') ?></p>
    </div>

    <?php if (!empty($message)): ?>
        <div class="msg <?= h($messageType) ?>"><?= $message ?></div>
    <?php endif; ?>

    <div class="section">
        <h2>Upload File</h2>
        <?php if ($health['status'] !== 'healthy'): ?>
            <p><strong>Upload disabled</strong> until Defender is healthy.</p>
        <?php else: ?>
            <form action="" method="POST" enctype="multipart/form-data">
                <input type="file" name="file" required>
                <br>
                <button type="submit">Upload and Scan</button>
            </form>
        <?php endif; ?>
    </div>

    <?php if ($scanDetails): ?>
        <div class="section">
            <h2>Scan Details</h2>
            <p><strong>Status:</strong> <?= h($scanDetails['status'] ?? '') ?></p>
            <p><strong>Message:</strong> <?= h($scanDetails['message'] ?? '') ?></p>
            <p><strong>Threat:</strong> <?= h($scanDetails['virus'] ?? 'None') ?></p>
            <p><strong>Scan command:</strong> <?= h($scanDetails['scan_command'] ?? '') ?></p>
            <?php if (!empty($scanDetails['detection'])): ?>
                <h3>Detection Data</h3>
                <pre><?= h(print_r($scanDetails['detection'], true)) ?></pre>
            <?php endif; ?>
            <?php if (!empty($scanDetails['output'])): ?>
                <h3>Raw Output</h3>
                <pre><?= h(implode("\n", $scanDetails['output'])) ?></pre>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>
</body>
</html>
