<?php

class WindowsDefenderScanner
{
    public function healthCheck(): array
    {
        if (!$this->isWindows()) {
            return [
                'status' => 'unsupported',
                'message' => 'Windows Defender sample only works on Windows.',
                'details' => [],
            ];
        }

        $statusJson = $this->runPowerShell(
            'Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, ' .
            'AntivirusSignatureVersion, AMProductVersion, AMRunningMode, QuickScanAge, FullScanAge | ConvertTo-Json -Compress'
        );

        if (!$statusJson['success']) {
            return [
                'status' => 'unhealthy',
                'message' => 'Unable to read Microsoft Defender status.',
                'details' => $statusJson,
            ];
        }

        $decoded = json_decode($statusJson['stdout'], true);

        if (!is_array($decoded)) {
            return [
                'status' => 'unhealthy',
                'message' => 'Failed to parse Microsoft Defender status output.',
                'details' => $statusJson,
            ];
        }

        $healthy =
            !empty($decoded['AMServiceEnabled']) &&
            !empty($decoded['AntivirusEnabled']) &&
            !empty($decoded['RealTimeProtectionEnabled']);

        return [
            'status' => $healthy ? 'healthy' : 'unhealthy',
            'message' => $healthy
                ? 'Microsoft Defender appears ready for scanning.'
                : 'Microsoft Defender is not fully active. Check service state, running mode, and protection settings.',
            'details' => $decoded,
            'raw' => $statusJson,
        ];
    }

    public function updateSignatures(): array
    {
        return $this->runPowerShell('Update-MpSignature');
    }

    public function scan(string $filePath): array
    {
        if (!$this->isWindows()) {
            return [
                'status' => 'error',
                'message' => 'This scanner only works on Windows.',
                'virus' => null,
                'output' => [],
            ];
        }

        if (!file_exists($filePath)) {
            return [
                'status' => 'error',
                'message' => 'File does not exist.',
                'virus' => null,
                'output' => [],
            ];
        }

        $realPath = realpath($filePath);
        if ($realPath === false) {
            return [
                'status' => 'error',
                'message' => 'Unable to resolve file path.',
                'virus' => null,
                'output' => [],
            ];
        }

        // Clear old data reference point (best effort; history can still contain older items)
        $before = $this->getThreatDetections();

        $scan = $this->runPowerShell(
            "Start-MpScan -ScanType CustomScan -ScanPath '" . $this->escapePowerShellString($realPath) . "'"
        );

        $after = $this->getThreatDetections();

        if (!$scan['success']) {
            return [
                'status' => 'error',
                'message' => 'Defender scan command failed.',
                'virus' => null,
                'output' => [$scan['stderr'] ?: $scan['stdout']],
                'scan_command' => 'Start-MpScan -ScanType CustomScan -ScanPath <file>',
            ];
        }

        $detection = $this->findDetectionForPath($realPath, $before['items'] ?? [], $after['items'] ?? []);

        if ($detection !== null) {
            return [
                'status' => 'infected',
                'message' => 'Threat detected by Microsoft Defender.',
                'virus' => $detection['ThreatName'] ?? 'Unknown threat',
                'output' => [$after['stdout'] ?? ''],
                'detection' => $detection,
                'scan_command' => 'Start-MpScan -ScanType CustomScan -ScanPath <file>',
            ];
        }

        return [
            'status' => 'clean',
            'message' => 'No threat detection found for the uploaded file.',
            'virus' => null,
            'output' => [$scan['stdout']],
            'scan_command' => 'Start-MpScan -ScanType CustomScan -ScanPath <file>',
        ];
    }

    protected function getThreatDetections(): array
    {
        $result = $this->runPowerShell(
            'Get-MpThreatDetection | Select-Object ThreatName, Resources, InitialDetectionTime, ActionSuccess, CurrentAction, DomainUser | ConvertTo-Json -Compress'
        );

        if (!$result['success']) {
            return [
                'items' => [],
                'stdout' => $result['stdout'] ?? '',
                'stderr' => $result['stderr'] ?? '',
            ];
        }

        $decoded = json_decode($result['stdout'], true);

        if ($decoded === null || $decoded === '') {
            return [
                'items' => [],
                'stdout' => $result['stdout'] ?? '',
                'stderr' => $result['stderr'] ?? '',
            ];
        }

        if (isset($decoded['ThreatName']) || isset($decoded['Resources'])) {
            $decoded = [$decoded];
        }

        return [
            'items' => is_array($decoded) ? $decoded : [],
            'stdout' => $result['stdout'] ?? '',
            'stderr' => $result['stderr'] ?? '',
        ];
    }

    protected function findDetectionForPath(string $filePath, array $before, array $after): ?array
    {
        $beforeHashes = [];
        foreach ($before as $item) {
            $beforeHashes[] = md5(json_encode($item));
        }

        foreach ($after as $item) {
            $hash = md5(json_encode($item));
            $resources = $item['Resources'] ?? [];

            if (!is_array($resources)) {
                $resources = [$resources];
            }

            foreach ($resources as $resource) {
                if (is_string($resource) && stripos($resource, $filePath) !== false) {
                    return $item;
                }
            }

            if (!in_array($hash, $beforeHashes, true)) {
                foreach ($resources as $resource) {
                    if (is_string($resource) && stripos($resource, basename($filePath)) !== false) {
                        return $item;
                    }
                }
            }
        }

        return null;
    }

    protected function runPowerShell(string $script): array
    {
        $command = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ' . escapeshellarg($script);

        $output = [];
        $exitCode = null;
        exec($command . ' 2>&1', $output, $exitCode);

        $stdout = implode("\n", $output);
        $success = ($exitCode === 0);

        return [
            'success' => $success,
            'exit_code' => $exitCode,
            'stdout' => $stdout,
            'stderr' => $success ? '' : $stdout,
            'command' => $command,
        ];
    }

    protected function escapePowerShellString(string $value): string
    {
        return str_replace("'", "''", $value);
    }

    protected function isWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows';
    }
}
?>
