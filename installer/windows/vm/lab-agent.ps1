# Disposable test VM only. Polls the host for PowerShell commands and posts
# their output back. Host side: installer/windows/vm/lab.py.
$base = 'http://10.0.2.2:8765'
$wc = New-Object System.Net.WebClient
while ($true) {
    try {
        $job = $wc.DownloadString("$base/next")
        if ($job -and $job.Trim()) {
            $id, $script = $job -split "`n", 2
            try {
                $out = & ([scriptblock]::Create($script)) 2>&1 | Out-String -Width 400
                $code = if ($?) { 0 } else { 1 }
            } catch {
                $out = ($_ | Out-String); $code = 2
            }
            $wc.Headers['Content-Type'] = 'text/plain; charset=utf-8'
            [void]$wc.UploadString("$base/done?id=$id&code=$code", $out)
        } else {
            Start-Sleep -Seconds 1
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}
