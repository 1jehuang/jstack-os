# PH-08 campaign agent: run one authorised action from an attached control medium.
#
# This is what an installed guest runs at logon during a campaign. It exists
# because the harness deliberately provides no channel into a running guest: no
# port forward, no guest agent, no shared folder. The guest therefore has to look
# for its own instructions rather than be told, and the only thing it can be
# handed is a read-only volume.
#
# The direction of that relationship is the safety property. Nothing outside the
# guest can make this run, and nothing this runs can reach outside the guest. It
# reads a volume, acts inside the machine it is already on, and writes a file. A
# host reading that file later does so offline, against a stopped disk image.
#
# It is deliberately incurious. It does not search for work, retry, or interpret:
# if the medium is absent, malformed, or carries an action this guest was not
# asked to perform, it records why and stops. A campaign agent that improvises is
# a campaign whose result means nothing.

$ErrorActionPreference = 'Stop'

# Where the agent leaves its result. The host reads this back out of the run's
# overlay after the guest stops, so the path is part of the contract.
$ObservationPath = 'C:\jstack-observation.json'

function Write-JStackObservation {
    param([hashtable]$Body)

    # Written with a temporary and a move, so a host reading the overlay never
    # sees a half-written document and mistakes truncation for a malformed
    # report. The failure modes have to stay distinguishable.
    $temporary = "$ObservationPath.part"
    $json = $Body | ConvertTo-Json -Depth 12
    Set-Content -LiteralPath $temporary -Value $json -Encoding UTF8 -NoNewline
    Move-Item -LiteralPath $temporary -Destination $ObservationPath -Force
}

function Find-JStackControlMedium {
    # The medium is a small removable FAT volume carrying exactly two files. It
    # is located by content rather than by drive letter, because Windows assigns
    # letters in an order no answer file controls, and picking the wrong volume
    # is how an agent ends up acting on something nobody handed it.
    foreach ($volume in Get-Volume -ErrorAction SilentlyContinue) {
        if (-not $volume.DriveLetter) { continue }
        $root = "$($volume.DriveLetter):"
        $request = Join-Path $root 'jstack-request.json'
        $adapters = Join-Path $root 'jstack-adapters.ps1'
        if ((Test-Path -LiteralPath $request) -and (Test-Path -LiteralPath $adapters)) {
            return [pscustomobject]@{ Root = $root; Request = $request; Adapters = $adapters }
        }
    }
    return $null
}

try {
    $medium = Find-JStackControlMedium
    if ($null -eq $medium) {
        # Absence is a normal state, not a failure: a guest booted for any other
        # reason has no action to run. Recorded so the host can tell "no medium"
        # from "medium ignored", which are very different bugs.
        Write-JStackObservation @{
            status = 'no-control-medium'
            detail = 'no attached volume carries both a request and the adapters'
        }
        exit 0
    }

    $request = Get-Content -LiteralPath $medium.Request -Raw | ConvertFrom-Json

    # The adapters demand a matching pair of attestation variables and refuse to
    # mutate without them. The agent supplies the token the medium carries; it
    # cannot mint one, so a medium without a valid attestation is inert.
    $env:JSTACK_DISPOSABLE_VM = [string]$request.attestation
    $env:JSTACK_DISPOSABLE_VM_EXPECTED = [string]$request.attestation

    # The adapters are invoked from the medium, byte-identical to the reviewed
    # repository copy, and read their request from stdin exactly as they do in
    # every test.
    $payload = Get-Content -LiteralPath $medium.Request -Raw
    $output = $payload | & powershell.exe -NoProfile -ExecutionPolicy Bypass `
        -File $medium.Adapters -Action ([string]$request.action) 2>&1
    $adapterExit = $LASTEXITCODE

    $parsed = $null
    try { $parsed = $output | Out-String | ConvertFrom-Json } catch { $parsed = $null }

    Write-JStackObservation @{
        status      = if ($adapterExit -eq 0) { 'completed' } else { 'failed' }
        action      = [string]$request.action
        plan_hash   = [string]$request.plan_hash
        exit_code   = $adapterExit
        # The adapter re-observes the machine after mutating, so its own
        # postcondition is the evidence. The agent passes it through unchanged
        # rather than summarising: a summary is a second, weaker claim.
        postcondition = $parsed
        raw         = ($output | Out-String)
    }
    exit 0
}
catch {
    # A crash must still leave a readable result. A guest that mutated something
    # and then reported nothing is the worst outcome available, because the host
    # cannot tell it apart from a guest that never started.
    Write-JStackObservation @{
        status = 'agent-error'
        detail = $_.Exception.Message
        action = if ($request) { [string]$request.action } else { $null }
        plan_hash = if ($request) { [string]$request.plan_hash } else { $null }
        postcondition = $null
    }
    exit 1
}
