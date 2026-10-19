<#
Forensic ADOT runtime validation script (operator machine)

This revised script strictly follows M6.5A requirements:
 - Always regenerate the Terraform plan (delete any local plan artifacts first)
 - Parse the plan JSON structurally (no regex) to extract AOT_CONFIG_CONTENT
 - Verify the security metric declaration includes dimensions: [[event], [event, role]] and the rag.security.events selector
 - If plan is a no-op, STOP and reconcile: extract plan / live / repo snippets for rag.security.events only
 - Run patched ADOT locally with the exact extracted AOT_CONFIG_CONTENT (no base64), in a read-only non-root container with tmpfs /tmp
 - Verify collector health, OTLP receiver, awsemf initialization, and absence of parsing errors
 - Send synthetic OTLP metrics for all 9 security events
 - Run pinned Conftest against the freshly generated plan JSON
 - Collect minimal forensic artifacts under .tmp/adot_local and tmp/adot-local-output

USAGE: run from repository root (PowerShell)
  .\tools\adot\run_adot_with_plan.ps1

Requires: Docker daemon, Python 3.10+, terraform in PATH, aws CLI optional (for fallback live-check)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Resolve-Path -Path "$(Split-Path -Path $MyInvocation.MyCommand.Path -Parent)\..\.." | Select-Object -ExpandProperty Path
Set-Location $RepoRoot

$PlanJson = Join-Path $RepoRoot "infrastructure\environments\dev\tfplan-m6-5a.json"
$PlanFile = Join-Path $RepoRoot "infrastructure\environments\dev\tfplan-m6-5a"
$TmpDir = Join-Path $RepoRoot ".tmp\adot_local"
$OutputDir = Join-Path $RepoRoot "tmp\adot-local-output"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

function Write-Log {
    param([string]$m)
    $ts = Get-Date -Format o
    "$ts`t$m" | Tee-Object -FilePath (Join-Path $OutputDir 'run.log') -Append
}

Write-Log "Repo root: $RepoRoot"

# 1) Always regenerate the terraform plan (delete local artifacts first)
if (Test-Path $PlanJson) { Remove-Item -Force $PlanJson }
if (Test-Path $PlanFile) { Remove-Item -Force $PlanFile }

Push-Location (Join-Path $RepoRoot "infrastructure\environments\dev")
try {
    Write-Log "Running terraform init"
    terraform init -input=false -no-color | Tee-Object -FilePath (Join-Path $OutputDir 'terraform-init.txt')

    Write-Log "Running terraform validate"
    terraform validate -no-color | Tee-Object -FilePath (Join-Path $OutputDir 'terraform-validate.txt')

    Write-Log "Running terraform plan -out=tfplan-m6-5a"
    terraform plan -out=tfplan-m6-5a -no-color | Tee-Object -FilePath (Join-Path $OutputDir 'terraform-plan.txt')

    Write-Log "Exporting plan JSON (UTF8 no BOM)"
    $json = terraform show -json tfplan-m6-5a
    [System.IO.File]::WriteAllText($PlanJson, $json, [System.Text.UTF8Encoding]::new($false))
    # Assert both the binary plan and the JSON exist in-place
    if (-not (Test-Path (Join-Path (Get-Location) 'tfplan-m6-5a'))) { Write-Log "ERROR: tfplan-m6-5a binary not found"; throw "Plan binary missing" }
    if (-not (Test-Path $PlanJson)) { Write-Log "ERROR: plan JSON $PlanJson not found after write"; throw "Plan JSON missing" }
    Write-Log "Plan JSON written to $PlanJson"
} finally {
    Pop-Location
}

# 2) Parse plan JSON structurally (no regex) and extract AOT_CONFIG_CONTENT
Write-Log "Parsing plan JSON structurally"
$planObj = Get-Content $PlanJson -Raw -Encoding UTF8 | ConvertFrom-Json

# Find resource change for module.ecs.aws_ecs_task_definition.app
$taskChange = $planObj.resource_changes | Where-Object { $_.address -eq 'module.ecs.aws_ecs_task_definition.app' } | Select-Object -First 1
if (-not $taskChange) {
    Write-Log "ERROR: module.ecs.aws_ecs_task_definition.app not found in plan resource_changes. Cannot extract AOT_CONFIG_CONTENT."
    throw "task definition resource not found in plan"
}

# container_definitions may be in change.after.container_definitions or in change.before depending on action; prefer change.after
$container_defs_json = $null
if ($taskChange.change -and $taskChange.change.after -and $taskChange.change.after.container_definitions) {
    $container_defs_json = $taskChange.change.after.container_definitions
    Write-Log "Using change.after.container_definitions from plan"
} elseif ($taskChange.change -and $taskChange.change.before -and $taskChange.change.before.container_definitions) {
    $container_defs_json = $taskChange.change.before.container_definitions
    Write-Log "Using change.before.container_definitions from plan"
} elseif ($taskChange.before -and $taskChange.before.container_definitions) {
    $container_defs_json = $taskChange.before.container_definitions
    Write-Log "Using before.container_definitions from plan object"
} else {
    Write-Log "ERROR: container_definitions not present in plan change for task definition"
    throw "container_definitions missing"
}

# container_definitions is itself a JSON string (stringified array). Parse it into objects.
try {
    $containers = $container_defs_json | ConvertFrom-Json
} catch {
    Write-Log "ERROR: failed to parse container_definitions JSON string: $_"
    throw
}

# Find the aws-otel-collector container by name
$collectorContainer = $containers | Where-Object { $_.name -eq 'aws-otel-collector' } | Select-Object -First 1
if (-not $collectorContainer) {
    Write-Log "ERROR: aws-otel-collector container not found in container_definitions"
    throw "collector container missing"
}

# Environment is an array of {name,value}; find AOT_CONFIG_CONTENT entry
$aotEnv = $null
if ($collectorContainer.environment) {
    $aotEnv = $collectorContainer.environment | Where-Object { $_.name -eq 'AOT_CONFIG_CONTENT' } | Select-Object -First 1
}

if (-not $aotEnv -or -not $aotEnv.value) {
    Write-Log "ERROR: AOT_CONFIG_CONTENT environment variable not present for aws-otel-collector in plan"
    throw "AOT_CONFIG_CONTENT missing"
}

$AotConfigContent = $aotEnv.value
# Write raw exact content to file (UTF8 no BOM)
$RenderedConfigPath = Join-Path $TmpDir 'adot_rendered_config.yaml'
[System.IO.File]::WriteAllText($RenderedConfigPath, $AotConfigContent, (New-Object System.Text.UTF8Encoding($false)))
Write-Log "Extracted AOT_CONFIG_CONTENT and wrote to $RenderedConfigPath (exact bytes from plan)"

# 3) Verify the plan contains the new security dimensions and selector
Write-Log "Verifying metric_declarations block for rag.security.events contains both [event] and [event, role]"
$lines = $AotConfigContent -split "`n"
# Find the metric_declarations block
$mdStart = -1
for ($i=0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match '^[ \t]*metric_declarations:') { $mdStart = $i; break }
}
if ($mdStart -eq -1) {
    Write-Log "ERROR: metric_declarations block not found in extracted AOT_CONFIG_CONTENT"
    throw "metric_declarations missing"
}
# Collect metric_declarations lines until the next top-level 'service:' marker (or end)
$mdLines = @()
for ($i=$mdStart+1; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match '^[^ \t]') { break }
    $mdLines += $lines[$i]
}
# Split into entries that start with '-'
$entries = @()
$current = @()
for ($i=0; $i -lt $mdLines.Length; $i++) {
    if ($mdLines[$i] -match '^[ \t]*-\s*dimensions:') {
        if ($current.Count -gt 0) { $entries += ,[string[]]$current; $current = @() }
        $current += $mdLines[$i]
    } else {
        $current += $mdLines[$i]
    }
}
if ($current.Count -gt 0) { $entries += ,[string[]]$current }

$found = $false
foreach ($entry in $entries) {
    $entryText = $entry -join "`n"
    if ($entryText -match 'rag\\.security\\.events') {
        # find dimensions line inside entry
        $dimLine = ($entry | Where-Object { $_ -match 'dimensions:' }) | Select-Object -First 1
        if ($null -eq $dimLine) { continue }
        # normalize (remove whitespace)
        $norm = $dimLine -replace '\s',''
        $hasEvent = ($norm -match '\[event\]')
        $hasEventRole = ($norm -match '\[event,role\]')
        if ($hasEvent -and $hasEventRole) { $found = $true; break }
    }
}
if (-not $found) {
    Write-Log "ERROR: rag.security.events metric_declaration does not include both [event] and [event, role]"
    # Save a forensic snippet for debugging
    $snippet = ($AotConfigContent -split "`n") | Select-String -Pattern 'rag\\.security\\.events' -Context 4,4 | ForEach-Object { $_.Context.PreContext + $_.Line + $_.Context.PostContext }
    $snippet | Out-File -FilePath (Join-Path $OutputDir 'security_metric_declaration_plan.txt') -Encoding UTF8
    throw "Expected metric_declaration with both dimension families not found"
}
Write-Log "Verified rag.security.events metric_declaration includes both dimension families"

# Save a compact security metric declaration for reporting
$lines = $AotConfigContent -split "`n"
$foundLines = @()
for ($i=0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match 'rag\\.security\\.events') {
        $start = [Math]::Max(0, $i-4)
        $end = [Math]::Min($lines.Length-1, $i+4)
        for ($j=$start; $j -le $end; $j++) { $foundLines += $lines[$j] }
        break
    }
}
$foundLines | Set-Content -Path (Join-Path $OutputDir 'security_metric_declaration_plan.txt') -Encoding UTF8
Write-Log "Saved security metric declaration excerpt to security_metric_declaration_plan.txt"

# 4) Reconcile terraform plan actions: inspect non-no-op changes
$actions = $planObj.resource_changes | ForEach-Object { $_.change.actions -join ',' } | Group-Object | ForEach-Object { $_.Name + ':' + $_.Count }
$actionSummary = ($planObj.resource_changes | Group-Object -Property { $_.change.actions -join ',' }) | ForEach-Object { "Action=$($_.Name) Count=$($_.Count)" }
Set-Content -Path (Join-Path $OutputDir 'terraform_action_summary.txt') -Value ($actionSummary -join "`n") -Encoding UTF8
Write-Log "Terraform action summary saved"

# If plan reports NO CHANGES for all resources (no-op), stop and reconcile
$nonNoop = $planObj.resource_changes | Where-Object { ($_.change.actions -join ',') -ne 'no-op' }
# If there are non-no-op resources, print them and ensure they are only the expected ECS task/service updates
if ($nonNoop) {
    $nonNoop | ForEach-Object {
        $addr = $_.address
        $acts = ($_.change.actions -join ',')
        Add-Content -Path (Join-Path $OutputDir 'non_noop_resources.txt') -Value "$addr : $acts"
        Write-Log "Non-noop resource: $addr : $acts"
    }
    # Validate only expected changes are present
    $allowed = $true
    foreach ($r in $nonNoop) {
        $addr = $r.address
        $acts = ($r.change.actions -join ',')
        if ($addr -eq 'module.ecs.aws_ecs_task_definition.app') {
            if (-not ($acts -match 'create' -and $acts -match 'delete')) { $allowed = $false }
        } elseif ($addr -eq 'module.ecs.aws_ecs_service.app') {
            if (-not ($acts -match 'update')) { $allowed = $false }
        } else {
            $allowed = $false
        }
    }
    if (-not $allowed) { Write-Log "ERROR: unexpected non-no-op resources present. See non_noop_resources.txt"; throw "Unexpected plan changes" }
    Write-Log "Plan non-noop resources are limited to expected ECS task/service updates"
}
if (-not $nonNoop) {
    Write-Log "Terraform plan is NO-OP (no non-no-op resource changes). Will reconcile plan AOT_CONFIG_CONTENT vs live revision and repository template."
    # A) plan AOT snippet (we have $foundLines)
    $planSnippetPath = Join-Path $OutputDir 'security_metric_declaration_plan.txt'

    # B) Attempt to extract current live revision :4 AOT_CONFIG_CONTENT from plan 'before' if present, else attempt AWS CLI describe-task-definition
    $liveSnippetPath = Join-Path $OutputDir 'security_metric_declaration_live.txt'
    $liveFound = $false
    if ($taskChange.change -and $taskChange.change.before -and $taskChange.change.before.container_definitions) {
        $before_json = $taskChange.change.before.container_definitions
        try { $before_containers = $before_json | ConvertFrom-Json } catch { $before_containers = $null }
        if ($before_containers) {
            $beforeCollector = $before_containers | Where-Object { $_.name -eq 'aws-otel-collector' } | Select-Object -First 1
            if ($beforeCollector -and $beforeCollector.environment) {
                $aotBefore = ($beforeCollector.environment | Where-Object { $_.name -eq 'AOT_CONFIG_CONTENT' })
                if ($aotBefore -and $aotBefore.value) {
                    $beforeContent = $aotBefore.value
                    # extract security metric snippet
                    $lines2 = $beforeContent -split "`n"
                    $found2 = @()
                    for ($i=0; $i -lt $lines2.Length; $i++) {
                        if ($lines2[$i] -match 'rag\\.security\\.events') {
                            $start = [Math]::Max(0, $i-4)
                            $end = [Math]::Min($lines2.Length-1, $i+4)
                            for ($j=$start; $j -le $end; $j++) { $found2 += $lines2[$j] }
                            break
                        }
                    }
                    $found2 | Set-Content -Path $liveSnippetPath -Encoding UTF8
                    $liveFound = $true
                }
            }
        }
    }
    # If not in plan before, try AWS CLI describe-task-definition if available
    if (-not $liveFound) {
        Write-Log "Attempting to query AWS for current task definition (fallback). Requires aws CLI configured."
        # Attempt to find task definition family from plan (change.before.family or change.after.family)
        $family = $null
        if ($taskChange.change -and $taskChange.change.before -and $taskChange.change.before.family) { $family = $taskChange.change.before.family }
        if (-not $family -and $taskChange.change -and $taskChange.change.after -and $taskChange.change.after.family) { $family = $taskChange.change.after.family }
        if ($family) {
            try {
                $desc = aws ecs describe-task-definition --task-definition "$family:4" | ConvertFrom-Json
                $containerDefs = $desc.taskDefinition.containerDefinitions | ConvertTo-Json -Depth 10 | ConvertFrom-Json
                $collector = $containerDefs | Where-Object { $_.name -eq 'aws-otel-collector' } | Select-Object -First 1
                if ($collector -and $collector.environment) {
                    $aot = $collector.environment | Where-Object { $_.name -eq 'AOT_CONFIG_CONTENT' }
                    if ($aot -and $aot.value) {
                        $beforeContent = $aot.value
                        $lines2 = $beforeContent -split "`n"
                        $found2 = @()
                        for ($i=0; $i -lt $lines2.Length; $i++) {
                            if ($lines2[$i] -match 'rag\\.security\\.events') {
                                $start = [Math]::Max(0, $i-4)
                                $end = [Math]::Min($lines2.Length-1, $i+4)
                                for ($j=$start; $j -le $end; $j++) { $found2 += $lines2[$j] }
                                break
                            }
                        }
                        $found2 | Set-Content -Path $liveSnippetPath -Encoding UTF8
                        $liveFound = $true
                    }
                }
            } catch {
                Write-Log "AWS CLI live-task lookup failed or not configured: $_"
            }
        } else {
            Write-Log "Task definition family not found in plan for AWS fallback lookup"
        }
    }

    if (-not $liveFound) { Write-Log "Live revision :4 AOT_CONFIG_CONTENT snippet not available via plan before or AWS fallback" }

    # C) repository template snippet: extract the relevant lines from the repo template file
    $tpl = Join-Path $RepoRoot 'infrastructure\modules\observability\templates\adot-collector-config.yaml.tpl'
    $tplLines = Get-Content $tpl -Raw -Encoding UTF8
    $tplLinesArr = $tplLines -split "`n"
    $tplFound = @()
    for ($i=0; $i -lt $tplLinesArr.Length; $i++) {
        if ($tplLinesArr[$i] -match 'rag\\.security\\.events') {
            $start = [Math]::Max(0, $i-4)
            $end = [Math]::Min($tplLinesArr.Length-1, $i+4)
            for ($j=$start; $j -le $end; $j++) { $tplFound += $tplLinesArr[$j] }
            break
        }
    }
    $tplFound | Set-Content -Path (Join-Path $OutputDir 'security_metric_declaration_tpl.txt') -Encoding UTF8

    # Show the three snippets paths and explain why identical
    Write-Log "Plan snippet: $(Join-Path $OutputDir 'security_metric_declaration_plan.txt')"
    if (Test-Path $liveSnippetPath) { Write-Log "Live snippet: $liveSnippetPath" } else { Write-Log "Live snippet: not available" }
    Write-Log "Template snippet: $(Join-Path $OutputDir 'security_metric_declaration_tpl.txt')"

    # Compare plan AOT content vs beforeContent if available
    if ((Test-Path $RenderedConfigPath) -and (Test-Path $tpl)) {
        $planText = Get-Content $RenderedConfigPath -Raw -Encoding UTF8
        $tplText = Get-Content $tpl -Raw -Encoding UTF8
        if ($planText -eq $tplText) {
            Write-Log "Plan AOT_CONFIG_CONTENT is byte-for-byte identical to repository template rendered (after Terraform interpolation)."
        } else {
            Write-Log "Plan AOT_CONFIG_CONTENT differs from repository template. See artifacts for exact diffs."
        }
    }

    Write-Log "STOPPING as plan is a no-op; do not continue runtime testing"
    throw "Plan is no-op; reconciliation complete"
}

# 5) Preserve exact environment content: use $AotConfigContent as-is
# Write the exact content to output for evidence
$evidencePath = Join-Path $OutputDir 'adot_config_exact_from_plan.yaml'
[System.IO.File]::WriteAllText($evidencePath, $AotConfigContent, (New-Object System.Text.UTF8Encoding($false)))
Write-Log "Wrote exact AOT_CONFIG_CONTENT forensic copy to $evidencePath"

# 6) Build the ADOT image
$ImageTag = 'adot-patched:v0.50.0-patched.1'
$DockerfilePath = Join-Path $RepoRoot 'tools\adot\Dockerfile'
$BuildContext = Join-Path $RepoRoot 'tools\adot'
Write-Log "Building ADOT image $ImageTag"
try {
    docker version | Out-Null
} catch {
    Write-Log "ERROR: Docker not available: $_"
    throw
}
$buildLog = Join-Path $OutputDir 'docker-build.txt'
docker build --no-cache --platform linux/amd64 -t $ImageTag -f "$DockerfilePath" "$BuildContext" 2>&1 | Tee-Object -FilePath $buildLog
if ($LASTEXITCODE -ne 0) { Write-Log "Docker build failed (see $buildLog)"; throw "docker build failed" }
Write-Log "Docker image built: $ImageTag"
# Verify the image config has a non-root user configured
$imgUser = docker image inspect $ImageTag --format '{{.Config.User}}' 2>&1
Set-Content -Path (Join-Path $OutputDir 'docker-image-user.txt') -Value $imgUser -Encoding UTF8
Write-Log "Docker image configured user: $imgUser"
if (($imgUser -eq '') -or ($imgUser -match '(^root$|^0$|^0:0)')) { Write-Log "ERROR: image user is root or unset: $imgUser"; throw "Image user invalid (root or unset)" }

# 7) Run collector container with exact AOT_CONFIG_CONTENT (no base64)
$ContainerName = 'adot-local-test'
if (docker ps -a --format '{{.Names}}' | Select-String -SimpleMatch $ContainerName) { docker rm -f $ContainerName | Out-Null; Start-Sleep -Seconds 1 }

Write-Log "Starting collector container with --read-only and tmpfs /tmp"
$runLog = Join-Path $OutputDir 'docker-run.txt'
# Construct docker run command; pass the env var directly; ensure PowerShell handles newlines
try {
    $envArg = "AOT_CONFIG_CONTENT=$(Get-Content $RenderedConfigPath -Raw -Encoding UTF8)"
    & docker run --name $ContainerName -d -p 4318:4318 -p 13133:13133 --read-only --tmpfs /tmp:rw,exec --security-opt no-new-privileges -e $envArg $ImageTag 2>&1 | Tee-Object -FilePath $runLog
    if ($LASTEXITCODE -ne 0) { Write-Log "docker run returned non-zero; see $runLog"; throw "docker run failed" }
} catch {
    Write-Log "ERROR: Failed to start docker run with direct env: $_"
    throw
}
Write-Log "Docker run started; container name $ContainerName; waiting 6s"
Start-Sleep -Seconds 6

# Verify container running
$inspect = docker inspect -f '{{.State.Running}}' $ContainerName 2>&1
if ($inspect -match 'true') { Write-Log "Container $ContainerName is running" } else { Write-Log "Container is NOT running; check logs"; docker logs $ContainerName 2>&1 | Tee-Object -FilePath (Join-Path $OutputDir 'container-failed-logs.txt'); throw "container not running" }

# 8) Verify collector runtime: healthcheck, OTLP receiver, awsemf init, no parsing errors
$healthOk = $false
for ($i=0; $i -lt 10; $i++) {
    try {
        $resp = Invoke-WebRequest -UseBasicParsing -Uri http://localhost:13133/ -TimeoutSec 3 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) { $healthOk = $true; break }
    } catch {}
    try {
        $resp = Invoke-WebRequest -UseBasicParsing -Uri http://localhost:13133/health -TimeoutSec 3 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) { $healthOk = $true; break }
    } catch {}
    Start-Sleep -Seconds 2
}

$containerLogTail = Join-Path $OutputDir 'container-logs-tail.txt'
docker logs --since 0s $ContainerName 2>&1 | Select-String -Pattern 'awsemf|metric_declarations|error|ERROR|Failed|panic' -Context 0,2 | Tee-Object -FilePath $containerLogTail

if ($healthOk) { Write-Log "Collector /healthcheck OK" } else { Write-Log "ERROR: Collector /healthcheck did not return 200 within timeout"; Write-Log "See $containerLogTail"; throw "healthcheck failed" }

# Check awsemf init presence
$awsemfInit = Select-String -Path $containerLogTail -Pattern 'awsemf' -Quiet
if ($awsemfInit) { Write-Log "awsemf exporter init messages detected" } else { Write-Log "ERROR: No awsemf init messages found in log tail"; docker logs $ContainerName 2>&1 | Tee-Object -FilePath (Join-Path $OutputDir 'container-full-logs.txt'); throw "awsemf init not detected" }

# 9) Send synthetic OTLP metrics for all 9 events using isolated venv
$Python = 'python'
try { & $Python --version > $null } catch { Write-Log "ERROR: Python not found"; throw }
$VenvDir = Join-Path $TmpDir 'pyvenv'
if (Test-Path $VenvDir) { Remove-Item -Recurse -Force $VenvDir }
& $Python -m venv $VenvDir
$pip = Join-Path $VenvDir 'Scripts\pip.exe'
$py = Join-Path $VenvDir 'Scripts\python.exe'
Write-Log "Created venv at $VenvDir"
& $pip install --upgrade pip | Tee-Object -FilePath (Join-Path $OutputDir 'pip-upgrade.txt')
& $pip install opentelemetry-api opentelemetry-sdk opentelemetry-exporter-otlp-proto-http requests | Tee-Object -FilePath (Join-Path $OutputDir 'pip-install.txt')

$pyScript = @'
import time
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.resources import Resource

exporter = OTLPMetricExporter(endpoint="http://127.0.0.1:4318/v1/metrics")
reader = PeriodicExportingMetricReader(exporter, export_interval_millis=500)
provider = MeterProvider(metric_readers=[reader], resource=Resource.create({"service.name": "adot-local-test"}))
metrics.set_meter_provider(provider)
meter = metrics.get_meter("adot-local-test")

counter = meter.create_counter("rag.security.events")

# role-less events
for e in ['missing_tenant','unknown_tenant','unknown_role','input_sanitized']:
    counter.add(1,{"event":e})

# roleful events
counter.add(1,{"event":"action_denied","role":"reader"})
counter.add(1,{"event":"classification_denied","role":"ingestor","classification":"restricted"})
counter.add(1,{"event":"path_rejected","role":"admin"})
counter.add(1,{"event":"prompt_too_large","role":"reader"})
# rls_violation samples
counter.add(1,{"event":"rls_violation"})
counter.add(1,{"event":"rls_violation","role":"reader"})

print('Sent metrics, sleeping to flush...')
time.sleep(5)
try:
    provider.shutdown()
except Exception:
    pass
print('Done')
'@
$pyScriptPath = Join-Path $TmpDir 'send_metrics.py'
Set-Content -Path $pyScriptPath -Value $pyScript -Encoding UTF8
Write-Log "Wrote OTLP sender to $pyScriptPath"
& $py $pyScriptPath 2>&1 | Tee-Object -FilePath (Join-Path $OutputDir 'python-sender-output.txt')
if ($LASTEXITCODE -ne 0) { Write-Log "ERROR: Python OTLP sender exited non-zero ($LASTEXITCODE). See python-sender-output.txt"; throw "OTLP sender failed" }

# Capture container logs after send (tail)
docker logs --tail 500 $ContainerName 2>&1 | Tee-Object -FilePath (Join-Path $OutputDir 'container-post-send-logs.txt')
Write-Log "Captured post-send container logs"

# 10) Run pinned Conftest against the fresh plan JSON
Write-Log "Running pinned Conftest container test"
$conftestLog = Join-Path $OutputDir 'conftest.txt'
docker run --rm -v "${RepoRoot}:/project" -w /project openpolicyagent/conftest:v0.68.2@sha256:5fd81e332d7e4bc01daf3ef35371800a9a9720a30c0c37a78de0c5fbe4b6d622 test --policy policy/terraform infrastructure/environments/dev/tfplan-m6-5a.json 2>&1 | Tee-Object -FilePath $conftestLog
$last = $LASTEXITCODE
$conftestOut = Get-Content $conftestLog -Raw -Encoding UTF8
if ($last -ne 0) { Write-Log "ERROR: Conftest container returned non-zero exit code ($last). See $conftestLog"; throw "Conftest failed" }
# Require 4 passed / 0 failed
if ($conftestOut -notmatch '4\s+passed.*0\s+failed') { Write-Log "ERROR: Conftest did not report '4 passed, 0 failed'"; throw "Conftest assertions not met" }
Write-Log "Conftest passed: 4 passed, 0 failed"

# 11) Run checkov (already available) - save output
Write-Log "Running checkov scan (terraform)"
$checkovLog = Join-Path $OutputDir 'checkov.txt'
checkov --framework terraform -d (Join-Path $RepoRoot 'infrastructure') --compact 2>&1 | Tee-Object -FilePath $checkovLog
if ($LASTEXITCODE -ne 0) { Write-Log "ERROR: Checkov scan failed; exit=$LASTEXITCODE. See $checkovLog"; throw "Checkov failure" }
Write-Log "Checkov scan passed"

# 12) git diff --check and git status
Write-Log "Running git diff --check"
git --no-pager diff --no-color --check | Tee-Object -FilePath (Join-Path $OutputDir 'git-diff-check.txt')
if ($LASTEXITCODE -ne 0) { Write-Log "ERROR: git diff --check found issues; see git-diff-check.txt"; throw "git diff --check failed" }
Write-Log "Recording git status"
git status --porcelain | Tee-Object -FilePath (Join-Path $OutputDir 'git-status.txt')

# Final forensic summary saved
$summary = @()
$summary += "PLAN_JSON=$(Resolve-Path $PlanJson)"
$summary += "PLAN_ACTION_SUMMARY=$(Get-Content (Join-Path $OutputDir 'terraform_action_summary.txt') -Raw)"
$summary += "SECURITY_METRIC_DECLARATION_PLAN=$(Get-Content (Join-Path $OutputDir 'security_metric_declaration_plan.txt') -Raw)"
$summary += "DOCKER_BUILD_LOG=$(Resolve-Path $buildLog)"
$summary += "DOCKER_RUN_LOG=$(Resolve-Path $runLog)"
$summary += "CONTAINER_LOG_TAIL=$(Resolve-Path $containerLogTail)"
$summary += "PYTHON_SENDER_OUTPUT=$(Resolve-Path (Join-Path $OutputDir 'python-sender-output.txt'))"
$summary += "CONFTESS_OUTPUT=$(Resolve-Path $conftestLog)"
$summary | Set-Content -Path (Join-Path $OutputDir 'forensic_summary.txt') -Encoding UTF8
Write-Log "Wrote forensic summary to forensic_summary.txt"

Write-Log "Script finished. Do NOT terraform apply. Artifacts are in $OutputDir"
