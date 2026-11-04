#requires -Version 5.1
<#
.SYNOPSIS
    2026년 11월 니케 PC 런처 사건의 공개 감염 지표를 읽기 전용으로 확인합니다.
.PARAMETER NikkePath
    자동으로 찾지 못한 게임 설치 폴더 또는 Launcher 폴더를 지정합니다.
.PARAMETER Json
    결과를 JSON으로 표준 출력에 표시합니다.
#>
[CmdletBinding()]
param(
    [string[]]$NikkePath = @(),
    [switch]$Json
)

if ($env:OS -ne 'Windows_NT') { throw '이 스크립트는 Windows용입니다.' }
if ($Json) { $ProgressPreference = 'SilentlyContinue' }

$checks = [System.Collections.Generic.List[object]]::new()
$launchers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$fixedDrives = @([IO.DriveInfo]::GetDrives() | Where-Object DriveType -eq Fixed | ForEach-Object Name)
$domains = @('insightjs.com', 'analytics.insightjs.com', 'insightjs.org')
$knownIPs = @('89.127.233.127', '89.126.250.172')
$payloadHashes = @(
    '60fd53ab7356384ba2161b9bc84420cd170905011a2f3ca09f3e38fe3122f3a1',
    'cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec'
)

function Add-Finding([string]$Name, [string]$Status, [string]$Detail) {
    $checks.Add([pscustomobject][ordered]@{ Check = $Name; Status = $Status; Detail = $Detail })
}

function Invoke-ReadCheck([string]$Name, [scriptblock]$Read) {
    $before = $checks.Count
    try {
        & $Read
        if ($checks.Count -eq $before) {
            Add-Finding $Name 'NotFound' '확인한 범위에서 일치하는 항목이 없습니다.'
        }
    } catch {
        # 원본 오류에는 개인 경로나 로그 내용이 들어갈 수 있습니다.
        Add-Finding $Name 'Unavailable' ('일부 항목을 읽지 못했습니다 ({0}).' -f $_.Exception.GetType().Name)
    }
}

function Test-LocalArtifact([string]$Path, [string]$Kind) {
    if ($Path -notmatch '^[A-Za-z]:\\') { return $false }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $drive = [IO.Path]::GetPathRoot($fullPath)
    if ($drive -notin $fixedDrives) { return $false }

    # Walk from the drive root so a junction in an ancestor cannot redirect a read.
    $current = $drive
    foreach ($part in ($fullPath.Substring($drive.Length) -split '\\' | Where-Object { $_ })) {
        $current = Join-Path $current $part
        try {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        } catch [System.Management.Automation.ItemNotFoundException] {
            return $false
        }
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw '재분석 지점이 있는 경로는 확인하지 않습니다.'
        }
    }
    if ($current -eq $drive) { return $Kind -eq 'Container' }
    if ($Kind -eq 'Container') { return [bool]$item.PSIsContainer }
    return -not $item.PSIsContainer
}

function Add-LauncherFolder([string]$Path) {
    if (Test-LocalArtifact $Path 'Container') {
        [void]$launchers.Add([IO.Path]::GetFullPath($Path).TrimEnd('\'))
    }
}

function Add-LaunchTime([string]$Source, [datetime]$Time) {
    $kst = [DateTimeOffset]::new($Time.ToUniversalTime()).ToOffset([TimeSpan]::FromHours(9))
    Add-Finding $Source 'Context' ('기록된 실행 시각 {0} KST. 실행 기록은 감염 여부와 별도로 해석하세요.' -f $kst.ToString('yyyy-MM-dd HH:mm:ss'))
}

Invoke-ReadCheck 'Windows 앱 실행 기록 (PCA)' {
    $pca = Join-Path $env:windir 'appcompat\pca\PcaAppLaunchDic.txt'
    if (-not (Test-LocalArtifact $pca 'Leaf')) {
        Add-Finding 'Windows 앱 실행 기록 (PCA)' 'Unavailable' 'PCA 기록 파일이 없습니다.'
        return
    }
    foreach ($line in (Select-String -LiteralPath $pca -Pattern '\\nikke_launcher\.exe\|' -ErrorAction Stop)) {
        $parts = $line.Line -split '\|', 2
        if ($parts[0] -notmatch '\\nikke_launcher\.exe$') { continue }
        $time = [datetime]::MinValue
        $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
        if ([datetime]::TryParse($parts[1], [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$time)) {
            Add-LaunchTime 'Windows 앱 실행 기록 (PCA)' $time
        }
        Add-LauncherFolder (Split-Path -Parent $parts[0])
    }
}

Invoke-ReadCheck 'Windows 사용자 실행 기록 (UserAssist)' {
    $keys = @(Get-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count' -ErrorAction SilentlyContinue)
    if ($keys.Count -eq 0) {
        Add-Finding 'Windows 사용자 실행 기록 (UserAssist)' 'Unavailable' '현재 사용자의 실행 기록 키를 읽지 못했습니다.'
    }
    foreach ($key in $keys) {
        foreach ($name in $key.GetValueNames()) {
            if ($name -notmatch 'avxxr_ynhapure\.rkr$') { continue }
            # UserAssist encodes value names using ROT13.
            $path = [regex]::Replace($name, '[A-Za-z]', {
                param($match)
                $code = [int][char]$match.Value
                $base = if ($code -le 90) { 65 } else { 97 }
                [string][char]($base + (($code - $base + 13) % 26))
            })
            $data = $key.GetValue($name)
            if ($data -is [byte[]] -and $data.Length -ge 68) {
                $fileTime = [BitConverter]::ToInt64($data, 60)
                if ($fileTime -gt 0 -and $fileTime -le [datetime]::MaxValue.ToFileTimeUtc()) {
                    Add-LaunchTime 'Windows 사용자 실행 기록 (UserAssist)' ([datetime]::FromFileTimeUtc($fileTime))
                }
            }
            if ($path -match '^[A-Za-z]:\\') { Add-LauncherFolder (Split-Path -Parent $path) }
        }
    }
}

Invoke-ReadCheck '니케 런처 로그' {
    foreach ($base in $fixedDrives + @($env:ProgramFiles, [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'))) {
        if ($base) { Add-LauncherFolder (Join-Path $base 'NIKKE\Launcher') }
    }
    $number = 0
    foreach ($requested in $NikkePath) {
        $number++
        if ($requested -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetPathRoot($requested) -notin $fixedDrives) {
            Add-Finding '니케 런처 로그' 'Unavailable' "지정 경로 #$number 에는 로컬 고정 드라이브의 절대 경로를 사용하세요."
            continue
        }
        if (Test-LocalArtifact (Join-Path $requested 'Launcher') 'Container') {
            Add-LauncherFolder (Join-Path $requested 'Launcher')
        } else {
            Add-LauncherFolder $requested
        }
    }

    $logCount = 0
    foreach ($launcher in $launchers) {
        $debug = Join-Path $launcher 'intl_service\debug.log'
        if (Test-LocalArtifact $debug 'Leaf') {
            $logCount++
            if (Select-String -LiteralPath $debug -SimpleMatch 'k2f_chan registered' -Quiet -ErrorAction Stop) {
                Add-Finding '니케 런처 로그' 'Strong' 'debug.log에 k2f_chan registered가 기록돼 있습니다.'
            }
        }
        $tinyget = Join-Path $launcher 'log\tinyget'
        if (-not (Test-LocalArtifact $tinyget 'Container')) { continue }
        $downloadReference = $false
        foreach ($file in (Get-ChildItem -LiteralPath $tinyget -File -Force -ErrorAction Stop)) {
            if ($file.Name -notmatch '^(?:k2f\.lua|tinyget(?:\..+)?\.log)$' -or
                ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
            $logCount++
            $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
            $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
            try {
                $header = New-Object byte[] 4
                $bytecode = $stream.Read($header, 0, 4) -eq 4 -and [BitConverter]::ToString($header) -eq '1B-4C-4A-01'
                if ($bytecode) {
                    $stream.Position = 0
                    if ($stream.Length -le 1MB -and (Get-FileHash -InputStream $stream -Algorithm SHA256 -ErrorAction Stop).Hash -in $payloadHashes) {
                        Add-Finding '니케 런처 로그' 'Strong' 'tinyget 파일의 SHA-256이 공개 악성 샘플과 일치합니다.'
                    } else {
                        Add-Finding '니케 런처 로그' 'Clue' 'tinyget에서 LuaJIT 바이트코드를 발견했습니다. 공개 악성 샘플과의 일치는 확인되지 않았습니다.'
                    }
                }
            } finally {
                $stream.Dispose()
            }
            if (-not $bytecode -and $file.Length -gt 32MB) {
                Add-Finding '니케 런처 로그' 'Unavailable' '크기 제한을 넘는 tinyget 텍스트 로그를 건너뛰었습니다.'
            }
            if (-not $bytecode -and -not $downloadReference -and $file.Length -le 32MB) {
                $downloadReference = Select-String -LiteralPath $file.FullName -SimpleMatch 'analytics.insightjs.com/comm/assets/insight.bundle' -Quiet -ErrorAction Stop
            }
        }
        if ($downloadReference) {
            Add-Finding '니케 런처 로그' 'Clue' 'insight.bundle 다운로드 주소가 기록돼 있습니다. 주소만으로 성공 여부를 확인할 수 없습니다.'
        }
    }
    if ($logCount -eq 0) {
        Add-Finding '니케 런처 로그' 'Unavailable' '확인한 경로에 런처 로그가 없습니다. 다른 설치 폴더가 있으면 -NikkePath로 지정하세요.'
    }
}

Invoke-ReadCheck '니케 런처 캐시' {
    $cacheFound = $false
    $hstsHashes = @{
        'wxL1BeG57AG6frvPqS7txqpE3NyN0/fSUZHCbEn9NSw=' = 'analytics.insightjs.com'
        'JeFWywdZy+3jPC93e3P7ACdJ8liQHB7rH+9VHn7kswg=' = 'insightjs.com'
    }
    foreach ($profile in @('nikke_launcher', 'nikke_launcher_hmt', 'nikke_launcher_google')) {
        $cache = Join-Path $env:APPDATA "$profile\tbs_cache"
        if (-not (Test-LocalArtifact $cache 'Container')) { continue }
        $cacheFound = $true
        $jsCache = Join-Path $cache 'Code Cache\js'
        foreach ($entry in @('dd65fa4d61079e7e_0', 'ce2fd3f1007a9fe9_0', '1416c638b3830103_0', 'fd520c7c0f65c2d7_0')) {
            if (Test-LocalArtifact (Join-Path $jsCache $entry) 'Leaf') {
                Add-Finding '니케 런처 캐시' 'Clue' "$profile 캐시에서 보고된 로더 캐시 파일명을 발견했습니다."
                break
            }
        }
        foreach ($relative in @('TransportSecurity', 'Network\TransportSecurity')) {
            $file = Join-Path $cache $relative
            if (-not (Test-LocalArtifact $file 'Leaf')) { continue }
            if ((Get-Item -LiteralPath $file -Force -ErrorAction Stop).Length -gt 8MB) {
                Add-Finding '니케 런처 캐시' 'Unavailable' '크기 제한을 넘는 HSTS 파일을 건너뛰었습니다.'
                continue
            }
            $state = Get-Content -LiteralPath $file -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            foreach ($entry in $state.sts) {
                if ($entry.host -and $hstsHashes.ContainsKey([string]$entry.host)) {
                    Add-Finding '니케 런처 캐시' 'Clue' ("{0} HSTS 캐시에서 {1} 흔적을 발견했습니다." -f $profile, $hstsHashes[[string]$entry.host])
                }
            }
        }
        $storage = Join-Path $cache 'Local Storage\leveldb'
        if (Test-LocalArtifact $storage 'Container') {
            foreach ($file in (Get-ChildItem -LiteralPath $storage -File -Force -ErrorAction Stop)) {
                if ($file.Extension -notin @('.log', '.ldb') -or $file.Length -gt 8MB -or
                    ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { continue }
                $data = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($file.FullName))
                if ($data.Contains('k2f.agent.state')) {
                    Add-Finding '니케 런처 캐시' 'Strong' "$profile 로컬 저장소에서 k2f.agent.state 지표를 발견했습니다."
                    break
                }
            }
        }
    }
    if (-not $cacheFound) {
        Add-Finding '니케 런처 캐시' 'Unavailable' '확인한 프로필에 런처 캐시가 없습니다.'
    }
}

Invoke-ReadCheck 'Chrome 백도어 흔적' {
    $clsid = '{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
    foreach ($registry in @('HKCU:\Software\Classes\CLSID', 'HKCU:\Software\Classes\Wow6432Node\CLSID')) {
        $key = Join-Path $registry $clsid
        if (-not (Test-Path -LiteralPath $key -ErrorAction Stop)) { continue }
        $inproc = Join-Path $key 'InprocServer32'
        $target = if (Test-Path -LiteralPath $inproc -ErrorAction Stop) {
            (Get-Item -LiteralPath $inproc -ErrorAction Stop).GetValue('')
        }
        if ($target -match '\\PlatformExperienceHelper\\[0-9a-f]{64}\\platform_experience_helper\.dll"?$') {
            Add-Finding 'Chrome 백도어 흔적' 'Strong' '현재 사용자의 등록 키가 보고된 Chrome 악성 DLL 경로를 가리킵니다.'
        } else {
            Add-Finding 'Chrome 백도어 흔적' 'Clue' '현재 사용자에 보고된 CLSID가 있습니다. DLL 연결값은 추가 확인이 필요합니다.'
        }
    }
    $helper = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\PlatformExperienceHelper'
    if (Test-LocalArtifact $helper 'Container') {
        foreach ($folder in (Get-ChildItem -LiteralPath $helper -Directory -Force -ErrorAction Stop)) {
            if ($folder.Name -match '^[0-9a-f]{64}$' -and
                -not ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
                (Test-LocalArtifact (Join-Path $folder.FullName 'platform_experience_helper.dll') 'Leaf')) {
                Add-Finding 'Chrome 백도어 흔적' 'Strong' '보고된 경로 구조의 Chrome 악성 DLL 파일명을 발견했습니다.'
            }
        }
    }
}

Invoke-ReadCheck 'K2F 임시 파일' {
    if (-not (Test-LocalArtifact $env:TEMP 'Container')) { throw '로컬 임시 폴더를 확인할 수 없습니다.' }
    $temporary = @(Get-ChildItem -LiteralPath $env:TEMP -File -Force -Filter 'k2f*' -ErrorAction Stop |
        Where-Object Name -match '^k2f-(?:bcreds|keyscan)-\d+-.+\.db$|^k2f_screen_\d+_\d+\.(?:png|jpg)$')
    if ($temporary.Count -gt 0) {
        Add-Finding 'K2F 임시 파일' 'Strong' ("보고된 K2F 임시 파일명과 일치하는 항목 {0}개가 있습니다." -f $temporary.Count)
    }
}

Invoke-ReadCheck 'K2F 실행 채널' {
    if ([IO.Directory]::GetFiles('\\.\pipe\') -match '\\k2f_chan$') {
        Add-Finding 'K2F 실행 채널' 'Strong' '실행 중인 k2f_chan 이름의 파이프를 발견했습니다.'
    }
}

Invoke-ReadCheck '현재 TCP 연결' {
    $active = Get-NetTCPConnection -ErrorAction Stop | Where-Object {
        $_.RemoteAddress -in $knownIPs -and $_.State -in @('Established', 'SynSent', 'SynReceived')
    }
    if ($active) {
        Add-Finding '현재 TCP 연결' 'Clue' '보고된 IP로 향하는 현재 연결이 있습니다. 연결 주체와 목적을 추가 확인하세요.'
    }
}

Invoke-ReadCheck 'DNS 캐시' {
    $cached = Get-DnsClientCache -ErrorAction Stop | Where-Object {
        ([string]$_.Entry).TrimEnd('.') -in $domains -or ([string]$_.RecordName).TrimEnd('.') -in $domains
    }
    if ($cached) {
        Add-Finding 'DNS 캐시' 'Clue' '보고된 도메인이 DNS 캐시에 있습니다. 다운로드나 실행 여부는 알 수 없습니다.'
    }
}

Invoke-ReadCheck 'Chrome MetaMask 폴더' {
    $chrome = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'
    if (-not (Test-LocalArtifact $chrome 'Container')) {
        Add-Finding 'Chrome MetaMask 폴더' 'Unavailable' '기본 Chrome 데이터 경로가 없습니다.'
        return
    }
    $id = 'nkbihfbeogaeaoehlefnkodbefgpgknn'
    foreach ($profile in (Get-ChildItem -LiteralPath $chrome -Directory -Force -ErrorAction Stop | Where-Object Name -match '^(Default|Profile \d+)$')) {
        foreach ($relative in @("Extensions\$id", "Local Extension Settings\$id", "IndexedDB\chrome-extension_$($id)_0.indexeddb.leveldb")) {
            if (Test-LocalArtifact (Join-Path $profile.FullName $relative) 'Container') {
                Add-Finding 'Chrome MetaMask 폴더' 'Context' 'Chrome에 MetaMask 설치 또는 데이터 폴더가 있습니다. 감염 지표로 집계하지 않습니다.'
                return
            }
        }
    }
}

Invoke-ReadCheck '등록된 Windows 백신' {
    $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
        Select-Object -ExpandProperty displayName -Unique)
    if ($products.Count -gt 0) { Add-Finding '등록된 Windows 백신' 'Context' ($products -join ', ') }
}

Invoke-ReadCheck 'Defender 전체 검사 기록' {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'
        ID = 1000, 1001, 1002, 1005
    } -MaxEvents 100 -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        $fields = ([xml]$event.ToXml()).Event.EventData.Data
        if (($fields | Where-Object Name -eq 'Scan Parameters Index').'#text' -ne '2') { continue }
        $status = switch ($event.Id) {
            1000 { '시작 기록만 확인됨' }
            1001 { '완료' }
            1002 { '중단' }
            1005 { '실패' }
        }
        Add-Finding 'Defender 전체 검사 기록' 'Context' ('최근 이벤트 {0} ({1} 로컬 시간). 이 이벤트는 탐지 결과와 별개입니다.' -f $status, $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))
        return
    }
    Add-Finding 'Defender 전체 검사 기록' 'Unavailable' '최근 전체 검사 이벤트를 확인할 수 없습니다.'
}

$verdict = if ($checks.Status -contains 'Strong') {
    '공개 감염 지표와 일치하는 강한 흔적을 발견했습니다. 원본을 보존하고 확인된 항목을 검토하세요.'
} elseif ($checks.Status -contains 'Clue') {
    '추가 확인이 필요한 단서를 발견했습니다. 이 결과만으로 감염 여부를 판정할 수 없습니다.'
} else {
    '확인한 범위에서 알려진 감염 지표를 찾지 못했습니다. 과거 감염이나 정보 유출 여부는 확인할 수 없습니다.'
}

if ($Json) {
    [pscustomobject][ordered]@{ Verdict = $verdict; Checks = $checks.ToArray() } | ConvertTo-Json -Depth 4
} else {
    '니케 PC 런처 보안 점검'
    foreach ($finding in $checks) {
        $label = switch ($finding.Status) {
            Strong { '강한 지표' }
            Clue { '단서' }
            Context { '참고' }
            NotFound { '미발견' }
            Unavailable { '확인 불가' }
        }
        '[{0}] {1} | {2}' -f $label, $finding.Check, $finding.Detail
    }
    ''
    $verdict
}
