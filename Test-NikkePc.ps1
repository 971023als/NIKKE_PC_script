#requires -Version 5.1
<#
.SYNOPSIS
    2026년 11월 니케 PC 런처 사건의 공개 감염 지표를 읽기 전용으로 확인합니다.
.PARAMETER NikkePath
    자동으로 찾지 못한 게임 설치 폴더 또는 Launcher 폴더를 지정합니다.
.PARAMETER Json
    결과를 JSON으로 표준 출력에 표시합니다.
.PARAMETER LogPath
    보존한 런처 로그 파일 또는 폴더를 추가로 확인합니다.
.PARAMETER Deep
    Prefetch와 보존된 Windows 네트워크 기록을 추가 확인합니다.
.PARAMETER Since
    실행 및 네트워크 기록을 조회할 시작 날짜입니다 (yyyy-MM-dd, 한국시간).
.PARAMETER Until
    실행 및 네트워크 기록을 조회할 마지막 날짜입니다 (yyyy-MM-dd, 한국시간, 당일 포함).
#>
[CmdletBinding()]
param(
    [string[]]$NikkePath = @(),
    [string[]]$LogPath = @(),
    [switch]$Deep,
    [string]$Since,
    [string]$Until,
    [switch]$Json
)

if ($env:OS -ne 'Windows_NT') { throw '이 스크립트는 Windows용입니다.' }
if ($Json) { $ProgressPreference = 'SilentlyContinue' }
$scannerVersion = '0.2.0'
$sinceKst = $null
$untilKst = $null
foreach ($bound in @('Since', 'Until')) {
    $text = Get-Variable -Name $bound -ValueOnly
    if (-not $text) { continue }
    $date = [datetime]::MinValue
    if (-not [datetime]::TryParseExact($text, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None, [ref]$date)) { throw "$bound 날짜는 yyyy-MM-dd 형식으로 입력하세요." }
    $dateKst = [DateTimeOffset]::new([datetime]::SpecifyKind($date, [DateTimeKind]::Unspecified), [TimeSpan]::FromHours(9))
    if ($bound -eq 'Since') { $sinceKst = $dateKst } else { $untilKst = $dateKst.AddDays(1) }
}
if ($sinceKst -and $untilKst -and $sinceKst -ge $untilKst) { throw 'Until은 Since와 같거나 뒤의 날짜여야 합니다.' }

$checks = [System.Collections.Generic.List[object]]::new()
$launchers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$fixedDrives = @([IO.DriveInfo]::GetDrives() | Where-Object DriveType -eq Fixed | ForEach-Object Name)
$domains = @('insightjs.com', 'analytics.insightjs.com', 'insightjs.org')
$knownIPs = @('89.127.233.127', '89.126.250.172')
$payloadHashes = @(
    '60fd53ab7356384ba2161b9bc84420cd170905011a2f3ca09f3e38fe3122f3a1',
    'cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec'
)

function Add-Finding([string]$Name, [string]$Status, [string]$Detail, [string]$Stage = '', [string]$Time = '') {
    $checks.Add([pscustomobject][ordered]@{ Check = $Name; Status = $Status; Detail = $Detail; Stage = $Stage; Time = $Time })
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

function Test-Period([DateTimeOffset]$Time) {
    return (-not $sinceKst -or $Time -ge $sinceKst) -and (-not $untilKst -or $Time -lt $untilKst)
}

function Add-LaunchTime([string]$Source, [datetime]$Time) {
    $kst = [DateTimeOffset]::new($Time.ToUniversalTime()).ToOffset([TimeSpan]::FromHours(9))
    if (Test-Period $kst) {
        Add-Finding $Source 'Context' ('기록된 실행 시각 {0} KST. 실행 기록은 감염 여부와 별도로 해석하세요.' -f $kst.ToString('yyyy-MM-dd HH:mm:ss.fff')) 'Context' $kst.ToString('o')
    }
}

Invoke-ReadCheck 'Windows 앱 실행 기록 (PCA)' {
    $pca = Join-Path $env:windir 'appcompat\pca\PcaAppLaunchDic.txt'
    if (-not (Test-LocalArtifact $pca 'Leaf')) {
        Add-Finding 'Windows 앱 실행 기록 (PCA)' 'Unavailable' 'PCA 기록 파일이 없습니다.'
        return
    }
    foreach ($line in (Select-String -LiteralPath $pca -Pattern '\\nikke_launcher(?:_google|_hmt)?\.exe\|' -ErrorAction Stop)) {
        $parts = $line.Line -split '\|', 2
        if ($parts[0] -notmatch '\\nikke_launcher(?:_google|_hmt)?\.exe$') { continue }
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
            if ($name -notmatch 'avxxr_ynhapure(?:_tbbtyr|_uzg)?\.rkr$') { continue }
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

Invoke-ReadCheck '설치 경로 확인' {
    $candidates = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($base in $fixedDrives + @($env:ProgramFiles, [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'))) {
        if (-not $base) { continue }
        foreach ($folder in @('NIKKE', 'NIKKE_GOOGLE', 'NIKKE_HMT')) {
            [void]$candidates.Add((Join-Path $base "$folder\Launcher"))
        }
    }
    $number = 0
    foreach ($requested in $NikkePath) {
        $number++
        try {
            if ($requested -notmatch '^[A-Za-z]:\\' -or [IO.Path]::GetPathRoot($requested) -notin $fixedDrives) {
                Add-Finding '설치 경로 확인' 'Unavailable' "지정 경로 #$number 에는 로컬 고정 드라이브의 절대 경로를 사용하세요."
                continue
            }
            if (Test-LocalArtifact (Join-Path $requested 'Launcher') 'Container') {
                [void]$candidates.Add((Join-Path $requested 'Launcher'))
            } elseif (Test-LocalArtifact $requested 'Container') {
                [void]$candidates.Add($requested)
            } else {
                Add-Finding '설치 경로 확인' 'Unavailable' "지정 경로 #$number 가 현재 연결된 드라이브에 없습니다."
            }
        } catch {
            Add-Finding '설치 경로 확인' 'Unavailable' "지정 경로 #$number 를 읽지 못했습니다."
        }
    }
    foreach ($candidate in $candidates) {
        try { Add-LauncherFolder $candidate } catch {
            Add-Finding '설치 경로 확인' 'Unavailable' '알려진 설치 경로 일부를 읽지 못했습니다.'
        }
    }
    Add-Finding '설치 경로 확인' 'Context' ("읽을 수 있는 런처 폴더 {0}개. 설치 위치가 다르거나 드라이브가 분리돼 있으면 -NikkePath로 보완하세요." -f $launchers.Count)
}

Invoke-ReadCheck '점검 전 실행 상태' {
    $running = @(Get-Process -ErrorAction Stop | Where-Object ProcessName -in @('nikke_launcher', 'nikke_launcher_google', 'nikke_launcher_hmt', 'NIKKE', 'tbs_browser', 'chrome'))
    if ($running.Count -gt 0) {
        Add-Finding '점검 전 실행 상태' 'Context' '니케 런처·내장 브라우저·게임 또는 Chrome 이름의 프로세스가 실행 중입니다. 원본 파일이 검사 중 바뀌거나 잠겨 일부 검사가 불완전할 수 있습니다. 공식 수동 절차는 네트워크 차단과 프로그램 종료 후 진행합니다.'
    } else {
        Add-Finding '점검 전 실행 상태' 'Context' '확인 대상 프로그램 이름의 실행 프로세스를 찾지 못했습니다. 시스템 트레이도 직접 확인하세요.'
    }
}

function Get-NikkeLogStamp([string]$Line) {
    $stamp = [regex]::Match($Line, '^\[?(?<full>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)')
    if ($stamp.Success) {
        $text = $stamp.Groups['full'].Value
        $instant = $null
        if ($text -match '(?:Z|[+-]\d{2}:\d{2})$') {
            $parsed = [DateTimeOffset]::MinValue
            if ([DateTimeOffset]::TryParse($text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) { $instant = $parsed }
        }
        # tinyget's numeric bracket can identify a worker thread, so it is not a process/session ID.
        return [pscustomobject]@{ Text = $text; Day = $text.Substring(0, 10); Clock = $text.Substring(11); Process = ''; Instant = $instant }
    }
    $stamp = [regex]::Match($Line, '^\[(?<pid>\d+):\d+:(?<day>\d{4})/(?<clock>\d{6}\.\d+)')
    if (-not $stamp.Success) { $stamp = [regex]::Match($Line, '^\[(?<day>\d{4})/(?<clock>\d{6}\.\d+)') }
    if ($stamp.Success) {
        $day = $stamp.Groups['day'].Value
        return [pscustomobject]@{ Text = ($day + '/' + $stamp.Groups['clock'].Value + ' (연도·시간대 미기재)'); Day = $day; Clock = $stamp.Groups['clock'].Value; Process = $stamp.Groups['pid'].Value; Instant = $null }
    }
    return [pscustomobject]@{ Text = ''; Day = ''; Clock = ''; Process = ''; Instant = $null }
}

function Read-NikkeTextLog([IO.FileInfo]$File, [string]$Label) {
    if ($File.Length -gt 32MB) { throw 'TextSizeLimit' }
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true)
    $tasks = @{}
    $sessions = @{}
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $days = [System.Collections.Generic.HashSet[string]]::new()
    $lines = 0
    $unknownPeriod = $false
    try {
        while (-not $reader.EndOfStream) {
            if ($stream.Length -gt 32MB -or $lines -ge 200000) { throw 'TextReadLimit' }
            $line = $reader.ReadLine()
            $lines++
            $stamp = Get-NikkeLogStamp $line
            if ($stamp.Day) { [void]$days.Add($stamp.Day) }
            $inPeriod = $true
            if ($sinceKst -or $untilKst) {
                if ($null -eq $stamp.Instant) { $unknownPeriod = $true }
                elseif (($sinceKst -and $stamp.Instant -lt $sinceKst) -or ($untilKst -and $stamp.Instant -ge $untilKst)) { $inPeriod = $false }
            }

            # Chromium can omit the process ID. In that format only this file's chronological flow can be linked.
            $sessionKey = $stamp.Process + '|' + $stamp.Day
            if ($line -match '\blua downloaded\b|\bstartup failed\b|\bstartup already in progress\b') { $sessions.Remove($sessionKey) }
            if ($line -match '(?<![A-Za-z0-9_])k2f_chan registered(?![A-Za-z0-9_])') {
                if ($stamp.Day -and $stamp.Clock) { $sessions[$sessionKey] = @{ Line = $lines; Clock = $stamp.Clock } }
                if ($inPeriod -and $stamp.Text) {
                    $key = 'execution|' + $stamp.Text
                    if ($seen.Add($key)) { Add-Finding $Label 'Strong' 'k2f_chan registered 표식이 있어 악성 에이전트의 로컬 실행을 뒷받침합니다.' 'Execution' $stamp.Text }
                } elseif ($inPeriod -and $seen.Add('undated-registration')) {
                    Add-Finding $Label 'Clue' 'k2f_chan registered 문자열이 있으나 로그의 시각 형식을 확인하지 못했습니다. 원본 실행 로그인지 검토하세요.' 'Execution'
                }
            }
            if ($line -match '\b(?:adopted|resuming)\s+[0-9a-f]{8}-[0-9a-f-]{20,}\b') {
                $registered = $sessions[$sessionKey]
                if ($inPeriod -and $registered -and $stamp.Day -and $stamp.Clock -ge $registered.Clock -and $lines -gt $registered.Line) {
                    if ($seen.Add('response|' + $stamp.Text)) { Add-Finding $Label 'Strong' '같은 로그의 날짜·실행 흐름에서 채널 등록 뒤 adopted/resuming 표식을 확인했습니다. 서버 응답을 뒷받침하며 개별 명령이나 유출 내용은 알 수 없습니다.' 'ServerResponse' $stamp.Text }
                } elseif ($inPeriod -and $seen.Add('unlinked-response|' + $stamp.Text)) {
                    Add-Finding $Label 'Clue' 'adopted/resuming 표식이 있으나 같은 실행의 채널 등록과 연결하지 못했습니다.' 'Context' $stamp.Text
                }
            }
            if ($line -match '\bstartup failed\b' -and $inPeriod -and $seen.Add('startup-failed|' + $stamp.Text)) {
                Add-Finding $Label 'Context' 'startup failed 표식이 있습니다. 별도로 확인된 채널 등록은 에이전트가 실행된 흔적으로 남습니다.' 'Context' $stamp.Text
            }
            if ($line -match '\blua downloaded\b' -and $inPeriod -and $seen.Add('lua|' + $stamp.Text)) {
                Add-Finding $Label 'Clue' 'lua downloaded 표식이 있습니다. 파일 수신을 시사하며 다운로드 작업의 성공·실행 표식과 함께 검토하세요.' 'Download' $stamp.Text
            }

            $taskId = [regex]::Match($line, '(?i)\btask(?:_id)?\s*[=:]\s*(?<id>\d+)\b')
            $taskKey = $taskId.Groups['id'].Value
            $bundle = $line -match '(?i)https?://analytics\.insightjs\.com(?::\d+)?/comm/assets/insight\.bundle(?:[?\s,"''\]]|$)'
            if ($line -match '\bAddTask\b') {
                if ($taskId.Success) {
                    $tasks.Remove($taskKey)
                    if ($bundle) { $tasks[$taskKey] = @{ Curl = $false; Failed = $false; Reported = $false; InPeriod = $inPeriod; Time = $stamp.Text } }
                }
                if ($bundle -and $inPeriod -and $seen.Add('request|' + $stamp.Text + '|' + $taskId.Value)) {
                    Add-Finding $Label 'Clue' 'AddTask에 insight.bundle 요청이 기록돼 있습니다. 이 줄만으로 파일 수신은 확인되지 않습니다.' 'Request' $stamp.Text
                }
            }
            if (-not $taskId.Success) { continue }
            $task = $tasks[$taskKey]
            if (-not $task) { continue }
            # A terminal failure ends this attempt. A later AddTask must start a new attempt.
            if ($line -match '\bcurl_error\s*[=:]\s*[1-9]\d*\b') { $task.Failed = $true }
            if ($line -match '\bcurl perform success\b' -and -not $task.Failed) { $task.Curl = $true }
            if ($line -notmatch '\bOnDownloadResult\b') { continue }
            $result = [regex]::Match($line, '\bresult\s*=\s*(?<n>-?\d+)\b')
            $total = [regex]::Match($line, '\btotal\s*=\s*(?<n>\d+)\b')
            if (-not $result.Success -or -not $total.Success) { continue }
            $bytes = [uint64]$total.Groups['n'].Value
            if ($result.Groups['n'].Value -ne '0' -or $bytes -eq 0) {
                $task.Failed = $true
                if ($task.InPeriod -and $inPeriod -and -not $task.Reported) {
                    Add-Finding $Label 'Context' 'insight.bundle의 같은 다운로드 작업에 실패 또는 0바이트 결과가 있습니다. 이 시도의 다운로드 성공은 확인되지 않습니다.' 'Request' $stamp.Text
                    $task.Reported = $true
                }
            } elseif ($task.InPeriod -and $inPeriod -and -not $task.Reported) {
                if ($task.Curl -and -not $task.Failed) {
                    Add-Finding $Label 'Strong' ('같은 AddTask 작업의 curl perform success와 OnDownloadResult result=0, total={0}을 확인했습니다. 악성 파일 다운로드 완료를 뒷받침하며 실행은 별도 확인이 필요합니다.' -f $bytes) 'Download' $stamp.Text
                } else {
                    Add-Finding $Label 'Clue' ('insight.bundle 작업에 result=0, total={0}이 있으나 같은 시도의 curl 성공 기록까지 대조하지 못했습니다.' -f $bytes) 'Download' $stamp.Text
                }
                $task.Reported = $true
            }
        }
    } finally { $reader.Dispose() }
    $dateSummary = @($days | Sort-Object) -join ', '
    if ($dateSummary.Length -gt 240) { $dateSummary = $dateSummary.Substring(0, 240) + '…' }
    Add-Finding $Label 'Context' ('텍스트 {0}줄을 확인했습니다. 기록 날짜 {1}. 로그에 시간대가 없으면 KST로 확정하지 않으며 날짜 목록은 세션 전체 보존을 보장하지 않습니다.' -f $lines, $(if ($dateSummary) { $dateSummary } else { '해석 불가' })) 'Context'
    if ($unknownPeriod) { Add-Finding $Label 'Unavailable' '연도나 시간대가 없는 줄의 지정 기간 포함 여부를 확정할 수 없습니다. 해당 줄의 발견 항목은 로그 전체 범위의 흔적으로 표시했습니다.' 'Context' }
}

Invoke-ReadCheck '니케 런처 로그' {
    $files = [System.Collections.Generic.Dictionary[string,IO.FileInfo]]::new([StringComparer]::OrdinalIgnoreCase)
    $directories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($launcher in $launchers) {
        [void]$directories.Add((Join-Path $launcher 'intl_service'))
        [void]$directories.Add((Join-Path $launcher 'log\tinyget'))
    }
    $requestedNumber = 0
    foreach ($requested in $LogPath) {
        $requestedNumber++
        try {
            if (Test-LocalArtifact $requested 'Leaf') { $files[$requested] = Get-Item -LiteralPath $requested -Force -ErrorAction Stop }
            elseif (Test-LocalArtifact $requested 'Container') {
                foreach ($relative in @('', 'intl_service', 'log\tinyget', 'Launcher\intl_service', 'Launcher\log\tinyget')) {
                    $dir = if ($relative) { Join-Path $requested $relative } else { $requested }
                    if (Test-LocalArtifact $dir 'Container') { [void]$directories.Add($dir) }
                }
            } else { Add-Finding '니케 런처 로그' 'Unavailable' "지정 로그 경로 #$requestedNumber 를 찾지 못했습니다." }
        } catch { Add-Finding '니케 런처 로그' 'Unavailable' "지정 로그 경로 #$requestedNumber 를 안전하게 읽지 못했습니다." }
    }
    foreach ($directory in $directories) {
        try {
            if (-not (Test-LocalArtifact $directory 'Container')) { continue }
            $candidates = @(Get-ChildItem -LiteralPath $directory -File -Force -ErrorAction Stop | Select-Object -First 257)
            if ($candidates.Count -gt 256) { Add-Finding '니케 런처 로그' 'Unavailable' '한 폴더의 로그 후보가 256개를 넘어 일부만 확인합니다.' }
            foreach ($file in ($candidates | Select-Object -First 256)) {
                if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { Add-Finding '니케 런처 로그' 'Unavailable' '재분석 지점인 로그 후보를 건너뛰었습니다.'; continue }
                if ((Split-Path -Leaf $directory) -eq 'tinyget' -or $file.Name -match '^(?:debug\.log(?:[.-].+)?|tinyget(?:\..+)?\.log|k2f\.lua|insight\.bundle)$') { $files[$file.FullName] = $file }
            }
        } catch { Add-Finding '니케 런처 로그' 'Unavailable' '로그 후보 폴더 일부를 읽지 못했습니다.' }
    }
    if ($files.Count -eq 0) {
        Add-Finding '니케 런처 로그' 'Unavailable' '확인한 경로에 런처 로그가 없습니다. 다른 설치 폴더는 -NikkePath, 로그 사본은 -LogPath로 지정하세요.'
        return
    }
    $number = 0
    foreach ($file in $files.Values) {
        $number++
        $label = "니케 로그 #$number"
        try {
            if (-not (Test-LocalArtifact $file.FullName 'Leaf')) { throw 'MissingFile' }
            $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
            $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
            try {
                $header = New-Object byte[] 4
                $bytecode = $stream.Read($header, 0, 4) -eq 4 -and [BitConverter]::ToString($header) -eq '1B-4C-4A-01'
                if ($bytecode) {
                    $stream.Position = 0
                    if ($stream.Length -le 4MB -and (Get-FileHash -InputStream $stream -Algorithm SHA256 -ErrorAction Stop).Hash -in $payloadHashes) {
                        Add-Finding $label 'Strong' '파일 SHA-256이 공개 악성 샘플과 일치합니다. 파일 존재만으로 실행 여부는 알 수 없습니다.' 'Artifact'
                    } else { Add-Finding $label 'Clue' 'LuaJIT 바이트코드 파일이 있습니다. 공개 악성 샘플과의 해시 일치는 확인되지 않았습니다.' 'Artifact' }
                }
            } finally { $stream.Dispose() }
            if (-not $bytecode) {
                if ($file.Length -eq 205135 -and $file.Name -match '^tinyget\..+\.log$') { Add-Finding $label 'Context' '공개 가이드의 205,135바이트·tinyget 파일명 조건과 일치합니다. 크기와 이름만으로 악성 여부를 확정할 수 없습니다.' 'Artifact' }
                Read-NikkeTextLog $file $label
            }
        } catch { Add-Finding $label 'Unavailable' ('로그 일부를 읽거나 해석하지 못했습니다 ({0}).' -f $_.Exception.GetType().Name) }
    }
}


function Read-NikkeCacheJson([string]$Path) {
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    try {
        if ($stream.Length -gt 8MB) { throw 'JSON 파일의 크기 제한을 넘습니다.' }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -eq 0) { throw 'JSON 파일 길이가 바뀌었습니다.' }
            $offset += $count
        }
        if ($stream.Length -ne $bytes.Length) { throw 'JSON 파일 길이가 바뀌었습니다.' }
    } finally { $stream.Dispose() }
    $memory = [IO.MemoryStream]::new($bytes, $false)
    $reader = [IO.StreamReader]::new($memory, [Text.Encoding]::UTF8, $true)
    try { $reader.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop }
    finally { $reader.Dispose() }
}

function Find-NikkeCacheHosts($Node, [int]$Depth) {
    if ($Depth -gt 12) { throw '네트워크 상태 JSON의 깊이 제한을 넘습니다.' }
    if ($null -eq $Node) { return }
    if ($Node -is [string]) {
        $candidate = $Node.TrimEnd('.')
        if ($candidate -in $domains) { $candidate.ToLowerInvariant(); return }
        $address = $null
        if ([uri]::TryCreate($Node, [UriKind]::Absolute, [ref]$address) -and $address.DnsSafeHost.TrimEnd('.') -in $domains) {
            $address.DnsSafeHost.TrimEnd('.').ToLowerInvariant()
        }
        return
    }
    if ($Node -is [System.Collections.IEnumerable]) {
        foreach ($child in $Node) { Find-NikkeCacheHosts $child ($Depth + 1) }
        return
    }
    if ($Node -is [pscustomobject]) {
        foreach ($property in $Node.PSObject.Properties) {
            Find-NikkeCacheHosts $property.Name ($Depth + 1)
            Find-NikkeCacheHosts $property.Value ($Depth + 1)
        }
    }
}


$nikkeStorageSource = @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

// Read-only, bounded LevelDB WAL/SST inspection. Values are neither returned nor interpreted.
public sealed class NikkeStorageResult
{
    public int StateRecords;
    public int DeletedStateKeys;
    public string Error;
}
public static class NikkeStorageReader
{
    const int Limit = 16 * 1024 * 1024;
    const int BlockLimit = 4 * 1024 * 1024;
    static readonly uint[] CrcTable = MakeCrcTable();
    static uint[] MakeCrcTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++) {
            uint crc = i;
            for (int bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0x82f63b78U : 0U);
            table[i] = crc;
        }
        return table;
    }
    static uint MaskedCrc(byte[] bytes, int start, int count, int initialByte)
    {
        uint crc = 0xffffffffU;
        if (initialByte >= 0) crc = CrcTable[(crc ^ (byte)initialByte) & 255] ^ (crc >> 8);
        for (int i = start; i < start + count; i++) crc = CrcTable[(crc ^ bytes[i]) & 255] ^ (crc >> 8);
        crc ^= 0xffffffffU;
        return unchecked(((crc >> 15) | (crc << 17)) + 0xa282ead8U);
    }
    static ulong Varint(byte[] bytes, ref int position, int end)
    {
        ulong value = 0;
        for (int shift = 0; shift < 64; shift += 7) {
            if (position >= end) throw new InvalidDataException("Truncated varint");
            byte b = bytes[position++];
            if (shift == 63 && b > 1) throw new InvalidDataException("Varint overflow");
            value |= (ulong)(b & 127) << shift;
            if (b < 128) return value;
        }
        throw new InvalidDataException("Varint overflow");
    }
    static int Length(byte[] bytes, ref int position, int end, int limit)
    {
        ulong n = Varint(bytes, ref position, end);
        if (n > (ulong)limit || n > (ulong)(end - position)) throw new InvalidDataException("Length limit or bounds");
        return (int)n;
    }
    static bool IsStateKey(byte[] bytes, int start, int count)
    {
        byte[] prefix = Encoding.ASCII.GetBytes("_https://www.nikkelauncher.com\0");
        if (count <= prefix.Length) return false;
        for (int i = 0; i < prefix.Length; i++) if (bytes[start + i] != prefix[i]) return false;
        int offset = start + prefix.Length;
        int encoding = bytes[offset++];
        int length = count - prefix.Length - 1;
        string key;
        if (encoding == 1) key = Encoding.GetEncoding(28591).GetString(bytes, offset, length);
        else if (encoding == 0 && length % 2 == 0) key = Encoding.Unicode.GetString(bytes, offset, length);
        else return false;
        return key == "k2f.agent.state" || key == "k2f.agent";
    }
    static void Batch(byte[] bytes, NikkeStorageResult result)
    {
        if (bytes.Length < 12) throw new InvalidDataException("Truncated write batch");
        uint count = BitConverter.ToUInt32(bytes, 8);
        if (count > 100000) throw new InvalidDataException("Write batch count limit");
        int position = 12;
        int states = 0, deleted = 0;
        for (uint entry = 0; entry < count; entry++) {
            if (position >= bytes.Length) throw new InvalidDataException("Truncated batch entry");
            byte tag = bytes[position++];
            if (tag != 0 && tag != 1) throw new InvalidDataException("Unknown batch entry");
            int keyLength = Length(bytes, ref position, bytes.Length, 65536);
            bool matches = IsStateKey(bytes, position, keyLength);
            position += keyLength;
            if (tag == 1) {
                int valueLength = Length(bytes, ref position, bytes.Length, Limit);
                if (matches && valueLength > 0) states++;
                position += valueLength;
            } else if (matches) deleted++;
        }
        if (position != bytes.Length) throw new InvalidDataException("Trailing batch bytes");
        result.StateRecords += states;
        result.DeletedStateKeys += deleted;
    }
    static void Log(byte[] bytes, NikkeStorageResult result)
    {
        using (var fragment = new MemoryStream()) {
            bool pending = false;
            int position = 0;
            while (position < bytes.Length) {
                int blockEnd = Math.Min(bytes.Length, ((position / 32768) + 1) * 32768);
                if (blockEnd - position < 7) {
                    for (; position < blockEnd; position++) if (bytes[position] != 0) throw new InvalidDataException("Log trailer");
                    continue;
                }
                uint expected = BitConverter.ToUInt32(bytes, position);
                int length = BitConverter.ToUInt16(bytes, position + 4);
                byte type = bytes[position + 6];
                position += 7;
                if (type == 0 && length == 0 && expected == 0) {
                    for (; position < blockEnd; position++) if (bytes[position] != 0) throw new InvalidDataException("Log padding");
                    continue;
                }
                if (length > blockEnd - position || type < 1 || type > 4) throw new InvalidDataException("Log record bounds or type");
                if (MaskedCrc(bytes, position, length, type) != expected) throw new InvalidDataException("Log checksum");
                if ((type == 1 || type == 2) && pending) throw new InvalidDataException("Unfinished log fragment");
                if ((type == 3 || type == 4) && !pending) throw new InvalidDataException("Missing log fragment");
                if (type == 1 || type == 2) fragment.SetLength(0);
                if (fragment.Length + length > Limit) throw new InvalidDataException("Log fragment size limit");
                fragment.Write(bytes, position, length);
                position += length;
                pending = type == 2 || type == 3;
                if (type == 1 || type == 4) Batch(fragment.ToArray(), result);
            }
            if (pending) throw new InvalidDataException("Truncated final log fragment");
        }
    }
    public static byte[] Snappy(byte[] input)
    {
        int position = 0;
        ulong declared = Varint(input, ref position, input.Length);
        if (declared > BlockLimit) throw new InvalidDataException("Snappy output limit");
        var output = new byte[(int)declared];
        int written = 0;
        while (position < input.Length) {
            byte tag = input[position++];
            int kind = tag & 3;
            int length, distance;
            if (kind == 0) {
                int encodedLength = tag >> 2;
                if (encodedLength < 60) length = encodedLength + 1;
                else {
                    int lengthBytes = encodedLength - 59;
                    if (position + lengthBytes > input.Length) throw new InvalidDataException("Snappy literal header");
                    uint n = 0;
                    for (int i = 0; i < lengthBytes; i++) n |= (uint)input[position++] << (8 * i);
                    if (n >= BlockLimit) throw new InvalidDataException("Snappy literal size");
                    length = (int)n + 1;
                }
                if (length > input.Length - position || length > output.Length - written) throw new InvalidDataException("Snappy literal bounds");
                Buffer.BlockCopy(input, position, output, written, length);
                position += length;
                written += length;
                continue;
            }
            int distanceBytes = kind == 1 ? 1 : kind == 2 ? 2 : 4;
            if (position + distanceBytes > input.Length) throw new InvalidDataException("Snappy copy header");
            if (kind == 1) {
                length = 4 + ((tag >> 2) & 7);
                distance = ((tag & 224) << 3) | input[position++];
            } else {
                length = 1 + (tag >> 2);
                uint n = 0;
                for (int i = 0; i < distanceBytes; i++) n |= (uint)input[position++] << (8 * i);
                if (n > int.MaxValue) throw new InvalidDataException("Snappy distance limit");
                distance = (int)n;
            }
            if (distance <= 0 || distance > written || length > output.Length - written) throw new InvalidDataException("Snappy copy bounds");
            for (int i = 0; i < length; i++) { output[written] = output[written - distance]; written++; }
        }
        if (written != output.Length) throw new InvalidDataException("Snappy output length");
        return output;
    }
    sealed class Pair { public byte[] Key; public byte[] Value; }
    static List<Pair> Entries(byte[] block)
    {
        if (block.Length < 8) throw new InvalidDataException("Block restart bounds");
        uint restarts = BitConverter.ToUInt32(block, block.Length - 4);
        if (restarts == 0 || restarts > (block.Length - 4) / 4) throw new InvalidDataException("Block restart count");
        int end = block.Length - 4 - (int)restarts * 4;
        uint last = 0;
        for (int i = 0; i < restarts; i++) {
            uint offset = BitConverter.ToUInt32(block, end + i * 4);
            if ((i == 0 && offset != 0) || offset > end || (i > 0 && offset <= last)) throw new InvalidDataException("Block restart offset");
            last = offset;
        }
        int position = 0;
        byte[] previous = new byte[0];
        var records = new List<Pair>();
        while (position < end) {
            ulong shared = Varint(block, ref position, end);
            int extra = Length(block, ref position, end, 65536);
            int valueLength = Length(block, ref position, end, BlockLimit);
            if (shared > (ulong)previous.Length || shared + (ulong)extra > 65536 || extra + valueLength > end - position) throw new InvalidDataException("Entry bounds");
            var key = new byte[(int)shared + extra];
            Buffer.BlockCopy(previous, 0, key, 0, (int)shared);
            Buffer.BlockCopy(block, position, key, (int)shared, extra);
            position += extra;
            var value = new byte[valueLength];
            Buffer.BlockCopy(block, position, value, 0, valueLength);
            position += valueLength;
            records.Add(new Pair { Key = key, Value = value });
            previous = key;
            if (records.Count > 100000) throw new InvalidDataException("Block entry count limit");
        }
        return records;
    }
    static byte[] ReadBlock(byte[] file, byte[] handle, ref int decoded)
    {
        int p = 0;
        ulong offset = Varint(handle, ref p, handle.Length);
        ulong size = Varint(handle, ref p, handle.Length);
        if (offset > (ulong)file.Length || size > BlockLimit || size + 5 > (ulong)file.Length - offset || offset + size + 5 > (ulong)(file.Length - 48)) throw new InvalidDataException("Table block bounds");
        int at = (int)offset, count = (int)size;
        if (MaskedCrc(file, at, count + 1, -1) != BitConverter.ToUInt32(file, at + count + 1)) throw new InvalidDataException("Table block checksum");
        var compressed = new byte[count];
        Buffer.BlockCopy(file, at, compressed, 0, count);
        byte kind = file[at + count];
        byte[] block;
        if (kind == 0) block = compressed;
        else if (kind == 1) block = Snappy(compressed);
        else throw new InvalidDataException("Unsupported table compression");
        decoded = checked(decoded + block.Length);
        if (decoded > 64 * 1024 * 1024) throw new InvalidDataException("Decoded table limit");
        return block;
    }
    static void Table(byte[] bytes, NikkeStorageResult result)
    {
        if (bytes.Length < 48 || BitConverter.ToUInt64(bytes, bytes.Length - 8) != 0xdb4775248b80fb57UL) throw new InvalidDataException("Table footer magic");
        int footer = bytes.Length - 48, p = footer;
        Varint(bytes, ref p, footer + 40);
        Varint(bytes, ref p, footer + 40);
        int indexBegin = p;
        Varint(bytes, ref p, footer + 40);
        Varint(bytes, ref p, footer + 40);
        var indexHandle = new byte[p - indexBegin];
        Buffer.BlockCopy(bytes, indexBegin, indexHandle, 0, indexHandle.Length);
        int decoded = 0;
        var seen = new HashSet<string>();
        foreach (Pair index in Entries(ReadBlock(bytes, indexHandle, ref decoded))) {
            if (!seen.Add(Convert.ToBase64String(index.Value))) throw new InvalidDataException("Duplicate table handle");
            foreach (Pair pair in Entries(ReadBlock(bytes, index.Value, ref decoded))) {
                if (pair.Key.Length < 8) throw new InvalidDataException("Short internal key");
                byte type = pair.Key[pair.Key.Length - 8];
                if (type > 1) throw new InvalidDataException("Unsupported internal key type");
                if (!IsStateKey(pair.Key, 0, pair.Key.Length - 8)) continue;
                if (type == 1 && pair.Value.Length > 0) result.StateRecords++;
                else if (type == 0) result.DeletedStateKeys++;
            }
        }
    }
    public static NikkeStorageResult Inspect(byte[] bytes, bool isTable)
    {
        var result = new NikkeStorageResult();
        try {
            if (bytes == null || bytes.Length > Limit) throw new InvalidDataException("Storage file limit");
            if (isTable) Table(bytes, result); else Log(bytes, result);
        } catch (Exception e) {
            result.Error = e.Message;
        }
        return result;
    }
}

'@

Invoke-ReadCheck '니케 런처 캐시' {
    $hstsHashes = @{
        'wxL1BeG57AG6frvPqS7txqpE3NyN0/fSUZHCbEn9NSw=' = 'analytics.insightjs.com'
        'JeFWywdZy+3jPC93e3P7ACdJ8liQHB7rH+9VHn7kswg=' = 'insightjs.com'
        '+EQMCXxbp1N4L3mxYGR66hSUD0cvdir6DDtJBLH3wPk=' = 'insightjs.org'
    }
    foreach ($profile in @('nikke_launcher', 'nikke_launcher_hmt', 'nikke_launcher_google')) {
        Invoke-ReadCheck ("런처 캐시 $profile") {
            $cache = Join-Path $env:APPDATA "$profile\tbs_cache"
            if (-not (Test-LocalArtifact $cache 'Container')) {
                Add-Finding ("런처 캐시 $profile") 'Unavailable' '해당 프로필의 캐시가 없습니다. 삭제 전의 흔적은 확인할 수 없습니다.'
                return
            }
            $jsCache = Join-Path $cache 'Code Cache\js'
            foreach ($entry in @('dd65fa4d61079e7e_0', 'ce2fd3f1007a9fe9_0', '1416c638b3830103_0', 'fd520c7c0f65c2d7_0')) {
                if (Test-LocalArtifact (Join-Path $jsCache $entry) 'Leaf') {
                    Add-Finding ("런처 로더 캐시 $profile") 'Clue' '보고된 로더 캐시 파일명이 있습니다. 파일명만으로 악성 내용이나 에이전트 실행을 확인할 수 없습니다.' 'Artifact'
                    break
                }
            }
            foreach ($relative in @('TransportSecurity', 'Network\TransportSecurity')) {
                $file = Join-Path $cache $relative
                if (-not (Test-LocalArtifact $file 'Leaf')) { continue }
                Invoke-ReadCheck ("런처 HSTS $profile") {
                    $state = Read-NikkeCacheJson $file
                    foreach ($entry in $state.sts) {
                        if (-not $entry.host -or -not $hstsHashes.ContainsKey([string]$entry.host)) { continue }
                        $hostName = $hstsHashes[[string]$entry.host]
                        $stamp = ''
                        $seconds = 0.0
                        if ([double]::TryParse([string]$entry.sts_observed, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$seconds) -and
                            -not [double]::IsNaN($seconds) -and -not [double]::IsInfinity($seconds) -and
                            $seconds -gt 0 -and $seconds -lt 253402268400) {
                            $stamp = ([DateTimeOffset]::new(1970, 1, 1, 0, 0, 0, [TimeSpan]::Zero)).AddSeconds($seconds).ToOffset([TimeSpan]::FromHours(9)).ToString('yyyy-MM-dd HH:mm:ss.fff')
                        }
                        $description = "$hostName HSTS 항목이 있습니다."
                        if ($stamp) { $description += " 마지막 HSTS 헤더 수신·저장 시각 $stamp KST." }
                        else { $description += ' 유효한 저장 시각을 확인하지 못했습니다.' }
                        $description += ' 첫 접속 시각이나 악성 명령 실행·유출 여부는 이 항목으로 판단할 수 없습니다.'
                        Add-Finding ("런처 HSTS $profile") 'Clue' $description 'Artifact' $stamp
                    }
                }
            }
            foreach ($relative in @('Network Persistent State', 'Network\Network Persistent State')) {
                $file = Join-Path $cache $relative
                if (-not (Test-LocalArtifact $file 'Leaf')) { continue }
                Invoke-ReadCheck ("런처 네트워크 상태 $profile") {
                    $state = Read-NikkeCacheJson $file
                    $matches = @(Find-NikkeCacheHosts $state 0 | Select-Object -Unique)
                    foreach ($hostName in $matches) {
                        Add-Finding ("런처 네트워크 상태 $profile") 'Clue' ("{0} 호스트 항목이 남아 있습니다. 저장된 네트워크 상태만으로 다운로드·에이전트 실행을 확인할 수 없습니다." -f $hostName) 'Artifact'
                    }
                }
            }
            $storage = Join-Path $cache 'Local Storage\leveldb'
            if (-not (Test-LocalArtifact $storage 'Container')) {
                Add-Finding ("런처 로컬 저장소 $profile") 'Unavailable' 'LevelDB 폴더가 없어 에이전트 상태 기록을 확인할 수 없습니다.'
                return
            }
            if (-not ('NikkeStorageReader' -as [type])) {
                Add-Type -TypeDefinition $nikkeStorageSource -ErrorAction Stop
            }
            $files = @(Get-ChildItem -LiteralPath $storage -File -Force -ErrorAction Stop | Where-Object Extension -in @('.log', '.ldb', '.sst') | Select-Object -First 129)
            if ($files.Count -eq 0) {
                Add-Finding ("런처 로컬 저장소 $profile") 'Unavailable' '확인할 LevelDB 기록 파일이 없습니다.'
                return
            }
            if ($files.Count -gt 128) {
                Add-Finding ("런처 로컬 저장소 $profile") 'Unavailable' 'LevelDB 파일이 128개를 넘어 일부 파일만 확인합니다.'
            }
            $storageBudget = @{ ReadBytes = 0L }
            $fileNumber = 0
            foreach ($file in ($files | Sort-Object Name | Select-Object -First 128)) {
                $fileNumber++
                $name = "런처 로컬 저장소 $profile 파일 #$fileNumber"
                Invoke-ReadCheck $name {
                    if (-not (Test-LocalArtifact $file.FullName 'Leaf')) { throw '저장소 파일이 없어졌습니다.' }
                    if ($file.Length -gt 16MB -or $storageBudget.ReadBytes + $file.Length -gt 64MB) {
                        Add-Finding $name 'Unavailable' '파일당 16MB 또는 프로필당 64MB 제한으로 확인하지 못했습니다.'
                        return
                    }
                    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
                    $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
                    try {
                        if ($stream.Length -gt 16MB -or $storageBudget.ReadBytes + $stream.Length -gt 64MB) { throw '열린 파일이 크기 제한을 넘습니다.' }
                        $bytes = New-Object byte[] ([int]$stream.Length)
                        $offset = 0
                        while ($offset -lt $bytes.Length) {
                            $n = $stream.Read($bytes, $offset, $bytes.Length - $offset)
                            if ($n -eq 0) { throw '저장소를 읽는 동안 파일 길이가 바뀌었습니다.' }
                            $offset += $n
                        }
                        if ($stream.Length -ne $bytes.Length) { throw '저장소를 읽는 동안 파일 길이가 바뀌었습니다.' }
                        $storageBudget.ReadBytes += $bytes.Length
                    } finally { $stream.Dispose() }
                    $result = [NikkeStorageReader]::Inspect($bytes, $file.Extension -in @('.ldb', '.sst'))
                    if ($result.StateRecords -gt 0) {
                        Add-Finding $name 'Strong' '니케 런처 origin의 k2f.agent 또는 k2f.agent.state 키에 값을 저장한 유효한 LevelDB 기록이 있습니다. 과거 기록도 포함하며 값 내용은 출력하지 않습니다.' 'Artifact'
                    }
                    if ($result.DeletedStateKeys -gt 0) {
                        Add-Finding $name 'Clue' '니케 런처 origin의 에이전트 상태 키를 삭제한 LevelDB 기록이 있습니다. 상태 값이나 실행 시각은 확인할 수 없습니다.' 'Artifact'
                    }
                    if ($result.Error) {
                        Add-Finding $name 'Unavailable' 'LevelDB 구조·체크섬·압축 형식·크기 중 일부를 검증하지 못했습니다. 이 파일의 음성 판정은 사용할 수 없습니다.'
                    }
                }
            }
        }
    }
}


Invoke-ReadCheck 'Chrome 백도어 흔적' {
    $clsid = '{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $rootKey = $null
        $key = $null
        $inproc = $null
        try {
            $rootKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::CurrentUser, $view)
            $key = $rootKey.OpenSubKey("Software\Classes\CLSID\$clsid", $false)
            if (-not $key) { continue }
            $inproc = $key.OpenSubKey('InprocServer32', $false)
            $target = if ($inproc) { $inproc.GetValue('') } else { $null }
            if ($target -is [string] -and $target -match '\\PlatformExperienceHelper\\[0-9a-f]{64}\\platform_experience_helper\.dll"?$') {
                Add-Finding 'Chrome 백도어 흔적' 'Strong' ("현재 사용자 {0}의 등록 키가 보고된 Chrome 악성 DLL 경로를 가리킵니다." -f $view) 'Artifact'
            } else {
                Add-Finding 'Chrome 백도어 흔적' 'Clue' ("현재 사용자 {0}에 보고된 CLSID가 있습니다. DLL 연결값은 추가 확인이 필요합니다." -f $view) 'Artifact'
            }
        } catch {
            Add-Finding 'Chrome 백도어 흔적' 'Unavailable' ("현재 사용자 {0}의 레지스트리를 읽지 못했습니다." -f $view)
        } finally {
            if ($inproc) { $inproc.Dispose() }
            if ($key) { $key.Dispose() }
            if ($rootKey) { $rootKey.Dispose() }
        }
    }
    $helper = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\PlatformExperienceHelper'
    if (Test-LocalArtifact $helper 'Container') {
        foreach ($folder in (Get-ChildItem -LiteralPath $helper -Directory -Force -ErrorAction Stop)) {
            if ($folder.Name -match '^[0-9a-f]{64}$' -and
                -not ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
                (Test-LocalArtifact (Join-Path $folder.FullName 'platform_experience_helper.dll') 'Leaf')) {
                Add-Finding 'Chrome 백도어 흔적' 'Strong' '보고된 경로 구조의 Chrome 악성 DLL 파일명을 발견했습니다.' 'Artifact'
            }
        }
    }
}

Invoke-ReadCheck 'K2F 임시 파일' {
    if (-not (Test-LocalArtifact $env:TEMP 'Container')) { throw '로컬 임시 폴더를 확인할 수 없습니다.' }
    $temporary = @(Get-ChildItem -LiteralPath $env:TEMP -File -Force -Filter 'k2f*' -ErrorAction Stop |
        Where-Object Name -match '^k2f-(?:bcreds|keyscan)-\d+-.+\.db$|^k2f_screen_\d+_\d+\.(?:png|jpg)$')
    if ($temporary.Count -gt 0) {
        Add-Finding 'K2F 임시 파일' 'Strong' ("보고된 K2F 임시 파일명과 일치하는 항목 {0}개가 있습니다." -f $temporary.Count) 'Artifact'
    }
}

Invoke-ReadCheck 'K2F 실행 채널' {
    if ([IO.Directory]::GetFiles('\\.\pipe\') -match '\\k2f_chan$') {
        Add-Finding 'K2F 실행 채널' 'Strong' '실행 중인 k2f_chan 이름의 파이프를 발견했습니다.' 'Artifact'
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
    $events = @()
    try { $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'
        ID = 1000, 1001, 1002, 1005
    } -MaxEvents 100 -ErrorAction Stop) } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound,*') { throw }
    }
    foreach ($event in $events) {
        $fields = ([xml]$event.ToXml()).Event.EventData.Data
        if (($fields | Where-Object Name -eq 'Scan Parameters Index').'#text' -ne '2') { continue }
        $scanStatus = switch ($event.Id) {
            1000 { '시작 기록만 확인됨' }
            1001 { '완료' }
            1002 { '중단' }
            1005 { '실패' }
        }
        Add-Finding 'Defender 전체 검사 기록' 'Context' ('최근 이벤트 {0} ({1} 로컬 시간). 이 이벤트는 탐지 결과와 별개입니다.' -f $scanStatus, $event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))
        return
    }
    Add-Finding 'Defender 전체 검사 기록' 'Unavailable' '최근 전체 검사 이벤트를 확인할 수 없습니다.'
}

Invoke-ReadCheck 'Defender 보호·탐지 상태' {
    $state = Get-MpComputerStatus -ErrorAction Stop
    Add-Finding 'Defender 보호·탐지 상태' 'Context' ('Defender 서비스 {0}, 실시간 보호 {1}, 실행 모드 {2}. 다른 백신 사용 시 함께 확인하세요.' -f $state.AMServiceEnabled, $state.RealTimeProtectionEnabled, $state.AMRunningMode)
    $detections = @(Get-MpThreatDetection -ErrorAction Stop)
    Add-Finding 'Defender 보호·탐지 상태' 'Context' ('보존된 Defender 탐지 항목 {0}개. 탐지가 없어도 과거 감염을 배제할 수 없습니다. 다른 백신의 탐지 결과는 해당 프로그램에서 확인하세요.' -f $detections.Count)
}

if ($Deep) {
    Invoke-ReadCheck 'Windows Prefetch 실행 기록' {
        $prefetch = Join-Path $env:windir 'Prefetch'
        if (-not (Test-LocalArtifact $prefetch 'Container')) {
            Add-Finding 'Windows Prefetch 실행 기록' 'Unavailable' 'Prefetch 폴더가 없습니다.'
            return
        }
        if (-not ('NikkePrefetchV2' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public sealed class NikkePrefetchResult {
    public DateTime[] Times;
    public bool HasDebugLog;
    public string FileNames;
    public string Process;
}
public static class NikkePrefetchV2 {
    [DllImport("ntdll.dll")]
    static extern int RtlGetCompressionWorkSpaceSize(ushort format,out uint size,out uint fragment);
    [DllImport("ntdll.dll")]
    static extern int RtlDecompressBufferEx(ushort format,byte[] output,uint size,byte[] input,uint length,out uint written,IntPtr workspace);
    public static NikkePrefetchResult Parse(byte[] input) {
        const int limit=4*1024*1024;
        if(input.Length<8 || input.Length>limit)throw new InvalidDataException();
        byte[] data=input;
        if(input[0]==77 && input[1]==65 && input[2]==77) {
            if(input[3]!=4)throw new NotSupportedException("MAM variant");
            uint length=BitConverter.ToUInt32(input,4);
            if(length<156 || length>limit)throw new InvalidDataException();
            uint workspaceSize,fragmentSize,written;
            if(RtlGetCompressionWorkSpaceSize(4,out workspaceSize,out fragmentSize)!=0 || workspaceSize>limit)throw new InvalidDataException();
            IntPtr workspace=Marshal.AllocHGlobal((int)workspaceSize);
            try {
                byte[] packed=new byte[input.Length-8];
                Buffer.BlockCopy(input,8,packed,0,packed.Length);
                data=new byte[(int)length];
                if(RtlDecompressBufferEx(4,data,length,packed,(uint)packed.Length,out written,workspace)!=0 || written!=length)throw new InvalidDataException();
            } finally {Marshal.FreeHGlobal(workspace);}
        }
        if(data.Length<156 || Encoding.ASCII.GetString(data,4,4)!="SCCA" || BitConverter.ToUInt32(data,12)!=data.Length)throw new InvalidDataException();
        uint version=BitConverter.ToUInt32(data,0);
        int timeOffset,count;
        switch(version) {
            case 17: timeOffset=120;count=1;break;
            case 23: timeOffset=128;count=1;break;
            case 26: case 30: case 31: timeOffset=128;count=8;break;
            default:throw new NotSupportedException("Prefetch version");
        }
        if(timeOffset+8*count>data.Length)throw new InvalidDataException();
        string process=Encoding.Unicode.GetString(data,16,60).TrimEnd('\0');
        if(process!="NIKKE_LAUNCHER.EXE" && process!="NIKKE_LAUNCHER_GOOGLE.EXE" && process!="NIKKE_LAUNCHER_HMT.EXE" && process!="TBS_BROWSER.EXE")throw new InvalidDataException();
        uint nameOffset=BitConverter.ToUInt32(data,100),nameSize=BitConverter.ToUInt32(data,104);
        if(nameOffset>data.Length || nameSize>data.Length-nameOffset || nameSize%2!=0)throw new InvalidDataException();
        string names=Encoding.Unicode.GetString(data,(int)nameOffset,(int)nameSize);
        bool hasDebug=names.IndexOf(@"\INTL_SERVICE\DEBUG.LOG",StringComparison.OrdinalIgnoreCase)>=0;
        var times=new List<DateTime>();
        long oldest=new DateTime(2000,1,1,0,0,0,DateTimeKind.Utc).ToFileTimeUtc();
        long newest=DateTime.UtcNow.AddDays(1).ToFileTimeUtc();
        for(int i=0;i<count;i++) {
            long value=BitConverter.ToInt64(data,timeOffset+8*i);
            if(value==0)continue;
            if(value<oldest || value>newest)throw new InvalidDataException();
            times.Add(DateTime.FromFileTimeUtc(value));
        }
        return new NikkePrefetchResult{Times=times.ToArray(),HasDebugLog=hasDebug,FileNames=names,Process=process};
    }
}
'@ -ErrorAction Stop
        }
        $files = @(Get-ChildItem -LiteralPath $prefetch -File -ErrorAction Stop |
            Where-Object Name -match '^(?:NIKKE_LAUNCHER(?:_GOOGLE|_HMT)?|TBS_BROWSER)\.EXE-[0-9A-F]+\.pf$')
        if ($files.Count -gt 64) {
            Add-Finding 'Windows Prefetch 실행 기록' 'Unavailable' 'Prefetch 후보가 64개를 넘어 일부를 건너뜁니다.'
        }
        foreach ($file in ($files | Select-Object -First 64)) {
            try {
                if (-not (Test-LocalArtifact $file.FullName 'Leaf')) { continue }
                if ($file.Length -gt 4MB) { throw '크기 제한' }
                $parsed = [NikkePrefetchV2]::Parse([IO.File]::ReadAllBytes($file.FullName))
                $nikkeReference = $parsed.FileNames -match '\\NIKKE(?:_GOOGLE|_HMT)?\\LAUNCHER\\'
                foreach ($launcher in $launchers) {
                    if ($parsed.FileNames.IndexOf($launcher.Substring(2).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -ge 0) { $nikkeReference = $true }
                }
                if ($parsed.Process -eq 'TBS_BROWSER.EXE' -and (-not $parsed.HasDebugLog -or -not $nikkeReference)) {
                    Add-Finding 'Windows Prefetch 실행 기록' 'Unavailable' '내장 브라우저 후보를 찾았으나 니케 로그 참조가 없어 니케 실행 기록으로 연결하지 못했습니다.'
                    continue
                }
                foreach ($time in $parsed.Times) {
                    Add-LaunchTime ('Windows Prefetch ' + $parsed.Process) $time
                }
                if ($parsed.HasDebugLog) {
                    Add-Finding 'Windows Prefetch 실행 기록' 'Context' '내장 브라우저 또는 런처 Prefetch에 intl_service\debug.log 파일 참조가 있습니다. 로그 내용과 감염 표식은 포함하지 않습니다.'
                }
            } catch {
                Add-Finding 'Windows Prefetch 실행 기록' 'Unavailable' 'Prefetch 후보 일부를 읽거나 지원되는 형식으로 해석하지 못했습니다.'
            }
        }
    }

    # These event sources can corroborate network activity, never application-level commands or exfiltration.
    $historyStart = if ($sinceKst) { $sinceKst } else {
        [DateTimeOffset]::Parse('2026-09-27T15:41:00+09:00', [Globalization.CultureInfo]::InvariantCulture)
    }
    $historyEnd = if ($untilKst) { $untilKst } else { [DateTimeOffset]::UtcNow }
    $sources = @(
        @{ Name = 'Sysmon 네트워크·DNS 기록'; Channel = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(3, 22) },
        @{ Name = 'Windows DNS 과거 기록'; Channel = 'Microsoft-Windows-DNS-Client/Operational'; Ids = @() },
        @{ Name = 'Windows 연결 감사 기록'; Channel = 'Security'; Ids = @(5156, 5157) }
    )
    $networkPattern = '(?i)(?<![a-z0-9.-])(?:(?:[a-z0-9-]+\.)*insightjs\.(?:com|org)\.?|89\.127\.233\.127|89\.126\.250\.172)(?![a-z0-9.-])'
    foreach ($source in $sources) {
        Invoke-ReadCheck $source.Name {
            $log = Get-WinEvent -ListLog $source.Channel -ErrorAction Stop
            if (-not $log.RecordCount) {
                Add-Finding $source.Name 'Unavailable' ("보존된 이벤트가 없습니다. 현재 채널 활성화 상태 {0}." -f $log.IsEnabled)
                return
            }
            $oldest = (Get-WinEvent -LogName $source.Channel -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated
            $oldestKst = [DateTimeOffset]::new($oldest.ToUniversalTime()).ToOffset([TimeSpan]::FromHours(9))
            Add-Finding $source.Name 'Context' ('가장 오래 보존된 이벤트 {0} KST. 현재 채널 활성화 상태 {1}.' -f $oldestKst.ToString('yyyy-MM-dd HH:mm:ss'), $log.IsEnabled)
            if ($oldestKst -gt $historyStart) {
                Add-Finding $source.Name 'Unavailable' '요청한 시작 시각 이전까지 로그가 보존되어 있지 않습니다. 해당 기간 전체를 확인할 수 없습니다.'
            }
            $query = @{ LogName = $source.Channel; StartTime = $historyStart.UtcDateTime; EndTime = $historyEnd.UtcDateTime.AddTicks(-1) }
            if ($source.Ids.Count) { $query.Id = $source.Ids }
            $count = 0
            $hitCount = 0
            try {
                Get-WinEvent -FilterHashtable $query -MaxEvents 20000 -ErrorAction Stop | ForEach-Object {
                    $count++
                    if ($_.ToXml() -match $networkPattern) {
                        $hitCount++
                        if ($hitCount -le 20) {
                            $stamp = [DateTimeOffset]::new($_.TimeCreated.ToUniversalTime()).ToOffset([TimeSpan]::FromHours(9))
                            Add-Finding $source.Name 'Clue' ('알려진 도메인/IP가 이벤트 ID {0}에 있습니다. 조회·연결·차단 기록으로, 악성코드 실행이나 서버 명령 수신을 확정할 수 없습니다.' -f $_.Id) 'Context' $stamp.ToString('o')
                        }
                    }
                }
            } catch {
                if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound,*') { throw }
            }
            if ($count -ge 20000) { Add-Finding $source.Name 'Unavailable' '이벤트 20,000개 제한에 도달해 일부 기록을 확인하지 못했습니다.' }
            Add-Finding $source.Name 'Context' ("지정 기간 이벤트 {0}개, 알려진 주소 일치 {1}개. 과거 기록 설정과 보존 상태의 영향을 받습니다." -f $count, $hitCount)
            if ($count -eq 0) {
                Add-Finding $source.Name 'Unavailable' '해당 기간의 관련 이벤트가 없어 과거 접속 여부를 판정할 수 없습니다.'
            } elseif ($hitCount -eq 0) {
                Add-Finding $source.Name 'NotFound' '읽은 이벤트에서 알려진 주소가 발견되지 않았습니다.'
            }
        }
    }

    Invoke-ReadCheck 'Windows 방화벽 과거 기록' {
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        $paths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($profile in $profiles) {
            Add-Finding 'Windows 방화벽 과거 기록' 'Context' ('{0} 프로필의 현재 허용 로그 {1}, 차단 로그 {2}. 현재 설정으로 과거 설정은 판단할 수 없습니다.' -f $profile.Name, $profile.LogAllowed, $profile.LogBlocked)
            if ($profile.LogFileName) {
                $path = [Environment]::ExpandEnvironmentVariables($profile.LogFileName)
                if ($path -match '^[A-Za-z]:\\') { [void]$paths.Add($path); [void]$paths.Add($path + '.old') }
            }
        }
        $defaultFolder = Join-Path $env:windir 'System32\LogFiles\Firewall'
        if (Test-LocalArtifact $defaultFolder 'Container') {
            foreach ($file in (Get-ChildItem -LiteralPath $defaultFolder -File -ErrorAction Stop |
                Where-Object Name -match '^pfirewall[^\\]*\.log(?:\.old)?$')) { [void]$paths.Add($file.FullName) }
        }
        $filesRead = 0
        foreach ($path in $paths) {
            try {
                if (-not (Test-LocalArtifact $path 'Leaf')) { continue }
                if ((Get-Item -LiteralPath $path -ErrorAction Stop).Length -gt 32MB) { throw '크기 제한' }
                $filesRead++
                $rows = 0
                $hits = 0
                $format = ''
                $earliest = $null
                $latest = $null
                Get-Content -LiteralPath $path -ReadCount 512 -ErrorAction Stop | ForEach-Object {
                    foreach ($line in $_) {
                        if ($line -match '^#Time Format:\s*(Local|UTC)\s*$') { $format = $Matches[1]; continue }
                        if ($line -notmatch '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s') { continue }
                        if (-not $format) { continue }
                        $value = [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
                        if ($format -eq 'UTC') { $value = [datetime]::SpecifyKind($value, [DateTimeKind]::Utc) }
                        else { $value = [datetime]::SpecifyKind($value, [DateTimeKind]::Local) }
                        $stamp = [DateTimeOffset]::new($value)
                        if (-not $earliest -or $stamp -lt $earliest) { $earliest = $stamp }
                        if (-not $latest -or $stamp -gt $latest) { $latest = $stamp }
                        if ($stamp -lt $historyStart -or $stamp -ge $historyEnd) { continue }
                        $rows++
                        if ($line -match $networkPattern) { $hits++ }
                    }
                }
                if (-not $format) {
                    Add-Finding 'Windows 방화벽 과거 기록' 'Unavailable' '로그의 시간대 머리말이 없어 기간별 접속 여부를 확인하지 못했습니다.'
                    continue
                }
                if (-not $earliest -or $earliest -gt $historyStart -or $latest -lt $historyStart) {
                    Add-Finding 'Windows 방화벽 과거 기록' 'Unavailable' '로그에 요청한 시작 시각까지의 기록이 남아 있지 않습니다.'
                }
                Add-Finding 'Windows 방화벽 과거 기록' 'Context' ("읽은 파일 #{0}, 기간 내 행 {1}개, 알려진 주소 일치 {2}개." -f $filesRead, $rows, $hits)
                if ($hits) {
                    Add-Finding 'Windows 방화벽 과거 기록' 'Clue' '알려진 주소가 방화벽 로그에 있습니다. 허용·차단 여부와 연결 주체를 원본에서 추가 확인해야 합니다.' 'Context'
                } elseif ($rows) {
                    Add-Finding 'Windows 방화벽 과거 기록' 'NotFound' '읽은 방화벽 행에서 알려진 주소를 찾지 못했습니다.'
                }
            } catch { Add-Finding 'Windows 방화벽 과거 기록' 'Unavailable' '방화벽 로그 일부를 읽거나 해석하지 못했습니다.' }
        }
        if ($filesRead -eq 0) { Add-Finding 'Windows 방화벽 과거 기록' 'Unavailable' '읽을 수 있는 방화벽 로그 파일이 없습니다.' }
    }
}

$verdict = if ($checks.Status -contains 'Strong') {
    '공개 감염 지표와 일치하는 강한 흔적을 발견했습니다. 원본을 보존하고 확인된 항목을 검토하세요.'
} elseif ($checks.Status -contains 'Clue') {
    '추가 확인이 필요한 단서를 발견했습니다. 이 결과만으로 감염 여부를 판정할 수 없습니다.'
} else {
    '확인한 범위에서 알려진 감염 지표를 찾지 못했습니다. 과거 감염이나 정보 유출 여부는 확인할 수 없습니다.'
}

$unavailableCount = @($checks | Where-Object Status -eq 'Unavailable').Count
if ($unavailableCount) { $verdict += ' 확인 불가 항목 {0}개가 남아 있습니다.' -f $unavailableCount }
$stages = foreach ($stage in @('Request', 'Download', 'Execution', 'ServerResponse', 'Exfiltration')) {
    $evidence = @($checks | Where-Object { $_.Stage -eq $stage -and $_.Status -in @('Strong', 'Clue') })
    $stageStatus = if ($evidence.Status -contains 'Strong') { 'Supported' }
        elseif ($stage -eq 'Request' -and $evidence.Count) { 'Recorded' }
        elseif ($evidence.Count) { 'Unconfirmed' } else { 'Unknown' }
    $meaning = switch ($stage) {
        Request { '악성 파일 요청 표식' }
        Download { '동일 작업의 다운로드 완료 표식' }
        Execution { '악성 에이전트 실행 표식' }
        ServerResponse { '등록 이후 같은 실행 흐름의 서버 응답 표식' }
        Exfiltration { '특정 정보의 접근·전송 증거. 이 스크립트는 유출 내용을 판정하지 않습니다.' }
    }
    [pscustomobject][ordered]@{ Stage = $stage; Status = $stageStatus; EvidenceCount = $evidence.Count; Detail = $meaning }
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Json) {
    [pscustomobject][ordered]@{
        SchemaVersion = 2
        ScannerVersion = $scannerVersion
        CollectedAtKst = [DateTimeOffset]::UtcNow.ToOffset([TimeSpan]::FromHours(9)).ToString('o')
        IsAdmin = $isAdmin
        Deep = [bool]$Deep
        Period = [pscustomobject]@{ SinceKst = $Since; UntilKstInclusive = $Until }
        Verdict = $verdict
        Stages = @($stages)
        Checks = $checks.ToArray()
    } | ConvertTo-Json -Depth 5
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
    foreach ($stage in $stages) {
        $label = switch ($stage.Status) {
            Supported { '근거 확인' }
            Recorded { '요청 기록' }
            Unconfirmed { '단서만 확인' }
            Unknown { '미확인' }
        }
        '[{0}] {1}' -f $label, $stage.Detail
    }
    ''
    $verdict
}
