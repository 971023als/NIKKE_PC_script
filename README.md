# 니케 PC 런처 보안 점검

2026년 11월 공개된 니케 PC 런처 사건의 감염 지표를 Windows에서 확인하는 비공식 PowerShell 스크립트입니다. 현재 Windows 계정의 파일·레지스트리와 남아 있는 실행·통신 기록을 조회합니다. 기본 검사는 일반 사용자 권한으로 실행할 수 있습니다. **과거 로그가 사라졌거나 검사에 실패하면 확인 불가로 표시하며, 감염 및 정보 유출 여부를 완전히 보장하지 않습니다.**

운영사는 **2026년 9월 27일 15시 41분 KST 이후 Windows PC 런처를 한 번 이상 실행한 사용자**에게 점검을 안내했습니다. 모바일 버전만 이용한 사용자는 이번 PC 런처 사고의 점검 대상에 해당하지 않습니다. 공식 공지와 이 저장소의 사용 방법을 함께 확인하세요. [공식 수동 점검 안내](https://game.naver.com/lounge/nikke/board/detail/8412547)

## 다운로드하고 실행하기

1. [Test-NikkePc.ps1](./Test-NikkePc.ps1)을 열어 소스를 확인한 뒤 **Download raw file**로 내려받습니다.
2. 파일이 있는 폴더에서 **Windows PowerShell**을 열고 다음 명령을 실행합니다. Windows PowerShell 5.1과 Windows용 PowerShell 7을 지원합니다.

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Test-NikkePc.ps1
~~~

다운로드 표시 때문에 실행이 차단되면, 파일과 GitHub 소스가 일치하는지 확인한 뒤 그 파일의 차단을 해제하고 다시 실행하세요. 위 명령의 실행 정책은 새 프로세스에 적용됩니다. 조직에서 관리하는 PC에는 조직 정책이 적용됩니다. [Microsoft 다운로드 파일 차단 안내](https://learn.microsoft.com/ko-kr/powershell/module/microsoft.powershell.utility/unblock-file?view=powershell-5.1)

~~~powershell
Unblock-File -LiteralPath .\Test-NikkePc.ps1
~~~

게임 설치 폴더 또는 그 아래 `Launcher` 폴더를 지정할 수 있습니다. 여러 경로를 전달하려면 현재 PowerShell에서 배열로 호출하세요. 기본 설치 경로에는 NIKKE, `NIKKE_GOOGLE` 및 알려진 런처 변형을 포함합니다.

~~~powershell
.\Test-NikkePc.ps1 -NikkePath 'D:\Games\NIKKE'
.\Test-NikkePc.ps1 -NikkePath 'D:\Games\NIKKE', 'E:\Backup\NIKKE' -Json
~~~

보존해 둔 로그 사본은 `-LogPath`로 전달합니다. `debug.log` 사본이나 tinyget 로그 파일·폴더를 지정할 수 있습니다. 연결되지 않은 드라이브, 접근할 수 없는 폴더, 재분석 지점 및 크기 제한을 넘는 자료는 확인 불가로 표시됩니다. 텍스트 로그는 파일당 32MB·20만 줄, 후보는 폴더당 256개로 제한하며 넘어간 범위를 표시합니다.

~~~powershell
.\Test-NikkePc.ps1 -LogPath 'E:\Evidence\debug.log', 'E:\Evidence\tinyget' -Json
~~~

**`-Deep`은 남아 있는 Windows 기록을 추가 조회합니다.** 관리자 권한 PowerShell에서 실행하면 Prefetch, 보존된 Sysmon·DNS·Windows 보안 이벤트 및 방화벽 로그를 더 읽을 수 있습니다. 권한이 부족하거나 기록이 없으면 해당 검사를 확인 불가로 표시합니다. 스크립트가 관리자 권한으로 자동 재실행되지는 않습니다.

~~~powershell
.\Test-NikkePc.ps1 -NikkePath 'D:\Games\NIKKE' -Deep -Since '2026-10-24' -Until '2026-10-25' -Json
~~~

`-Since`와 `-Until`은 `yyyy-MM-dd` 형식의 **한국시간 날짜이며 양쪽 날짜를 모두 포함**합니다. 기간은 실행 이력과 과거 통신 이벤트에 적용합니다. 런처 로그에 연도가 없거나 시간대가 확인되지 않으면 요청한 기간과 일치한다고 확정하지 않습니다. 이런 줄의 발견 항목은 로그 전체 범위의 흔적으로 결과에 남기고, 기간 포함 여부는 확인 불가로 함께 표시합니다. 현재 남은 캐시·레지스트리·DLL, 현재 TCP 연결과 DNS 캐시는 기간과 관계없이 점검합니다.

## 결과를 읽는 방법

| Status | 화면 표시 | 의미 |
| --- | --- | --- |
| `Strong` | 강한 지표 | 알려진 악성 샘플 해시, 에이전트 실행 표식, Chrome DLL 지속성 구조 등과 일치합니다. 각 항목의 Detail을 확인하세요. |
| `Clue` | 단서 | 다운로드 요청, 알려진 주소나 캐시 이름처럼 추가 확인이 필요한 흔적입니다. |
| `Context` | 참고 | 니케 프로세스 실행, MetaMask 설치·잔여 폴더, 백신 등록·검사 기록 등입니다. |
| `NotFound` | 미발견 | 읽을 수 있었던 해당 범위에서 일치 항목을 찾지 못했습니다. |
| `Unavailable` | 확인 불가 | 기록 부재, 읽기 실패, 미지원 형식, 범위·크기 제한 등으로 검사가 불완전합니다. |

JSON은 `SchemaVersion` 2로 기존 `Verdict`와 `Checks`를 유지하고, 검사 버전·수집 시각·권한·기간 및 단계별 `Stages`를 함께 제공합니다. `Checks`의 `Stage`·`Time`으로 개별 근거를 확인하세요. 자동 해석 도구는 `Unavailable`도 함께 확인해야 합니다.

| `Stages.Status` | 화면 표시 | 의미 |
| --- | --- | --- |
| `Supported` | 근거 확인 | 해당 단계에 `Strong` 근거가 있습니다. |
| `Recorded` | 요청 기록 | 악성 파일 요청 표식이 기록돼 있습니다. |
| `Unconfirmed` | 단서만 확인 | 해당 단계에 `Clue`가 있으나 확정 근거가 부족합니다. |
| `Unknown` | 미확인 | 해당 단계를 뒷받침할 기록을 확보하지 못했습니다. |

`Stages`는 확보한 근거를 요약하므로 연도·시간대가 없는 로그의 발견도 포함할 수 있습니다. 지정 날짜에 발생한 일인지 판단할 때는 해당 `Checks`의 `Time`과 기간 관련 `Unavailable`을 함께 확인하세요. 특정 정보의 유출은 이 스크립트에서 판정하지 않아 `Exfiltration`을 미확인으로 남깁니다.

| 확인하려는 단계 | 필요한 증거 | 판정의 한계 |
| --- | --- | --- |
| 요청 | tinyget의 `insight.bundle` `AddTask` | 요청한 사실만 확인합니다. |
| 다운로드 완료 | 같은 작업의 `curl perform success`와 `OnDownloadResult`에서 `result=0`, `total>0` | 다른 작업의 성공 줄을 합치지 않습니다. 실패·요청만 남은 경우를 구분합니다. |
| 에이전트 실행 | `debug.log`의 `k2f_chan registered` | 실행의 강한 증거입니다. 이후 시작 오류가 있어도 등록 사실은 남습니다. |
| 서버 응답 | 같은 실행 흐름에서 등록 이후의 `adopted` 또는 `resuming` | 어떤 명령을 실행했는지까지 확인하지 못합니다. |
| 정보 유출 | 전송 내용, 특정 자료 접근·전송의 별도 증거 | 등록·응답 표식이나 통신량만으로 특정 계정·지갑의 유출을 확정할 수 없습니다. |

이 표는 공개 분석의 판별 기준을 요약합니다. `startup already in progress`만으로 다운로드·실행을 판단할 수 없으며, 정상 로그의 `FETCH_LIST` 성공 줄도 악성 실행 표식에 해당하지 않습니다. [로그 판별 기준](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5#check-if-you-are-infected)

## 공식 수동 조치와 대조하기

검사 전에 네트워크를 차단하고, 시스템 트레이까지 확인해 니케·런처·Chrome을 종료하세요. 먼저 필요한 로그와 캐시를 별도로 보존한 뒤 공식 안내에 따라 조치하세요. 보존한 자료에는 쿠키와 토큰이 포함될 수 있으므로 비공개로 보관하세요.

| 순서 | 확인할 항목 | 수동 조치 시 확인할 조건 |
| --- | --- | --- |
| 로그 | `Launcher\intl_service\debug.log` | `k2f_chan registered`를 검색합니다. `NIKKE_GOOGLE` 설치도 확인합니다. |
| 레지스트리 | `HKEY_CURRENT_USER\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` | 공식 안내의 현재 사용자 키를 확인하고 삭제합니다. 동일 CLSID의 `HKLM` 키는 Windows에서 사용될 수 있습니다. |
| 재부팅·DLL | `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper` | 키 조치 후 재부팅합니다. 이름이 64자리 16진수이고 내부에 `platform_experience_helper.dll`이 있는 두 조건을 모두 충족할 때만 해당 64자리 하위 폴더를 삭제합니다. |
| 다운로드 파일 | `Launcher\log\tinyget` | 공식 수동 안내에 따라 이 경로 안의 `tinyget.<날짜>-<시간>.log` 형식이면서 정확히 205,135바이트인 파일을 확인하고, 증거 보존 후 해당 파일을 삭제합니다. 스크립트는 크기만으로 악성을 확정하거나 자동 삭제하지 않습니다. |
| 런처 캐시 | `%APPDATA%\nikke_launcher\tbs_cache` | 증거 보존 후 전체 캐시를 정리합니다. HMT는 `nikke_launcher_hmt`, Google Play Games는 `nikke_launcher_google`도 확인합니다. |

`PlatformExperienceHelper` 자체에는 정상 Chrome 파일이 있을 수 있으므로 **이 폴더 전체를 삭제하지 마세요.** 위 두 조건을 충족하는 64자리 하위 폴더만 삭제 대상입니다. 악성 샘플은 빌드에 따라 크기·이름이 달라질 수 있어, 205,135바이트 파일이 없다는 결과만으로 과거 감염을 배제할 수 없습니다. 오래된 캐시가 변조된 파일을 다시 불러올 수 있으므로 런처를 재실행하기 전에 점검·보존·정리를 마치세요. [공식 수동 점검 안내](https://game.naver.com/lounge/nikke/board/detail/8412547) · [공개 분석의 제거·캐시 안내](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5#what-to-do)

이 스크립트의 역할은 조회와 요약입니다. 파일·레지스트리 삭제, 방화벽 변경, 캐시 정리, 백신 실행, Windows 초기화는 사용자가 해당 절차에 따라 진행해야 합니다. 운영사는 공식 PC 클라이언트의 ACE 검사·제거 기능과 고객센터 피해 접수도 안내하고 있습니다. [공식 후속 조치 안내](https://m.game.naver.com/lounge/NIKKE_The_Goddess_of_Victory/board/detail/8412545)

## 계정 보호와 Windows 재설치

노출 가능성이 있는 계정은 안전한 다른 기기에서 비밀번호를 변경하고 기존 로그인 세션을 해제하세요. 저장하거나 사용했던 API 키·액세스 토큰·개발 자격 증명도 폐기·재발급 여부를 확인하세요. 백신을 업데이트한 뒤 전체 검사와 Defender 오프라인 검사를 진행하되, 검사 완료 여부와 악성코드 탐지 여부를 각각 확인하세요. [공식 계정·백신 점검 안내](https://game.naver.com/lounge/nikke/board/detail/8412547)

MetaMask 폴더의 존재는 설치·잔여 데이터에 관한 참고 정보입니다. 그 자체로 탈취 시도를 의미하지 않습니다. 지갑 무단 거래나 복구 문구·개인키 노출 정황이 있다면 안전한 기기에서 MetaMask의 대응 절차를 따르세요. 복구 문구와 개인키를 AI 채팅이나 GitHub에 올리지 마세요. [MetaMask 피해 대응 안내](https://support.metamask.io/stay-safe/protect-yourself/ive-been-hacked-scammed-unauthorized-transactions-on-my-account)

Windows를 재설치하거나 초기화했다면 실제로 선택한 방식과 이후 사용 이력을 확인하세요. 이 스크립트는 재설치 방식이나 이전 환경의 복원 여부를 자동 판별하지 않습니다.

| 진행한 방식과 이후 이력 | 이번 사건의 PC 점검·삭제 적용 |
| --- | --- |
| 설치 미디어로 이전 Windows·앱·사용자 데이터를 제거하는 클린 설치를 마쳤고, 이후 니케 PC 런처를 실행하거나 이전 실행 환경을 복원하지 않음 | 이전 설치에 남았던 로그·레지스트리·DLL·캐시를 제거하는 단계는 통상 생략할 수 있습니다. 이는 클린 설치의 제거 범위에 근거한 적용 판단입니다. |
| 초기화에서 **내 파일 유지** 선택 | 개인 파일이 유지되므로 초기화만으로 점검을 생략하지 말고, 남은 파일을 포함해 추가 점검하세요. |
| 초기화에서 **모든 항목 제거** 선택 | 개인 파일·앱·설정을 제거하지만, 초기화 완료만으로 안전을 확정하지 않습니다. 감염이 의심되어 추가 복구가 필요하면 설치 미디어를 이용한 클린 설치 절차를 확인하세요. |
| 파일·앱을 유지하는 복구 재설치 또는 이전 환경을 백업에서 복원함 | 보존·복원한 환경을 기준으로 점검하세요. USB를 사용했더라도 설치 중 선택한 보존 옵션을 확인해야 합니다. |

클린 설치 후 런처를 다시 실행한 경우에는 실행 시점과 당시 배포 상태, 남은 흔적을 기준으로 판단해야 합니다. **어떤 방식으로 재설치·초기화했더라도 이전 PC에서 사용한 계정의 비밀번호 변경, 로그인 세션 해제, API 키·토큰 폐기·재발급은 별도로 진행하세요.** 재설치 방식별 보존 범위와 감염 의심 시 복구 절차는 Microsoft 안내를 확인하세요. [Microsoft 복구 옵션](https://support.microsoft.com/en-us/windows/experience/backup-recovery/recovery-options-in-windows) · [Microsoft 설치 미디어 재설치](https://support.microsoft.com/en-us/windows/deployment/install-upgrade/reinstall-windows-with-the-installation-media)

## 검사 범위와 남는 한계

- 기본 검사는 알려진 설치 경로·지정 경로의 런처 로그, 알려진 AppData 프로필의 캐시, 현재 계정의 Chrome 지속성 흔적, K2F 임시 파일·파이프, 현재 연결·DNS 캐시, MetaMask 폴더 및 백신 기록을 확인합니다.
- `-Deep`은 Prefetch 버전 17·23·26·30·31의 실행 시각을 확인하며 압축본은 `MAM04` 형식을 지원합니다. 파일당 4MB·후보 64개로 제한하고, 미지원·손상 자료는 확인 불가로 표시합니다. Google·HMT 런처 이름도 확인합니다. Prefetch에 런처·내장 브라우저의 실행이 남아 있어도 그 사실만으로 내부 에이전트 실행을 확정할 수 없습니다. 과거 네트워크 검사는 Sysmon 3·22, DNS Client, Windows 보안 5156·5157 및 보존된 방화벽 로그를 확인합니다. 이벤트는 채널당 20,000개, 방화벽 파일은 파일당 32MB로 제한합니다. 기록이 비활성화되었거나 오래된 항목이 지워졌다면 확인 불가로 남습니다. [Microsoft Sysmon 기록 설명](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- 캐시 파일 이름은 단서로 취급합니다. HSTS의 `sts_observed`는 해당 헤더를 마지막으로 받아 저장한 시각이며, 최초 감염 시각으로 사용할 수 없습니다. Local Storage는 LevelDB 기록과 지원되는 Snappy 압축 테이블을 해석합니다. 파일당 16MB·프로필당 64MB·128개 제한, 손상·미지원 자료 등으로 검색하지 못한 범위는 확인 불가 항목을 확인하세요. 과거에 삭제된 상태 기록도 현재 상태와 구분해 해석해야 합니다. [캐시와 저장소 판별 기준](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5#check-if-you-are-infected)
- 다른 Windows 계정은 그 계정에서 별도로 확인해야 합니다. 런처 관리자 승인에 다른 계정을 사용했다면 해당 계정의 AppData·TEMP·`HKCU`도 조사 대상이 됩니다.
- SRUM 앱별 통신량, USN 변경 이력, MFT 파일 레코드·삭제 파일 복구, VSS·백업 사본은 별도의 포렌식 조사 범위입니다. SRUM 집계 시간은 개별 접속 시각과 다르며, 파일 크기와 단일·누적 전송량 비교만으로 악성 다운로드 성공이나 MetaMask 유출 여부를 확정할 수 없습니다.
- 로그가 없으면 삭제·재설치·초기화, 연결되지 않은 예전 설치 드라이브, 별도 보관 사본을 확인하세요. Prefetch에 남은 로그 경로·파일 ID는 원문 로그를 대신하지 못하며 파일 ID가 재사용되었을 수도 있습니다. 원시 디스크 복구는 원본 보존과 전문 분석이 필요한 별도 작업입니다.

기록 조회는 파일 시스템과 Windows API를 이용합니다. 이 스크립트는 런처나 악성 파일을 실행하지 않으며, 검사 자료를 네트워크로 전송하지 않습니다. 원본 로그 줄, 쿠키·토큰·비밀번호·지갑 내용은 출력하지 않습니다. 공유 전에는 검사 시각·백신 이름 등 요약에 포함된 정보의 공개 범위도 확인하세요.

## AI 도구에 요청하는 방법

Test-NikkePc.ps1과 README.md를 같은 폴더에 저장한 뒤 해당 폴더를 로컬 Windows에서 여세요. 아래 문장을 사용 중인 도구에 붙여넣으세요. 설치 폴더와 로그 사본이 있으면 실제 경로를 추가하세요. 도구에 Windows 접근 권한이 없으면 직접 실행한 JSON 요약을 해석하도록 요청하세요.

### Codex

Codex 앱의 로컬 Windows 작업 또는 파일을 저장한 폴더의 Codex CLI에서 요청할 수 있습니다.

~~~text
README.md와 Test-NikkePc.ps1을 검토하고 로컬 Windows에서 다음 읽기 전용 점검을 실행해 주세요.
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Test-NikkePc.ps1 -Json
Stages와 Checks를 함께 읽어 요청·다운로드 완료·에이전트 실행·서버 응답·정보 유출 중 무엇이 확인됐는지 한국어로 설명해 주세요. Unavailable도 빠짐없이 표시하고, 로그 부재나 샌드박스 권한 부족을 미감염으로 해석하지 마세요. 추가 자료가 필요하면 제가 지정한 설치 폴더·로그 사본을 사용하고, Deep 실행이 필요하면 그 이유와 명령을 먼저 보여 주세요.
~~~

### Claude Code

로컬 Windows 터미널에서 파일이 있는 폴더를 열고 Claude Code에 요청하세요.

~~~text
README.md와 Test-NikkePc.ps1을 읽고 어떤 자료를 조회하는지 짧게 설명한 뒤 다음 명령을 실행해 주세요.
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Test-NikkePc.ps1 -Json
Strong·Clue·Context·NotFound·Unavailable과 단계별 결과를 한국어로 설명해 주세요. 서로 다른 tinyget 작업의 성공·실패를 합치지 말고, 실행 흔적과 악성 실행 증거를 구분해 주세요. 계정 토큰이나 원본 로그 대신 스크립트 요약을 사용하세요.
~~~

### Gemini CLI / Google Antigravity

로컬 Windows에 접근할 수 있는 세션에서 파일 폴더를 연 뒤 요청하세요.

~~~text
README.md와 Test-NikkePc.ps1을 검토하고 로컬 Windows에서 다음 명령으로 점검해 주세요.
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Test-NikkePc.ps1 -Json
Checks의 각 Status와 Stages를 함께 확인해 주세요. Strong과 Clue의 근거, 빠진 기록, 권한·형식 제한을 한국어로 알려 주세요. 캐시·Prefetch·SRUM 통신량만으로 특정 파일 다운로드나 지갑 탈취를 확정하지 마세요. 파일 정리나 계정 변경은 점검 결과와 별도 절차로 설명해 주세요.
~~~

### OpenCode

파일을 저장한 폴더의 로컬 Windows 세션에서 OpenCode에 요청하세요.

~~~text
이 폴더의 README.md와 Test-NikkePc.ps1을 읽고 다음 읽기 전용 명령을 실행해 주세요.
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Test-NikkePc.ps1 -Json
강한 지표·단서와 확인 불가 항목을 먼저 설명하고, 요청·다운로드·실행·서버 응답·정보 유출의 확인 범위를 구분해 주세요. Windows PowerShell에 접근할 수 없으면 직접 실행할 명령을 알려 주세요. 보존해야 할 자료가 있으면 정리 전에 안내해 주세요.
~~~

### 웹 채팅·원격 환경에서 결과만 해석하기

Windows PowerShell에서 직접 검사한 뒤, 공유할 범위를 검토한 JSON 요약을 사용하세요. 원본 로그·쿠키·로그인 티켓·지갑 데이터는 로컬에 보관하세요.

~~~text
아래는 제가 Windows에서 직접 실행한 니케 점검 스크립트의 JSON 요약입니다. 결과에 있는 자료만 근거로 Stages와 Checks를 함께 해석해 주세요. 다운로드 요청·완료·에이전트 실행·서버 응답·정보 유출을 구분하고, Unavailable 때문에 판단하지 못한 범위를 명시해 주세요. 미발견을 과거 감염이 없었다는 뜻으로 해석하지 마세요.

[검토한 JSON 요약을 여기에 붙여넣기]
~~~

## 출처

- 운영사의 점검 대상·레지스트리·DLL·다운로드 파일·캐시·계정·백신 안내. [공식 수동 점검 안내](https://game.naver.com/lounge/nikke/board/detail/8412547)
- 사고 경위와 ACE 검사·제거, 피해 접수 및 재발 방지 계획. [공식 후속 조치 안내](https://m.game.naver.com/lounge/NIKKE_The_Goddess_of_Victory/board/detail/8412545)
- 로그 표식, 캐시·HSTS, 샘플 해시와 Chrome 지속성. [MotherSphere의 공개 분석](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5)
- K2F 악성코드와 수집 대상에 대한 독립 분석. [WormW의 기술 분석](https://github.com/WormW/nikke_malware_analysis/blob/main/README.en.md)

공식 공지와 연구자 분석은 게시 시점과 확인 범위가 다릅니다. 이 도구는 특정 날짜에 런처를 실행했다는 이유만으로 감염을 판정하지 않으며, 개인 PC의 실제 검사 결과를 공개 저장소에 포함하지 않습니다.
