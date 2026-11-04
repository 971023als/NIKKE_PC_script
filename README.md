# 니케 PC 런처 보안 점검

2026년 11월 공개된 **승리의 여신: 니케 PC 런처 사건**의 감염 지표를 Windows에서 확인하는 비공식 PowerShell 스크립트입니다. 현재 Windows 계정과 알려진 로컬 경로를 읽기 전용으로 점검합니다. 별도 설치나 관리자 권한은 필요하지 않습니다.

## 다운로드하고 실행하기

1. [Test-NikkePc.ps1](./Test-NikkePc.ps1)을 열어 소스를 확인한 뒤 GitHub의 **Download raw file** 버튼으로 내려받습니다.
2. 파일이 있는 폴더에서 **Windows PowerShell**을 열고 아래 명령을 실행합니다. Windows PowerShell 5.1과 Windows용 PowerShell 7을 지원합니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\Test-NikkePc.ps1
```

브라우저가 붙인 다운로드 표시로 실행이 차단되면, 내려받은 파일과 GitHub 소스가 일치하는지 확인한 뒤 해당 파일에만 아래 명령을 실행하고 다시 시도하세요. 위 실행 명령의 정책은 새 PowerShell 프로세스에만 적용됩니다. 회사나 학교에서 실행을 제한하는 PC는 조직 정책을 따르세요. [Microsoft의 다운로드 파일 차단 설명](https://learn.microsoft.com/ko-kr/powershell/module/microsoft.powershell.utility/unblock-file?view=powershell-5.1)

```powershell
Unblock-File -LiteralPath .\Test-NikkePc.ps1
```

게임이 다른 위치에 설치돼 있으면 설치 폴더 또는 그 아래 `Launcher` 폴더의 절대 경로를 지정하세요. 현재 PowerShell에서 스크립트를 직접 호출할 때는 배열로 여러 경로를 넘길 수 있습니다. `-Json`은 결과를 JSON으로 화면에 표시합니다.

```powershell
.\Test-NikkePc.ps1 -NikkePath 'D:\Games\NIKKE'
.\Test-NikkePc.ps1 -NikkePath 'D:\Games\NIKKE', 'E:\Backup\NIKKE' -Json
```

## 결과 해석

| 표시 | 의미 |
| --- | --- |
| **강한 지표** | 런처 로그의 K2F 실행 표식, 알려진 악성 파일의 해시, 보고된 Chrome DLL 경로 등 공개 감염 지표와 일치하는 흔적입니다. |
| **단서** | DNS 캐시, 로더 캐시, 다운로드 주소, DLL 연결값을 확인하지 못한 사용자 레지스트리 키처럼 추가 검증이 필요한 흔적입니다. 다운로드 요청만 기록된 경우도 포함됩니다. |
| **참고** | 니케 실행 기록, MetaMask 확장 또는 잔여 폴더, 등록된 백신, Defender 검사 이벤트입니다. |
| **미발견** | 해당 점검이 확인한 범위에서 일치 항목을 찾지 못했습니다. |
| **확인 불가** | 로그나 캐시가 없거나 권한, 경로 또는 파일 크기 제한으로 일부를 읽지 못했습니다. |

강한 지표가 나오면 PC를 인터넷에서 분리하고, 조사에 필요한 원본 로그와 캐시를 보존하세요. 계정 조치는 신뢰할 수 있는 다른 기기에서 진행하세요. 지갑에서 무단 거래나 복구 문구 노출 정황을 발견하면 MetaMask의 피해 대응 절차를 따르세요. [연구자의 감염 대응 절차](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5#what-to-do) · [MetaMask 무단 거래 대응](https://support.metamask.io/stay-safe/protect-yourself/ive-been-hacked-scammed-unauthorized-transactions-on-my-account)

## 검사 범위

- 런처의 `intl_servicedebug.log`, `log	inyget`, 알려진 AppData 프로필의 캐시와 로컬 저장소를 확인합니다.
- 현재 계정의 Chrome 백도어 관련 레지스트리와 DLL 경로, K2F 임시 파일명·파이프, 현재 TCP 연결과 Windows DNS 캐시를 확인합니다.
- Windows의 PCA·UserAssist 실행 시각을 **한국시간(KST)**으로 표시합니다. 실행 기록은 일부 실행만 남을 수 있습니다.
- 로컬 고정 드라이브의 알려진 경로와 지정 경로를 확인합니다. LevelDB에서는 평문 표식을 검색하므로 압축된 데이터나 8MB를 넘는 파일에서 흔적을 놓칠 수 있습니다. tinyget 텍스트 로그는 파일당 최대 32MB까지 검색합니다.
- 앱별 과거 통신량(SRUM), NTFS 변경 기록(USN), 복원 지점, 다른 Windows 계정은 별도의 포렌식 조사 범위입니다. 감염 지표가 발견되지 않아도 과거 감염이나 정보 유출 여부는 미확인 상태입니다.

스크립트에는 다운로드·업로드·정리·백신 실행 기능이 없습니다. 원본 로그 줄, 쿠키, 비밀번호, 지갑 데이터 내용은 출력하지 않습니다. 결과를 공유하기 전에는 실행 시각이나 백신 이름 등 공개 범위를 확인하세요.

## 출처

- 운영사의 PC 런처 수정 공지. [니케 공식 안내](https://game.naver.com/lounge/nikke/board/detail/8407974)
- 런처 로그 표식, 캐시 파일명, 샘플 해시 및 Chrome 지속성 지표. [MotherSphere의 공개 분석](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5)
- K2F 악성코드와 수집 대상에 대한 독립 분석. [WormW의 기술 분석](https://github.com/WormW/nikke_malware_analysis/blob/main/README.en.md)
