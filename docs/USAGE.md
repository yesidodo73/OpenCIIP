# 사용 방법

릴리스 빌드는 점검 규칙을 포함한 단일 바이너리입니다. 실행할 서버에 Go나 별도 규칙 파일을 설치할 필요가 없습니다.

[Releases](https://github.com/yesidodo73/OpenCIIP/releases)에서 `openciip-linux-amd64`를 내려받은 뒤, 다운로드한 위치에서 실행 권한을 한 번 부여하세요. `/usr/local/bin` 같은 시스템 경로에 설치할 필요는 없습니다.

```bash
chmod +x ./openciip-linux-amd64
```

## 대화형 실행

대화형 터미널에서 인자 없이 실행하면 점검 화면이 열립니다.

```bash
sudo ./openciip-linux-amd64
```

시작 화면에서 방향키와 `Enter`로 실행 옵션을 선택하면 점검 범위, 개별 점검, 증적 저장 범위, 보고서 경로, 결과 표시 범위와 민감정보 마스킹을 설정할 수 있습니다. 옵션을 변경하지 않으면 전체 항목을 점검하고 문제 항목의 증적을 실행 당시 현재 디렉터리 아래 `reports/`의 절대경로에 마스킹하여 저장합니다.

점검 범위와 개별 점검은 목록에서 복수 선택합니다. TUI에서 보고서 경로를 직접 입력할 때는 절대경로를 사용합니다. 분류와 중요도 필터는 CLI에서 사용할 수 있습니다.

자동 조치 옵션은 TUI 실행 옵션에 표시됩니다. 지원 환경에서 U-19, U-22, U-29 중 취약으로 판정된 항목을 대상으로 합니다. 적용 전에는 변경 계획과 영향을 확인하고 승인해야 하며, 검증되지 않은 OS·버전이나 다른 점검 항목에는 적용되지 않습니다. 실제 시스템에서는 서비스 구성에 따라 영향이 다를 수 있으므로 각 변경 내용을 신중하게 확인하세요. 현재 소스에서는 수정되지 않은 사전 릴리스 빌드도 사용할 수 있지만 `+dirty`로 표시되는 수정된 빌드에서는 실제 적용과 사용자 요청 롤백이 차단됩니다. 이전 릴리스는 동작이 다를 수 있습니다. 버전 3 저널의 사용자 요청 롤백은 기존 기록 형식을 유지하기 위해 정식 버전을 사용해야 합니다.

`--quiet`와 `--no-color`는 비대화형 출력 옵션이므로 TUI 설정에서는 표시하지 않습니다.

## CLI 실행

전체 항목을 점검하려면 `scan` 명령을 사용하세요.

```bash
sudo ./openciip-linux-amd64 scan
```

root 권한 없이 실행하면 보호된 설정과 시스템 상태를 확인하지 못할 수 있습니다. 이 경우 실행 전에 경고가 표시되며 일부 항목이 `ERROR` 또는 `UNKNOWN`으로 끝날 수 있습니다.

자주 사용하는 예시는 다음과 같습니다.

```bash
sudo ./openciip-linux-amd64 scan --profile account
sudo ./openciip-linux-amd64 scan --check U-01,U-05,U-10
sudo ./openciip-linux-amd64 scan --category file_directory --severity high
sudo ./openciip-linux-amd64 scan --evidence all --report-dir /var/lib/openciip/reports
```

## 점검 옵션

| 옵션 | 설명 |
| --- | --- |
| `--profile` | 실행할 점검 프로필을 선택합니다. |
| `--check` | `U-NN` 형식의 항목 코드를 선택합니다. |
| `--category` | `account`, `file_directory`, `service`, `patch`, `logging`으로 필터링합니다. |
| `--severity` | `high`, `medium`, `low`로 필터링합니다. |
| `--evidence` | 증적 저장 범위를 `problems`, `all`, `none` 중에서 선택합니다. |
| `--report-dir` | 보고서 저장 경로를 지정합니다. CLI에서 상대경로를 입력하면 절대경로로 변환합니다. 기본값은 현재 디렉터리 아래 `reports/`입니다. |
| `--all` | 정상 항목을 포함한 모든 결과를 표시합니다. |
| `--quiet` | 최소 결과와 보고서 경로만 표시합니다. |
| `--no-color` | 색상 출력을 사용하지 않습니다. |
| `--no-redact` | 보고서의 민감정보 마스킹을 해제합니다. |

`--no-redact`로 만든 보고서에는 민감정보가 포함될 수 있습니다. 다른 사람과 공유하지 마세요.

## 보고서

각 실행 결과는 `--report-dir`로 지정한 경로 아래에 별도 디렉터리로 저장됩니다. 기본 경로는 현재 디렉터리 아래 `reports/`를 절대경로로 변환한 값입니다.

```text
summary.txt
failures.txt
metadata.json
results.json
evidence/
```

문제가 있는 항목의 증적만 저장하는 것이 기본값입니다. 모든 증적을 저장하려면 `--evidence all`, 증적 파일을 만들지 않으려면 `--evidence none`을 사용하세요.

터미널과 TXT 보고서의 점검 결과는 `취약`, `수동 확인 필요`, `확인 실패`, `양호`, `해당 없음`, `점검하지 않음` 순서로 표시됩니다. JSON에는 각각 `FAIL`, `UNKNOWN`, `ERROR`, `PASS`, `NOT_APPLICABLE`, `SKIPPED` 상태 코드를 기록합니다. 같은 상태의 항목은 항목 번호순으로 정렬됩니다.

## 종료 코드

| 코드 | 의미 |
| ---: | --- |
| `0` | `FAIL`, `UNKNOWN`, `ERROR` 없이 완료했습니다. |
| `1` | 하나 이상의 `FAIL`이 있습니다. |
| `2` | `FAIL`이나 `ERROR` 없이 하나 이상의 `UNKNOWN`이 있습니다. |
| `3` | 점검 실행 또는 설정 해석 중 오류가 발생했습니다. |
| `4` | 명령 인자나 설정이 잘못되었습니다. |

여러 상태가 함께 있으면 `ERROR`, `FAIL`, `UNKNOWN` 순서로 종료 코드가 결정됩니다.

## 버전 확인

```bash
./openciip-linux-amd64 version
```

`--version` 플래그로도 동일한 정보를 확인할 수 있습니다.

```bash
./openciip-linux-amd64 --version
```
