# 테스트

## 기본 원칙

모든 변경은 저장소에 반영하기 전에 변경 범위에 맞는 테스트를 수행합니다.

고정된 하나의 테스트 명령만 강제하지 않습니다.

작업 완료 시 사용자에게 다음 내용을 알립니다.

- 실행한 테스트
- 테스트 환경
- 테스트 결과
- 실행하지 못한 테스트
- 추가 검증 필요 여부

## 점검 항목 테스트

새 점검 항목이나 판정 로직을 추가할 때 다음 사례를 검토합니다.

- 명확한 양호 상태
- 명확한 취약 상태
- 설정 파일 없음
- 명령어 없음
- 권한 부족
- 중복 설정
- 주석 처리된 설정
- include된 설정
- 잘못된 형식
- 배포판별 차이
- timeout
- 예상하지 못한 출력
- 비ASCII 환경
- 상태 판정 불가

## fixture

점검 파서와 판정 로직은 실제 시스템 파일을 수정하지 않고 테스트할 수 있도록 fixture를 사용합니다.

예시:

```text
testdata/ssh/pass.conf
testdata/ssh/fail.conf
testdata/ssh/include.conf
testdata/outputs/rocky-9-sshd-t.txt
```

fixture에는 실제 운영 서버의 민감정보를 포함하지 않습니다.

## 회귀 테스트

버그를 수정할 때 가능하면 먼저 해당 문제를 재현하는 테스트를 추가합니다.

오탐과 미탐 사례는 회귀 테스트로 남깁니다.

## 실제 VM 검증

배포판 지원을 추가하거나 OS별 동작을 변경할 때 실제 VM에서 검증합니다.

Docker만으로 PAM, systemd, 서비스 재시작, 실제 권한 동작을 완전히 검증했다고 가정하지 않습니다.

필요한 환경이 없으면 사용자에게 다음 정보를 포함하여 VM을 요청합니다.

- 필요한 OS와 버전
- CPU 아키텍처
- 필요한 초기 설정
- 재현 절차
- root 권한 필요 여부

## 초기 검증 환경

최초 검증 대상은 Rocky Linux 9.8입니다.

Linux 공통 또는 RHEL 9 계열 구현을 사용하더라도 Rocky Linux 9.8 이외의 배포판과 버전은 별도의 실제 VM 검증 전까지 지원 대상으로 표시하지 않습니다.

CPU 아키텍처별 지원도 각각 검증합니다. amd64에서 검증한 결과만으로 arm64 지원이 검증되었다고 표시하지 않습니다.

초기 VM 검증에서는 최소한 다음 구성을 구분합니다.

- 최소 설치와 일반 서버 설치
- systemd 서비스가 설치된 경우와 설치되지 않은 경우
- authselect 및 PAM 구성
- OpenSSH 설치 및 활성화 여부
- firewalld와 SELinux 상태 차이
- 패키지와 명령이 존재하지 않는 경우

플랫폼 검증 전환 구조는 최소한 다음 사례를 자동화하여 확인합니다.

- `platform_verification`을 Linux 공통, OS 계열 또는 `version_major` 선택자에 선언하면 loader와 schema가 거부함
- 정확한 `id`와 `version` 선택자는 허용하며 선택한 아키텍처 범위만 일치함
- 여러 선언이 일치할 때 `priority` 오름차순과 계층 `id` 순서가 입력 배열 순서와 관계없이 동일한 결과를 만듦
- `pending`은 `targeted`와 경고, `verified`는 `verified`와 빈 경고, `rejected`는 `unsupported`와 경고로 전환됨
- 정확히 일치하는 선언이 없는 OS·배포판·버전은 `unsupported`이며 탐지기 코드의 특정 배포판 지원 상태 예외에 의존하지 않음
- 내장 Rocky Linux 9.8 선언과 규칙 검증은 실제 VM 증적 전까지 계속 `pending`이며 플랫폼 지원과 규칙·조치 정의 gate가 서로를 승격하지 않음
- 아키텍처가 없는 선언은 일치하는 모든 아키텍처를 포괄하므로 amd64 또는 arm64 일부 증적만으로 `verified`가 되지 않음

## 현재 비식별 검증 기록

2026-07-11에 Rocky Linux 9.8 amd64 일반 서버 설치 한 대에서 검증했습니다. 환경은 Go 1.26.4, systemd 252, SELinux enforcing, XFS 루트 파일시스템입니다. 서버 주소, 계정, 호스트 식별자와 원본 증적은 공개 문서에 기록하지 않습니다.

검증한 실행 코드 revision은 `72bec9fe814abd446d5ce32182169b5c26d1c41b`입니다. 이 revision을 `git archive`로 생성해 VM에 전송한 추적 소스 아카이브의 SHA-256은 `47949db0a9e15271a8310dbdda283102e1c38ca7d1a99595729321bcfd243a58`이며, VM에서 다시 계산한 값과 일치했습니다. 검증 뒤 별도로 커밋하는 공개 문서는 이 실행 코드 아카이브의 범위에 포함되지 않습니다.

다음 검증은 통과했습니다.

- `go mod verify`
- `go test -count=1 ./...`
- `go test -race -count=1 ./...`
- `go vet ./...`
- `go build -trimpath -o ./openciip ./cmd/openciip`
- `GOOS=linux GOARCH=arm64 CGO_ENABLED=0` 교차 빌드(실제 arm64 VM 실행 검증은 아님)
- 대상 루트 FD와 `openat2`를 사용하는 시스템 파일 수집 회귀 테스트: authselect 절대 PAM 링크 허용, 상대·절대 루트 이탈과 `/proc` magic link 거부, 수집 중 같은 크기 파일 변경 탐지, 멱등 close
- Rocky 기본 `/etc/pam.d/system-auth`, `password-auth`, `postlogin` 절대 링크의 실제 수집과 PAM 관련 `ERROR` 0개
- 비밀번호 PAM의 정책 모듈 순서, `use_authtok` 전달, 선행·후행 writer와 `pam_unix` 도달성, `pam_faillock`의 성공·실패 분기, 외부 include/substack 숫자 jump 경계를 false PASS 없이 처리하는 회귀 테스트
- firewalld 기본 zone의 단독 런타임 조회와 `firewalld.conf` 영구 값 수집, Rocky firewalld 1.3.4에서 잘못된 `--permanent --get-default-zone` 조합을 사용하지 않음
- `openciip_mutation_test` 태그의 임시 일반 파일 metadata 최소 변경·복원 테스트(같은 inode의 mode 축소 후 원래 mode 복원)
- 읽기 전용 전체 점검: 결과 67개, 최종 `UNKNOWN` 67개, `ERROR` 0개, 종료 코드 2
- 보고서 완료 메타데이터와 결과 67개, 보고서 디렉터리 mode `0700`, 파일 mode `0600`
- account 프로필 13개 선택, 존재하지 않는 U-99 선택의 종료 코드 4
- 실제 SSH PTY에서 TUI 시작과 정상 종료
- `remediate plan`이 `pending` 플랫폼 gate에서 대상 변경 전에 거부됨

다음 검증은 아직 수행하지 않았습니다.

- 내장 대상 경로의 실제 변경
- 항목별·실행 전체 롤백의 실제 VM end-to-end 실행
- Rocky Linux 9.8 최소 설치, arm64와 서비스별 설치·활성·변형 구성
- 파일 내용·생성·삭제와 서비스 조치(현재 미구현 범위)

따라서 Rocky Linux 9.8 플랫폼, U-01~U-67의 실효 규칙 바인딩, 세 개의 내장 조치 정의는 모두 `pending`을 유지하며 공식 지원 완료 상태는 없습니다.

## 자동 조치 검증

현재 내장 조치는 기존 단일 링크 일반 파일에서 허용되지 않은 소유자 UID와 mode 비트만 같은 inode에서 최소 변경하는 `file_metadata`로 제한됩니다. 허용된 소유자·더 엄격한 mode·GID 보존도 단위·오류 주입 테스트와 별개로 Rocky Linux 9.8 실제 VM에서 확인해야 `verified`로 전환할 수 있습니다. 조치 정의를 `verified`로 전환할 때는 중복되지 않는 정규화된 검증 환경, RFC 3339 검증 시각과 하나 이상의 중복되지 않는 소문자 SHA-256 증적 digest를 함께 기록합니다. 현재 세 개의 내장 조치 정의는 모두 `pending`입니다.

- 조치 정의 검증 상태 누락·알 수 없는 상태·중복 또는 비정규 환경 거부
- `verified`의 환경·검증 시각·증적 digest 누락, 잘못된 RFC 3339와 대문자·비 SHA-256·중복 digest 거부
- `pending`·`rejected`의 검증 완료 시각과 증적 digest 거부
- loader clone에서 검증 환경·증적 목록 격리와 조치 정의 digest 반영

자동 조치 입력 보고서는 알 수 없는 JSON 필드, 중복·escape 중복 object key, 두 번째 문서, trailing 데이터, 비-16진수 규칙 세트 digest, 잘못된 증적 범위·플랫폼 지원 상태·호스트 UUID와 검증 provenance를 모두 fail-closed로 거부하는지 확인합니다.

- `O_NOFOLLOW`로 연 대상과 승인한 파일·부모 inode 일치
- `fchown` 뒤 setuid·setgid 영향을 포함한 `fchmod` 재적용
- 변경과 롤백 뒤 `fsync` 및 같은 file descriptor 재수집
- 조치 가능한 대상의 내용, inode, 부모, 링크와 SELinux context 보존 및 POSIX ACL·비-SELinux 확장 속성이 있는 대상의 사전 거부
- 다중 하드 링크, 심볼릭 링크와 외부 변경 거부
- 부작용 전 apply·rollback intent의 WAL 영속성
- `apply_intent_durable`의 완료·후행 관측·롤백 흔적 거부와 `applied/verified`의 `ObservedAfter`·`AppliedAt` 필수 검증
- 백업 파일·디렉터리 권한, digest와 재시작 후 검증
- 중단 지점별 복구 판정과 부분 metadata 전이의 안전한 롤백
- apply intent 영속화 직후 또는 non-committed 적용 실패 뒤 대상이 정확히 `Before`이면 `ObservedAfter` 무효과 증적을 남기고 `failed`/`apply_failed`/`failed`로 종결하며 rollback work·intent·attempt를 만들지 않음
- rollback intent가 있는 `failed` 작업이 정확히 `Before`이면 무효과 적용 실패가 아니라 실제 `rolled_back`으로 정합화
- durable `applied/Desired`가 승인 범위 밖에서 `Before`로 바뀐 뒤 두 번 recover해도 AppliedAt·ObservedAfter를 지워 무효과로 세탁하지 않음
- 같은 자원의 앞선 실제 writer가 이후 롤백된 뒤에도 영속 무효과 작업을 non-writer로 건너뛰어 live frontier와 rollback suffix를 오염시키지 않음
- 무효과 증적 영속화 직후 중단 시 항목 정책은 앞선 `verified` 변경을 보존한 `failed`, 실행 정책은 앞선 변경을 미해결 범위로 둔 `recovery_required`로 정합화
- 다음 변경 세트의 apply intent 전 `applying`/`verifying` 중단에서 안정된 `planned`/`verified`/`apply_failed` shape를 정책별로 `failed` 또는 `recovery_required`로 정합화
- 한 변경 세트의 실제 적용 작업과 무효과 실패 작업이 섞이면 실제 작업만 복원하고 `rolled_back` 작업 최소 1개와 attempt 범위 교차 검증
- `apply_failed`가 남은 실패 실행에서 이전 `verified` 항목 일부를 롤백하면 `completed_with_rollbacks`가 아니라 실제 롤백 증적과 원래 오류를 가진 `failed`로 종결
- stable interruption의 원래 `apply_failed` 오류를 attempt history에 보존해 롤백 실패 후 재시도 성공도 동일한 `failed` 의미 유지
- `recover_interrupted_apply` 표식과 실제 부작용 뒤 일반 apply failure를 구분해 성공 보상 롤백의 `rolled_back`/`completed_with_rollbacks` 의미 보존
- 실행 전체 롤백 정책의 recovery 미해결 범위를 일부 항목 롤백으로 축소하는 미리보기와 실행 거부
- 무효과 대상만 남은 기존 미완료 attempt는 `blocked`로 닫되 새 attempt나 `rolled_back` 상태를 만들지 않고, 이미 완료된 attempt는 불변 이력과 경고를 보존
- 무효과-only attempt 대상과 범위 밖 unsafe 상태를 분리해 attempt 성공은 금지하면서 실행의 미해결 상태는 보존
- 무효과 attempt에 rollback group/context로 포함된 순수 `planned` 대상을 중립 보존하고 stale unresolved ID는 현재 상태로 재계산
- recover 전 apply intent·ambiguous·증적 없는 apply-failed 작업의 직접 rollback preview와 preflight 거부
- `applied` 영속화 뒤 검증 전 중단된 비검증 적용분을 `recovery_required`와 미해결 범위로 전환
- 기존 rollback intent가 있는 부분 metadata 재개와 intent 없는 외부 부분 변경 거부
- durable `AppliedAt`과 기존 `ObservedAfter`가 있는 작업을 부분 metadata 상태로 바꾼 뒤 두 번 recover해도 중단된 최초 적용으로 세탁하지 않고 `recovery_required`를 유지
- Before/Desired에서 UID와 GID를 섞은 불가능한 `fchown` 소유권 조합 거부와 mode-only 부분 전이 허용
- 공유 자원 A→B writer chain에서 B 복원 뒤 A 부분 롤백 중단·재시도
- 항목 evaluator 성공 전 `verified` 금지와 실행 전체 최종 evaluator 실패 정책
- 중단된 rollback attempt 자체의 종결, 남은 작업의 새 preview 요구와 완료된 실패·부분 상태의 `crash_recovery` 감사 기록
- 서로 다른 과거 실패·차단 item attempt의 여러 변경 세트가 한 recover에서 모두 `rolled_back`으로 정합화될 때 최신 범위 밖 항목도 성공·부분 성공 attempt coverage를 얻기 전에는 정상 종료하지 않음
- 위 다중 item 복구에 범위 밖 안정된 `verified` 변경이 있어도 모든 미보강 `rolled_back`을 같은 crash-recovery attempt로 감사하고 `completed_with_rollbacks`로 종결하며 verified 항목을 전체 롤백 범위로 확대하지 않음
- 정상 종료 상태의 unresolved·중간 state·미완료 rollback attempt 거부와 item 밖 비검증 상태의 `recovery_required` 승격
- `completed+planned`, `rolled_back+verified` 등 run별 정상 종결 조합 불일치 거부
- rollback intent 없이 실패 상태 뒤 관측된 부분 metadata를 외부 변경으로 보고 `recovery_required`로 유지
- 이전 verified 항목이 있어도 다음 항목의 부작용 전 실패에는 빈 rollback attempt를 만들지 않고 실행을 `failed`로 종결
- 모델과 journal schema에서 빈 `ExpandedChangeSets` rollback attempt 거부
- 사용자 요청 rollback의 dev·unknown·modified 빌드 거부, 호환 정식 릴리스 허용과 recover의 비변경 정합화 유지
- stale preview digest, 미승인 cascade와 다른 호스트·플랫폼·빌드 거부
- 적용 전 취소 실패 재시도와 저널·백업 보존

파일 생성·내용 교체·삭제 또는 서비스 조치는 현재 검증 범위가 아니며, 해당 처리기와 전용 테스트가 구현되기 전에는 지원 기능으로 표시하지 않습니다.

## 로컬 빌드

GitHub Actions를 기본 전제로 하지 않습니다.

로컬에서 빌드와 테스트를 수행합니다.

기본 검증에는 다음 명령을 사용합니다.

- `go mod verify`
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- `go build -trimpath -o ./openciip ./cmd/openciip`

프로젝트가 안정화되면 다음 추가 도구 사용을 검토할 수 있습니다.

- `staticcheck`
- `golangci-lint`
- `govulncheck`

모든 도구를 무조건 추가하지 않습니다.
