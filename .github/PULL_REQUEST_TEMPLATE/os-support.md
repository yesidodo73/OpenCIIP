## 대상 환경

- 배포판:
- 버전:
- 아키텍처:
- 커널:
- 지원 단계: `supported` / 읽기 전용 `tested` / 자동 조치 `verified`

## 변경 내용

- [ ] `/etc/os-release` fixture를 추가했습니다.
- [ ] 공통, 계열, 정확한 환경 중 알맞은 계층에 변경을 작성했습니다.
- [ ] 정확한 환경 selector에는 `id`, `version`, `architecture`만 사용했습니다.
- [ ] 상위 계층과 실제로 다른 값만 추가했습니다.

변경 이유와 상위 계층과 다른 값을 설명해주세요.

## 실행 가능 환경 확인

- [ ] 새 정확한 환경은 `scan_support: supported`에서 시작했습니다.
- [ ] 플랫폼 탐지와 규칙 로더 테스트를 실행했습니다.

## 읽기 전용 `tested` 승격

`supported`만 추가한다면 이 절을 삭제하세요.

- 실행 명령:
- 상태별 결과:
- candidate manifest:
- final manifest: `evidence/os-support/<id>-<version>-<architecture>.json`
- `evidence_sha256`:
- `manifest_sha256`:

- [ ] U-01부터 U-67까지 67개 항목을 빠짐없이 실행했습니다.
- [ ] 고유 항목 수가 67개이고 `ERROR`가 0건입니다.
- [ ] `UNKNOWN`과 `해당 없음`의 이유를 확인했습니다.
- [ ] candidate의 `verified_at`은 비어 있고 final에는 실제 승격 시각을 기록했습니다.
- [ ] candidate와 final의 `evidence_sha256`이 같습니다.
- [ ] final의 소스, 바이너리, 규칙 묶음과 점검 산출물이 새 실행을 가리킵니다.
- [ ] platform에 자동 조치용 `platform_verification`이나 binding `verification`을 추가하지 않았습니다.
- [ ] remediation 블록이 없는 manifest를 `verify-final`과 `verify-platform`으로 확인했습니다.
- [ ] README와 점검 지원 표를 갱신했습니다.

## 자동 조치 `verified` 승격

자동 조치를 검증하지 않았다면 이 절을 삭제하세요.

- 대상 항목:
- 조치 바이너리 SHA-256:
- runner SHA-256:
- 보관 파일 SHA-256:

- [ ] platform, binding, recipe가 같은 `id`, `version`, `architecture`를 사용합니다.
- [ ] platform, binding, recipe의 environment와 `verified_at`이 같습니다.
- [ ] 점검과 자동 조치에 같은 OpenCIIP 바이너리를 사용했습니다.
- [ ] 적용 후 원래 evaluator가 `PASS`인지 확인했습니다.
- [ ] 각 항목의 롤백과 실행 전체 롤백을 확인했습니다.
- [ ] 재부팅 후 전체 롤백과 정리를 확인했습니다.
- [ ] candidate와 final의 자동 조치 주장이 같고 산출물은 새 실행에서 생성되었습니다.
- [ ] 정규화 manifest의 `evidence_sha256`을 각 recipe에 연결했습니다.
- [ ] 같은 canonical 경로의 스캔 전용 manifest를 자동 조치 포함 final manifest로 교체했습니다.
- [ ] `verify-final`과 `verify-promotion`을 모두 통과했습니다.

## 로컬 확인

```text
go test ./cmd/openciip-support-evidence ./internal/supportevidence ./internal/platform ./internal/rules ./internal/remediation/recipe ./internal/remediation/workflow
go vet ./...
go build ./cmd/openciip
```

실행하지 못했거나 추가 확인이 필요한 항목:

## 공개 자료 확인

- [ ] 비밀번호, 키, 토큰, IP 주소, 호스트 이름, 계정, VM 식별자, 로컬·원격 경로, 명령줄과 원본 설정 내용을 포함하지 않았습니다.
