# Linux 배포판 지원 추가

OpenCIIP는 Linux 공통 계층, 배포판 계열 계층, 정확한 환경 계층을 차례로 합쳐 점검합니다. 새 배포판을 추가할 때는 상위 계층과 실제로 다른 값만 작성해주세요.

지원 단계는 다음과 같이 구분합니다.

- `supported`: Linux 공통 점검을 실행할 수 있습니다.
- `tested`: 정확한 OS·버전·아키텍처에서 U-01부터 U-67까지 읽기 전용 점검을 완료했습니다.
- `pending`: 자동 조치 후보이지만 적용과 복구 검증이 끝나지 않았습니다.
- `verified`: 적용, 재점검, 항목별 롤백과 실행 전체 롤백을 모두 확인했습니다.

읽기 전용 점검의 `tested`와 자동 조치의 `verified`는 서로 다른 상태입니다. 읽기 전용 점검만 검증한 플랫폼에는 `platform_verification`이나 항목별 `verification`을 추가하지 않습니다.

## 플랫폼 계층

| 계층 | selector | 권장 priority | 용도 |
| --- | --- | --- | --- |
| Linux 공통 | `os: linux` | 100 | 여러 Linux 환경에 같은 설정 |
| 배포판 계열 | `family` | 200 | RHEL 계열, Debian 계열과 같은 공통 차이 |
| 정확한 환경 | `id`, `version`, `architecture` | 300 | 한 OS 버전과 아키텍처에서 확인한 차이 |

같은 우선순위에서는 계층 ID 순서로 적용됩니다. 서로 충돌하는 계층을 만들지 마세요. 정확한 환경의 `tested` 및 자동 조치 selector에는 `os`나 `family`를 함께 넣지 않습니다.

## 1. 실행 가능 환경 추가

1. [platform.yaml](platform.yaml)을 `rules/platforms/<배포판>-<버전>.yaml`로 복사합니다.
2. [platform-fixture.yaml](platform-fixture.yaml)을 `rules/platforms/testdata/<배포판>-<버전>-<아키텍처>.yaml`로 복사합니다.
3. `linux-common.yaml`과 기존 계열 파일을 확인하고 실제 차이가 있는 binding만 추가합니다.
4. 새 계열이 필요하면 [family-platform.yaml](family-platform.yaml)로 계열 파일을 추가합니다.
5. 정확한 환경 파일은 `scan_support: supported`로 제출합니다.

새 배포판 ID가 `rhel`, `debian`, `suse`, `alpine` 계열 매핑에 없으면 `internal/platform/detect.go`의 `detectFamily`와 fixture 테스트를 함께 수정해야 합니다.

플랫폼 YAML과 fixture는 자동으로 발견되므로 Go 소스에 파일 목록을 추가할 필요가 없습니다.

## 2. 읽기 전용 점검을 `tested`로 승격

`tested`에는 공개 가능한 candidate와 final 증적이 필요합니다. 기본 입력 예제인 [evidence-manifest.yaml](evidence-manifest.yaml)은 자동 조치 내용을 포함하지 않는 읽기 전용 예제입니다.

증적에는 정확한 플랫폼, 실행 시각, 소스 커밋, 바이너리와 규칙 묶음의 SHA-256, 67개 점검 결과, `ERROR` 0건, 실행 전후 상태 보존 여부와 보고서 보관 파일의 SHA-256을 기록합니다. 호스트를 식별할 수 있는 원본 보고서나 로그는 공개하지 않습니다.

1. candidate 플랫폼은 `scan_support: supported` 상태로 유지합니다.
2. 공개 환경 이름과 승격 주장 해시를 준비합니다.

   ```bash
   go run ./cmd/openciip-support-evidence prepare \
     --platform <candidate-platform> \
     --environment "Example Linux 1.0 amd64" \
     --output promotion-claims.json
   ```

3. candidate 바이너리로 전체 읽기 전용 점검을 실행하고 `artifact_stage: candidate`, 빈 `verified_at`, 실제 `captured_at`을 기록합니다.
4. 점검이 통과하면 final 플랫폼을 `scan_support: tested`로 바꾸고 final 바이너리를 새로 빌드합니다. 자동 조치용 verification metadata는 추가하지 않습니다.
5. final 바이너리로 전체 점검을 다시 실행하고 `artifact_stage: final`, 승격 시각인 `verified_at`, 새 `captured_at`과 새 산출물 해시를 기록합니다.
6. final manifest를 정규화하고 candidate와 final을 함께 확인합니다.

   ```bash
   go run ./cmd/openciip-support-evidence normalize \
     --input <final-manifest.yaml> \
     --output evidence/os-support/example-1.0-amd64.json

   go run ./cmd/openciip-support-evidence verify-final \
     --repository-root . \
     --candidate <candidate-manifest.json> \
     --final evidence/os-support/example-1.0-amd64.json \
     --platform rules/platforms/example-1.0.yaml \
     --source-commit <final-source-commit> \
     --binary <final-openciip-binary> \
     --rule-bundle <final-rule-bundle> \
     --scan-archive <final-scan-archive>
   ```

최종 파일만 다시 확인할 때는 다음 명령을 사용합니다.

```bash
go run ./cmd/openciip-support-evidence verify-platform \
  --repository-root . \
  --manifest evidence/os-support/example-1.0-amd64.json \
  --platform rules/platforms/example-1.0.yaml
```

`verify-platform`은 자동 조치 블록이 있는 manifest를 거부합니다. 공개 경로는 `evidence/os-support/<id>-<version>-<architecture>.json`으로 고정됩니다.

같은 플랫폼에서 자동 조치까지 `verified`로 승격하면 별도 스캔 증적 파일을 만들지 않고 이 canonical 파일을 자동 조치 포함 final manifest로 교체합니다. 이 경우 저장소 증적 검사는 플랫폼과 recipe를 함께 검증하며, 단일 파일 확인에는 `verify-platform`이 아니라 `verify-promotion`을 사용합니다.

## 3. 자동 조치를 `verified`로 승격

현재 지원 환경의 U-19, U-22, U-29는 자동 조치 검증을 완료했습니다. 새 OS나 항목의 자동 조치는 다음 조건을 모두 확인한 뒤에만 `verified`로 제출할 수 있습니다.

1. exact platform과 대상 binding, recipe가 같은 `id`, `version`, `architecture`를 사용합니다.
2. platform, binding, recipe의 environment와 `verified_at`을 일치시킵니다.
3. [remediation.yaml](remediation.yaml)에서 시작해 dry-run, 승인, 적용 후 원래 evaluator의 `PASS`, 항목별 롤백, 실행 전체 롤백, 재부팅 후 복구와 정리를 확인합니다.
4. candidate에서는 verification 상태를 `pending`으로 유지하고 다음 명령으로 해시를 준비합니다.

   ```bash
   go run ./cmd/openciip-support-evidence prepare \
     --platform <candidate-platform> \
     --recipes <candidate-recipes> \
     --environment "Example Linux 1.0 amd64" \
     --remediation \
     --output promotion-claims.json
   ```

5. candidate와 final을 각각 실행한 뒤 final manifest의 `evidence_sha256`을 각 recipe에 연결합니다.
6. 기존 스캔 전용 canonical manifest를 자동 조치 포함 final manifest로 교체하고, 실제 final 바이너리, runner, 규칙 묶음과 보관 파일을 확인합니다.

   ```bash
   go run ./cmd/openciip-support-evidence verify-final \
     --repository-root . \
     --candidate <candidate-manifest.json> \
     --final evidence/os-support/example-1.0-amd64.json \
     --platform rules/platforms/example-1.0.yaml \
     --recipes remediation/2026/unix \
     --source-commit <final-source-commit> \
     --binary <final-openciip-binary> \
     --rule-bundle <final-rule-bundle> \
     --runner <final-runner> \
     --scan-archive <final-scan-archive> \
     --item-archive <final-item-rollback-archive> \
     --reboot-archive <final-reboot-rollback-archive>

   go run ./cmd/openciip-support-evidence verify-promotion \
     --repository-root . \
     --manifest evidence/os-support/example-1.0-amd64.json \
     --platform rules/platforms/example-1.0.yaml \
     --recipes remediation/2026/unix
   ```

완료된 자동 조치 예시는 [examples/remediation-verified](examples/remediation-verified)에서 확인할 수 있습니다. 이 예제는 형식 설명용이며 현재 지원 환경을 뜻하지 않습니다.

`UNKNOWN`, `ERROR`, `SKIPPED` 결과는 자동 조치할 수 없습니다. 현재 제공하는 작업 유형은 단일 일반 파일의 내용과 복구 메타데이터를 보존하면서 소유자와 mode를 더 엄격하게 만드는 `preserve_content_file_metadata`입니다.

## 증적 해시

- `evidence_sha256`: candidate와 final에서 같아야 하는 플랫폼 및 검증 주장입니다.
- `manifest_sha256`: 한 번의 실제 실행 시각, 소스와 산출물 해시를 포함한 manifest 전체 값입니다.

정규화 도구는 필드 순서, 배열 정렬과 마지막 줄바꿈을 고정합니다. JSON Schema는 정규화된 JSON을 대상으로 사용합니다.

## 공개 전 확인

호스트 이름, IP 주소, 계정, VM 식별자, 키, 토큰, 로컬·원격 경로, 명령줄과 원본 설정 내용은 증적이나 pull request에 포함하지 마세요.

```bash
go test ./cmd/openciip-support-evidence ./internal/supportevidence ./internal/platform ./internal/rules ./internal/remediation/recipe ./internal/remediation/workflow
go vet ./...
go build ./cmd/openciip
```

실행하지 못한 검증은 pull request에 명시해주세요.
