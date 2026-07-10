# CLI와 TUI

## 우선순위

TUI 지원을 우선합니다.

CLI는 자동화, 디버깅, 특정 항목 실행을 위해 함께 유지합니다.

현재 구현된 명령 체계:

```text
openciip
openciip scan
openciip version
openciip remediate plan
openciip remediate approve RUN_ID
openciip remediate cancel RUN_ID
openciip remediate apply RUN_ID
openciip remediate status RUN_ID
openciip remediate rollback preview item RUN_ID CHANGE_SET_ID
openciip remediate rollback preview run RUN_ID
openciip remediate rollback item RUN_ID CHANGE_SET_ID
openciip remediate rollback run RUN_ID
openciip remediate recover RUN_ID
```

인자 없이 실행하면 대화형 터미널에서 TUI를 시작합니다. 비대화형 환경에서는 `openciip scan`을 사용합니다.

`remediate`는 실험적 명령군입니다. 현재 Rocky Linux 9.8 플랫폼 바인딩, U-01~U-67의 실효 규칙 바인딩, 세 개의 내장 조치 정의가 모두 `pending`이므로 조치 계획 gate를 통과할 수 없고, `dev`, `unknown`, 수정된 빌드는 적용 및 사용자 요청 롤백 gate에서 거부됩니다. 명령이 존재한다는 사실을 운영 지원 또는 VM 검증 완료로 해석하면 안 됩니다. 보고서 재조회와 조치 템플릿 명령은 아직 구현하지 않았습니다.

## 조치 CLI

조치 상태의 기본 경로는 `/var/lib/openciip/remediation`입니다. 현재 명령에는 이 경로를 바꾸는 공개 옵션이 없습니다. 계획·승인·적용은 root 권한과 같은 호스트·시스템 루트, 같은 플랫폼·규칙·조치 정의·실행 파일 identity를 요구합니다.

`remediate plan`은 완료되고 마스킹된 점검 보고서를 입력받아 시스템을 바꾸지 않는 계획과 plan digest를 출력합니다. 변경 내용·영향·위험과 함께 `<stateRoot>/<runID>/backups/<changeSet>/<generated-artifact>/{content,metadata.json}` 백업 예정 namespace, 항목별·실행 전체 롤백 가능 여부를 표시합니다. 무작위 artifact 이름과 실제 상대 경로는 적용 직전 백업을 생성한 뒤 저널에 확정합니다. `approve`는 화면에서 확인한 digest와 `--yes`를 모두 요구하고, `apply`는 별도 명령으로 실행합니다. 적용하지 않은 `planned` 또는 `approved` 실행만 `cancel --yes`로 취소할 수 있습니다.

`status`는 WAL이나 snapshot을 수정하지 않는 읽기 전용 조회입니다. 불완전한 마지막 WAL 레코드가 있으면 이를 알리지만 truncate하거나 정합화하지 않습니다. 정합화가 필요한 실행은 `recover RUN_ID --yes`로 현재 파일 상태와 대조합니다. `recover`는 마지막 불완전 WAL tail과 저널 상태만 복구하며 대상 파일을 새로 변경하지 않습니다. 적용분이 남으면 복구 출력의 범위를 확인한 뒤 새 `rollback preview item|run`, 새 preview digest와 `--yes`로 별도 롤백을 실행해야 합니다.

사용자 요청 롤백은 반드시 같은 revision에서 만든 미리보기를 먼저 확인합니다. 미리보기는 기존 lock과 WAL을 변경하지 않으며 불완전 WAL tail이 있으면 `recover --yes`를 먼저 요구합니다. 실행 명령에는 미리보기의 `--preview-digest`와 `--yes`가 필요하며, 항목 미리보기에 cascade가 표시되면 `--cascade`도 명시해야 합니다. revision이나 범위가 바뀌면 기존 digest는 거부됩니다.

사용자 요청 롤백은 정식·수정되지 않은 빌드에서만 실행합니다. 복구 가능성을 보존하기 위해 계획을 만든 바이너리와 완전히 같은 파일까지 요구하지는 않으며, 대신 현재 빌드가 해당 journal schema와 작업 종류를 해석하고 호스트·백업·자원 writer chain을 모두 검증할 수 있어야 합니다. `recover`는 대상 파일을 변경하지 않으므로 이 릴리스 gate 없이 저널 정합화에 사용할 수 있습니다.

현재 내장 조치는 기존 일반 파일에서 허용되지 않은 소유자 UID와 mode의 금지 비트만 최소 변경하는 `file_metadata` 작업으로 제한됩니다. 허용된 소유자, 더 엄격한 mode, GID, 내용과 inode는 보존하며 파일 내용·생성·삭제와 서비스 조치는 지원하지 않습니다.

## 기본 출력

기본 화면에는 문제가 발견된 항목만 표시합니다.

정상 항목 전체는 기본 화면에 출력하지 않습니다.

## 필터

현재 지원하는 필터:

- 특정 항목
- 중요도
- 카테고리

태그 기반 필터는 사용하지 않습니다.

예시:

```text
--all
--check U-01,U-02
--profile account
--severity high
--category account
--no-color
--quiet
--evidence all
--no-redact
--report-dir ./reports
```

실제로 구현되지 않은 옵션을 문서에 먼저 추가하지 않습니다.

## 종료 코드

종료 코드는 공개 호환성 형식입니다.

```text
0  점검 완료, FAIL/UNKNOWN/ERROR 없음
1  FAIL 발견
2  UNKNOWN 존재
3  점검 실행 또는 파싱 오류
4  잘못된 인자 또는 설정
```

여러 상태가 함께 존재하면 `ERROR`, `FAIL`, `UNKNOWN` 순서로 우선합니다. `NOT_APPLICABLE`과 사용자가 선택한 `SKIPPED`만으로는 실패 종료 코드를 반환하지 않습니다.

## TUI 흐름

초기 TUI는 다음 흐름을 제공합니다.

```text
점검 시작
→ 점검 실행
→ 문제 항목 목록
→ 전체 항목 전환
→ 항목 상세 보기
→ 보고서 경로 확인
```

기본 목록에는 `FAIL`, `UNKNOWN`, `ERROR`만 표시합니다. 전체 보기로 전환하면 모든 판정 상태를 표시합니다.

검증 완료 `FAIL`과 일치하는 내장 조치 정의가 있는 경우에는 다음 실험적 흐름도 제공합니다.

```text
점검 결과
→ 조치 dry-run 계획
→ plan digest 승인
→ 적용과 검증 또는 적용 전 취소
→ 상태 조회
→ 롤백 범위 미리보기
→ digest에 고정된 항목별 또는 실행 전체 롤백
```

플랫폼·규칙·조치 정의 또는 실행 빌드 gate가 충족되지 않으면 이 흐름은 실제 변경 전에 중단합니다.

## quiet 모드

quiet 모드는 다음을 숨깁니다.

- 진행 상황
- 로고
- ETA
- 일반 안내 문구

최소 결과만 출력합니다.

## ETA

- 실제 측정값을 기반으로 계산합니다.
- 초기 실행에서는 진행률만 표시할 수 있습니다.
- 이전 실행 통계가 있을 때만 ETA를 표시해도 됩니다.
- 근거 없는 고정 시간을 표시하지 않습니다.

## 병렬 실행

기본적으로 순차 실행을 우선합니다.

병렬 실행은 다음 조건을 모두 만족할 때만 허용합니다.

- 읽기 전용 점검
- 동일 파일이나 서비스에 영향을 주지 않음
- 과도한 디스크 I/O를 발생시키지 않음
- 결과 순서 보장
- timeout과 취소 처리 가능

자동 조치는 병렬로 실행하지 않습니다.

## 사용자 문구

사용자 대상 문구는 공손하고 공식적인 한국어를 사용합니다.

- 감탄사와 이모지 사용 금지
- 과장된 홍보 문구 금지
- 내부 구현 설명 금지
- 구현되지 않은 기능 표시 금지
- 오류 메시지는 원인과 다음 행동을 안내
