# 롤백 모델과 실행 저널

## 목적

이 문서는 자동 조치의 항목별 롤백과 실행 전체 롤백을 구현하기 위한 데이터 모델, 영속화, 상태 전이, 충돌 판정, 복구 알고리즘의 계약을 정의합니다.

자동 조치는 커널이나 파일 시스템이 제공하는 단일 트랜잭션이 아닙니다. OpenCIIP는 변경 전 상태를 먼저 안전하게 저장하고, 각 부작용의 의도를 write-ahead 방식으로 기록하며, 검증된 역연산을 순서대로 수행하는 보상 트랜잭션으로 원자성을 제공합니다.

현재 내장 조치의 실행 범위는 기존 일반 파일에서 허용되지 않은 소유자 UID와 mode 비트만 같은 inode에서 최소 변경하고 복원하는 `file_metadata`뿐입니다. 허용된 소유자, 더 엄격한 mode와 GID는 보존합니다. 아래 모델이 표현하는 파일 생성·삭제와 서비스 상태는 해당 처리기와 실제 VM 검증이 추가되기 전까지 지원 범위가 아닙니다. Rocky Linux 9.8 플랫폼 바인딩도 현재 `pending`이므로 이 문서는 운영 지원 완료를 뜻하지 않습니다.

이 문서에서 사용하는 표현의 의미는 다음과 같습니다.

- `반드시`: 구현이 지켜야 하는 불변 조건
- `금지`: 안전하게 자동 처리할 수 없으므로 작업을 중단해야 하는 조건
- `가능`: 플랫폼 구현이 명시적으로 지원하고 검증된 경우에만 허용하는 동작

초기 구현 대상 작업은 로컬 파일 시스템의 기존 단일 링크 일반 파일에 대한 `file_metadata` 변경뿐입니다. 심볼릭 링크, 디렉터리, 다중 하드 링크 파일, 파일 내용·생성·삭제, systemd 서비스, 특수 파일, 패키지, 사용자·그룹, 방화벽과 커널 파라미터는 전용 처리기와 실제 VM 검증이 추가되기 전까지 `UNSUPPORTED`로 판정하고 승인 전에 제외합니다.

## 핵심 불변 조건

1. 한 호스트에서는 한 번에 하나의 자동 조치 또는 롤백 실행만 허용합니다.
2. 승인된 계획의 내용과 순서는 적용 중 변경하지 않습니다. 계획이 바뀌면 기존 승인은 무효입니다.
3. 변경 세트의 모든 선행 기록과 백업이 영속 저장되기 전에는 해당 변경 세트의 첫 변경을 수행하지 않습니다.
4. 각 작업은 부작용을 수행하기 전에 작업 의도를 저널에 기록하고 디스크에 동기화합니다.
5. 파일이나 서비스의 현재 상태가 예상 상태와 다르면 이를 외부 변경으로 간주하고 덮어쓰지 않습니다.
6. 롤백은 적용 순서와 자원 의존 순서의 역순으로 수행합니다.
7. 롤백 작업은 재실행해도 같은 결과를 내는 멱등 연산이어야 합니다.
8. 백업 무결성, 저널 무결성, 대상 호스트 일치 여부를 증명하지 못하면 자동 롤백하지 않습니다.
9. 일부 자원의 복원 실패를 성공으로 축소 보고하지 않습니다.
10. 실행 중 오류 메시지와 보고서가 민감한 파일 내용이나 인증 정보를 노출하지 않도록 합니다.

## 현재 모델과 확장 방향

`internal/model/remediation.go`의 다음 타입이 현재 실행 계약의 기본 골격입니다.

- `RemediationRisk`
- `RollbackScope`
- `ResourceKind`, `ResourceRef`
- `FileSnapshot`, `ServiceSnapshot`, `ResourceSnapshot`
- `Approval`
- `ChangeSet`
- `RemediationJournal`

현재 모델은 다음 안전 정보를 분리해 기록합니다.

| 영역 | 현재 구현 |
|---|---|
| 상태 | 실행, 변경 세트와 개별 작업 상태를 각각 분리 |
| 부작용 | 작업별 apply·rollback intent, 선행·목표·관측 상태를 기록 |
| 파일 스냅샷 | 존재 여부, 파일 유형, 링크 수, 부모·inode, 내용·확장 메타데이터·SELinux fingerprint와 백업 아티팩트를 기록 |
| 자원 관계 | 정규화된 자원 키, 명시적 의존성, 작업 순서와 롤백 그룹을 기록 |
| 실행 영속성 | revision, 계획 digest, 호스트·빌드 identity, 충돌 그래프, 롤백 시도와 hash-chain WAL을 기록 |
| 오류 | 실패 단계, 자원, 오류 코드와 미해결 변경 세트를 구조화해 기록 |

기존 JSON 필드의 의미를 바꾸지 않습니다. 스키마 변경은 `schema_version`을 증가시키고, 알 수 없는 상위 버전의 저널은 자동 마이그레이션하거나 덮어쓰지 않습니다.

## 저장 구조와 권한

운영 CLI의 Linux 상태 루트는 `/var/lib/openciip/remediation`으로 고정하고 다음 구조를 사용합니다. 라이브러리 내부에서는 테스트 가능한 생성자를 유지하되, 서로 다른 공개 경로에 별도 잠금과 저널을 만드는 기능은 제공하지 않습니다.

```text
/var/lib/openciip/remediation/
├── remediation.lock
├── payloads/
│   └── <run-id>/
└── <run-id>/
    ├── journal.json
    ├── journal.wal
    ├── backups/
    │   └── <change-set-id>/
    │       └── <artifact-id>/
    │           ├── content
    │           └── metadata.json
    └── staging/
```

- 상태 루트, 실행 디렉터리, 백업 디렉터리는 `0700`으로 생성합니다.
- 저널, WAL, 백업 파일, 메타데이터 파일은 `0600`으로 생성합니다.
- 모든 파일의 소유자는 자동 조치 실행 계정이어야 하며, 초기 지원 환경에서는 `root:root`여야 합니다.
- 저널에 저장하는 백업 경로는 실행 디렉터리 기준 상대 경로여야 합니다. 절대 경로와 `..` 경로 요소는 거부합니다.
- 기존 파일을 저널, 임시 파일, 백업 대상으로 재사용하지 않습니다.
- 파일 생성과 열기에는 가능한 경우 `O_CLOEXEC`, `O_NOFOLLOW`, `O_EXCL`을 사용합니다.
- 보고서에는 저널 원문 대신 마스킹한 요약을 기록합니다. 백업 내용은 보고서에 복사하지 않습니다.

### 상태 파일 시스템 내구성 gate

`flock`, WAL과 백업의 `fsync`, 같은 디렉터리 안의 원자적 rename을 신뢰하려면 상태 루트가 로컬 영속 일반 파일 시스템임을 먼저 입증해야 합니다. Linux 구현은 denylist가 아니라 보수적인 allowlist를 사용하며, 현재 허용하는 유형은 검증된 영속 로컬 block-device graph에 마운트된 `xfs`와 `ext4`뿐입니다.

- 열린 디렉터리의 `fstatfs` filesystem magic·`fstat` device identity와 `/proc/self/mountinfo`의 실제 mount type·major:minor가 서로 일치해야 합니다.
- mount source는 `/dev` 아래에서 해석되는 block device여야 하고 해당 device의 major:minor가 mountinfo identity와 일치해야 합니다. `/sys/dev/block/<major>:<minor>`에서 backing graph를 bounded·cycle-safe 방식으로 재귀 확인하며 sysfs attribute와 slave 집합이 확인 도중 바뀌면 거부합니다. device-mapper와 MD는 slave가 하나 이상이고 모든 leaf가 허용된 NVMe·SCSI·virtio·Xen·MMC 계열 영속 로컬 장치일 때만 허용합니다. loop·zram·ramdisk·NBD·RBD·DRBD·AoE, 명백한 원격 transport와 알 수 없는 virtual leaf는 거부합니다.
- mountinfo의 filesystem root가 `/`이고 같은 underlying mount가 중복되지 않은 직접 mount만 허용합니다. bind mount, subdirectory mount, chroot 또는 판정할 수 없는 mount namespace는 거부합니다.
- NFS·CIFS 같은 네트워크 파일 시스템, `tmpfs`·ramfs 같은 휘발 파일 시스템, overlay, FUSE, proc/sysfs와 그 밖의 특수·미지원·알 수 없는 유형은 모두 거부합니다.
- 호스트의 `/`도 검증된 영속 로컬 block-device graph에 마운트된 지원 파일 시스템이어야 하며 현재 프로세스와 PID 1의 mount namespace가 같아야 합니다. 실제 디렉터리 FD로 연 현재 `/`와 `/proc/1/root`의 device/inode identity도 정확히 일치해야 하며 열기나 identity 확인이 불확실하면 chroot로 간주해 거부합니다. container marker, container cgroup, 중첩 PID namespace, isolated mount namespace, overlay root 또는 PID 1이 systemd가 아닌 실행 환경에서는 자동 조치를 시작하지 않습니다. VM 자체는 container로 취급하지 않지만 같은 파일 시스템 검증을 통과해야 합니다.
- 상태 루트가 없으면 어떤 디렉터리도 만들기 전에 가장 가까운 기존 부모의 파일 시스템을 검증합니다. 생성이 끝난 뒤 최종 상태 루트를 다시 열어 같은 검증을 반복하므로, 생성 도중 하위 mount가 나타나거나 최종 경로가 다른 파일 시스템으로 바뀐 경우에는 저널을 열지 않습니다.

파일 시스템이나 실행 환경을 안전하다고 증명하지 못하는 오류는 지원 가능한 것으로 추정하지 않습니다. 운영자는 로컬 `xfs` 또는 `ext4`의 고정 경로를 마련해야 하며, gate 우회 옵션은 제공하지 않습니다.

적용 상태의 변경 세트가 하나라도 남아 있으면 그 실행의 저널과 백업을 자동 삭제하지 않습니다. 보존 기간이 끝나 백업을 삭제하려면 사용자에게 더 이상 자동 롤백할 수 없음을 명시하고 별도 승인을 받아야 하며, 삭제 결과를 저널의 최종 메타데이터와 보고서에 남깁니다. 백업이 없는 실행을 롤백 가능하다고 표시하지 않습니다.

### 단일 실행 잠금

`remediation.lock`을 열고 배타적 비차단 잠금을 획득한 프로세스만 계획, 승인, 적용 전 취소, 적용, 롤백, 복구를 수행할 수 있습니다.

잠금 획득 실패 시 기존 프로세스의 PID만 신뢰하지 않습니다. 커널 잠금이 유지되고 있으면 즉시 중단합니다. 잠금 파일의 기록 정보는 진단용이며 잠금 소유권의 근거가 아닙니다.

읽기 전용 점검은 자동 조치 잠금과 독립적으로 실행할 수 있지만, 조치 실행에 연결된 재점검은 같은 잠금 범위에서 수행합니다.

## 원자적 저널 저장

`journal.json`은 현재 상태를 빠르게 읽기 위한 물질화된 스냅샷이고, `journal.wal`은 복구에 사용하는 권위 있는 write-ahead 기록입니다.

### revision과 무결성

모든 저널 갱신은 단조 증가하는 `revision`을 가집니다. WAL의 각 레코드는 다음 값을 포함합니다.

```go
type WALRecord struct {
    SchemaVersion  int                `json:"schema_version"`
    RunID          string             `json:"run_id"`
    Revision       uint64             `json:"revision"`
    PreviousDigest string             `json:"previous_digest,omitempty"`
    Journal        RemediationJournal `json:"journal"`
    Digest         string             `json:"digest"`
}
```

`Digest`는 `Digest` 필드를 제외한 레코드의 정규 JSON 바이트에 대한 SHA-256입니다. `PreviousDigest`는 직전 유효 레코드의 `Digest`와 같아야 합니다. 시간은 UTC RFC 3339 Nano 형식으로 직렬화합니다.

정규 JSON은 UTF-8, 불필요한 공백 없음, 구조체 스키마 순서 고정, map 키의 바이트 기준 오름차순, 배열 순서 보존, HTML 문자 임의 이스케이프 비활성화를 적용합니다. digest를 계산하는 인코더와 파일에 쓰는 인코더는 같은 바이트를 사용해야 하며, 다시 marshal하여 우연히 같은 값이 나오기를 기대하지 않습니다.

WAL은 레코드 하나를 한 줄의 JSON으로 저장합니다. 완전한 줄바꿈, JSON 파싱, digest, revision 연속성, 이전 digest 연결을 모두 만족한 레코드만 유효합니다. 비정상 종료로 마지막 줄이 일부만 기록되었으면 마지막 불완전 레코드만 버리고 그 앞의 마지막 유효 revision으로 복구합니다. 중간 레코드의 손상은 자동 복구하지 않습니다.

### 갱신 순서

저널을 갱신할 때 다음 순서를 반드시 지킵니다.

1. 메모리에서 기존 revision과 digest를 확인합니다.
2. 상태 전이와 불변 조건을 검증합니다.
3. 다음 전체 저널 상태를 포함하는 WAL 레코드를 생성합니다.
4. WAL에 레코드를 추가하고 `fsync` 또는 동등한 동기화를 수행합니다.
5. `journal.json.tmp-<random>`을 같은 디렉터리에 `0600`, 배타 모드로 생성합니다.
6. 정규 JSON을 기록하고 파일을 동기화합니다.
7. 임시 파일을 `journal.json`으로 원자적 rename 합니다.
8. 실행 디렉터리를 동기화합니다.

WAL이 영속화된 뒤 `journal.json` 갱신이 실패하면 WAL의 최신 유효 revision을 사용해 `journal.json`을 재생성할 수 있습니다. WAL보다 높은 revision의 `journal.json`은 유효하지 않습니다.

WAL 압축은 실행이 안전한 종료 상태이고, 같은 내용의 체크포인트가 영속 저장된 경우에만 허용합니다. 복구가 필요한 실행의 WAL은 자동 삭제하거나 압축하지 않습니다.

상태 루트가 있는 파일 시스템은 같은 디렉터리 안의 원자적 rename과 파일·디렉터리 동기화를 보장해야 합니다. 위 내구성 gate를 통과하지 못하면 저널·잠금·백업 저장소를 열지 않으며 자동 조치를 시작하지 않습니다.

### 백업 저장 순서

백업 아티팩트는 다음 순서로 저장합니다.

1. 예측 불가능한 새 아티팩트 디렉터리를 생성합니다.
2. 원본 내용을 스트리밍 복사하면서 SHA-256과 크기를 계산합니다.
3. 복사본과 메타데이터를 각각 동기화합니다.
4. 아티팩트 디렉터리를 동기화합니다.
5. 저장된 복사본을 다시 읽어 크기와 SHA-256을 확인합니다.
6. 검증된 아티팩트 참조를 선행 기록에 포함하여 저널을 갱신합니다.

백업 공간 부족, 짧은 쓰기, 동기화 실패, 해시 불일치 중 하나라도 발생하면 해당 변경 세트를 적용하지 않습니다.

비정상 종료로 생성됐지만 마지막 유효 WAL revision에서 참조하지 않는 백업과 staging 파일은 고아 아티팩트입니다. 고아 아티팩트는 복구 입력으로 사용하지 않으며, 유효 저널과 경로를 대조한 뒤에만 안전하게 정리합니다.

## 데이터 모델

아래 타입은 구현 계약을 설명하는 의사 코드입니다. 실제 패키지 분리는 달라질 수 있지만 필드 의미는 유지해야 합니다.

### 상태 타입

```go
type RunState string

const (
    RunPlanned                RunState = "planned"
    RunApproved               RunState = "approved"
    RunApplying               RunState = "applying"
    RunVerifying              RunState = "verifying"
    RunCompleted              RunState = "completed"
    RunRollingBack            RunState = "rolling_back"
    RunRolledBack             RunState = "rolled_back"
    RunCompletedWithRollbacks RunState = "completed_with_rollbacks"
    RunCanceling              RunState = "canceling"
    RunCanceled               RunState = "canceled"
    RunCancelFailed           RunState = "cancel_failed"
    RunFailed                 RunState = "failed"
    RunRollbackFailed         RunState = "rollback_failed"
    RunPartiallyRolledBack    RunState = "partially_rolled_back"
    RunRecoveryRequired       RunState = "recovery_required"
)

type ChangeSetState string

const (
    ChangePlanned             ChangeSetState = "planned"
    ChangePrepared            ChangeSetState = "prepared"
    ChangeApplying            ChangeSetState = "applying"
    ChangeApplied             ChangeSetState = "applied"
    ChangeVerifying           ChangeSetState = "verifying"
    ChangeVerified            ChangeSetState = "verified"
    ChangeApplyFailed         ChangeSetState = "apply_failed"
    ChangeRollingBack         ChangeSetState = "rolling_back"
    ChangeRolledBack          ChangeSetState = "rolled_back"
    ChangeRollbackBlocked     ChangeSetState = "rollback_blocked"
    ChangeRollbackFailed      ChangeSetState = "rollback_failed"
    ChangePartiallyRolledBack ChangeSetState = "partially_rolled_back"
    ChangeRecoveryRequired    ChangeSetState = "recovery_required"
)

type OperationState string

const (
    OperationPlanned               OperationState = "planned"
    OperationApplyIntentDurable    OperationState = "apply_intent_durable"
    OperationApplied               OperationState = "applied"
    OperationVerified              OperationState = "verified"
    OperationRollbackIntentDurable OperationState = "rollback_intent_durable"
    OperationRolledBack            OperationState = "rolled_back"
    OperationFailed                OperationState = "failed"
    OperationAmbiguous             OperationState = "ambiguous"
)
```

`prepared`는 변경 세트의 모든 자원에 대한 선행 스냅샷과 백업이 검증되어 영속 저장되었다는 뜻입니다. `applied`는 부작용 수행과 후행 스냅샷 저장까지 끝났지만 점검·문법·서비스 검증은 아직 끝나지 않았다는 뜻입니다. `verified`만 정상 적용 완료로 취급합니다.

`recovery_required`는 자동으로 현재 상태를 확정하거나 안전한 역연산을 선택할 수 없음을 뜻합니다. 이를 일반 `failed`로 낮추지 않습니다.

허용하는 상위 상태 전이는 다음과 같습니다. 같은 상태 안에서 하위 작업 결과만 갱신하는 전이는 허용하지만 revision은 반드시 증가해야 합니다. 표에 없는 상태 전이는 거부합니다.

| 수준 | 시작 상태 | 허용되는 다음 상태 |
|---|---|---|
| 실행 | `planned` | `approved`, `canceling`, `failed` |
| 실행 | `approved` | `applying`, `canceling`, `failed` |
| 실행 | `canceling` | `canceled`, `cancel_failed` |
| 실행 | `cancel_failed` | `canceling` |
| 실행 | `applying` | `verifying`, `rolling_back`, `failed`, `recovery_required` |
| 실행 | `verifying` | `completed`, `rolling_back`, `failed`, `recovery_required` |
| 실행 | `completed`, `completed_with_rollbacks`, `failed` | `rolling_back` |
| 실행 | `rollback_failed`, `partially_rolled_back` | `rolling_back`, 증명된 무효과 롤백 시도의 `failed` 정합화 |
| 실행 | `recovery_required` | `rolling_back`, `failed` |
| 실행 | `rolling_back` | `rolled_back`, `completed_with_rollbacks`, 증명된 무효과 롤백 시도의 `failed`, `rollback_failed`, `partially_rolled_back`, `recovery_required` |
| 변경 세트 | `planned` | `prepared`, `apply_failed` |
| 변경 세트 | `prepared` | `applying`, `apply_failed` |
| 변경 세트 | `applying` | `applied`, `apply_failed`, `rolling_back`, `recovery_required` |
| 변경 세트 | `applied` | `verifying`, `rolling_back`, `rollback_blocked`, `recovery_required` |
| 변경 세트 | `verifying` | `verified`, `rolling_back`, `recovery_required` |
| 변경 세트 | `verified` | `rolling_back`, `rollback_blocked`, `recovery_required` |
| 변경 세트 | `apply_failed` | `rolling_back` |
| 변경 세트 | `rollback_blocked`, `rollback_failed`, `partially_rolled_back` | `rolling_back`, 모든 작업이 `planned` 또는 증명된 무효과이면 `apply_failed` |
| 변경 세트 | `recovery_required` | `rolling_back`, `apply_failed` |
| 변경 세트 | `rolled_back` | `recovery_required` |
| 변경 세트 | `rolling_back` | `rolled_back`, 모든 작업이 `planned` 또는 증명된 무효과이면 `apply_failed`, `rollback_blocked`, `rollback_failed`, `partially_rolled_back`, `recovery_required` |
| 작업 | `planned` | `apply_intent_durable`, `failed` |
| 작업 | `apply_intent_durable` | `applied`, `failed`, `ambiguous`, `rollback_intent_durable` |
| 작업 | `applied` | `verified`, `rollback_intent_durable`, `ambiguous` |
| 작업 | `verified`, `failed` | `rollback_intent_durable` |
| 작업 | `ambiguous` | `applied`, `rolled_back`, `failed` |
| 작업 | `rollback_intent_durable` | `rolled_back`, `failed`, `ambiguous` |

`completed`, `rolled_back`, `completed_with_rollbacks`, `canceled`는 정상 종료 상태입니다. `canceling`은 payload 삭제 의도가 WAL에 기록된 미완료 상태이고, `cancel_failed`는 삭제를 재시도해야 하는 운영자 조치 상태입니다. `failed`는 `UnresolvedChangeSets`가 비어 있을 때만 안전한 종료 상태입니다. `rollback_failed`, `partially_rolled_back`, `recovery_required`는 프로세스 관점에서는 종료될 수 있지만 운영자 조치가 끝나지 않은 상태입니다.

정상 종료 상태와 `failed`에는 `UnresolvedChangeSets`, 미완료 롤백 시도, 변경 세트의 준비·적용·검증·롤백 중간 상태, 작업의 apply·rollback intent 또는 `ambiguous` 상태가 존재할 수 없습니다. 항목 롤백 뒤 범위 밖에 남는 변경은 변경 세트와 모든 작업이 `verified`인 경우에만 안정된 적용분으로 인정합니다. 범위 밖에 비검증 또는 중간 상태가 있으면 `completed_with_rollbacks`로 축소하지 않고 `recovery_required`와 미해결 ID를 기록합니다.

정상 종결 run과 변경 세트의 조합은 다음과 같이 제한합니다.

| run 상태 | 허용 변경 세트 상태 | 추가 조건 |
|---|---|---|
| `completed` | `verified` | 모든 변경 세트가 검증 완료 |
| `rolled_back` | `planned`, `rolled_back` | 실제 `rolled_back` 작업과 완료된 성공 rollback attempt가 각각 하나 이상 필요 |
| `completed_with_rollbacks` | `planned`, `verified`, `rolled_back` | `verified`, 실제 `rolled_back` 작업, 완료된 성공 rollback attempt가 각각 하나 이상 필요 |
| `canceled` | `planned` | 부작용·intent 없음 |
| `failed` | `planned`, `verified`, `apply_failed`, `rolled_back` | 미해결 또는 중간 상태 없음. `rolled_back`이 있으면 실제 작업과 성공 attempt 증명 필요 |

Go validator와 JSON Schema는 이 run별 조합을 동일하게 거부합니다.

정상 종결의 `apply_failed` 변경 세트에는 아직 시도하지 않은 `planned` 작업과, 영속 apply intent 뒤 정확한 무효과가 증명된 `failed` 작업만 존재할 수 있습니다. 무효과 증명은 `Before`, 백업, apply intent, 오류와 관측 스냅샷의 `captured_at`, rollback intent와 적용 완료 시각이 없다는 사실, `Before`와 fingerprint·파일 inode·부모 inode가 정확히 같은 `ObservedAfter`를 모두 요구합니다. 이 작업은 rollback work가 아니며 `rolled_back`으로 바꾸거나 새 rollback attempt에 넣지 않습니다.

`rolled_back` 변경 세트에는 하나 이상의 실제 `rolled_back` 작업이 있어야 합니다. 다중 작업 중 일부가 무효과 실패였다면 그 작업의 `failed` 증적은 그대로 보존하고 실제 적용된 작업만 복원합니다. 모든 `rolled_back` 작업에는 선행 rollback intent, `Before`와 정확히 같은 `ObservedRollback`, 완료 시각이 필요합니다. 정상 롤백 run에는 완료된 `succeeded` attempt가 하나 이상 있어야 하며, 각 `rolled_back` 변경 세트는 완료된 `succeeded` 또는 `partially_succeeded` attempt의 확장 범위에 포함되어야 합니다.

복구가 현재 rollback attempt 범위 밖의 `rolled_back` 변경 세트를 정상 상태로 취급하려면 기존 완료 attempt 이력이 그 변경 세트를 이미 포함해야 합니다. 여러 과거 실패·차단 attempt가 한 번의 `recover`에서 실제 복원 완료로 정합화되면, 최신 범위만 성공으로 보강하고 나머지를 누락하지 않습니다. 현재 crash-recovery 성공 attempt는 완료된 성공·부분 성공 이력이 없는 모든 `rolled_back` 변경 세트를 감사 범위에 함께 포함하며, 이 coverage가 확보된 뒤에만 정상 종료합니다. 항목 롤백 범위 밖의 안정된 `verified` 변경은 이 감사 보강 때문에 실행 전체 롤백 대상으로 확대하지 않습니다.

`apply_failed` 변경 세트가 남은 실패 실행에서 이전 `verified` 항목 일부를 사용자가 롤백해도 실행을 `completed_with_rollbacks`로 승격하지 않습니다. 실제 롤백 증적과 원래 적용 실패 오류를 보존한 `failed`로 유지합니다. `completed_with_rollbacks`는 범위 밖 변경 세트가 모두 안정된 `verified`이고 별도의 `apply_failed`가 없을 때만 사용합니다.

안정된 apply 중단의 원래 `apply_failed` 오류는 이후 모든 rollback attempt의 오류 이력에도 복사합니다. 첫 롤백이 실패해 run 오류와 변경 세트 상태가 `rollback_failed`로 바뀌어도 재시도 분류는 immutable attempt history에서 원래 실패 결과를 복원하므로, 재시도 횟수가 최종 run 의미를 `failed`에서 `rolled_back`으로 바꾸지 않습니다.

이 영속 결과 표식은 `recover_interrupted_apply` phase로 구분합니다. 실제 부작용이 발생한 일반 apply 실패가 검증된 롤백으로 모두 복원된 경우까지 무조건 `failed`로 고정하지 않으며, 해당 경우에는 실제 롤백 범위에 따라 `rolled_back` 또는 `completed_with_rollbacks`를 사용할 수 있습니다.

현재 항목이 부작용 전에 실패하고 항목 정책으로 되돌릴 작업이 없으면 빈 성공 rollback attempt를 만들지 않습니다. 앞선 `verified` 변경은 보존하고 현재 항목은 `apply_failed`, 이후 항목은 `planned`로 둔 채 실행을 `failed`로 종결합니다. `completed_with_rollbacks`는 확장 범위가 비어 있지 않은 실제 성공 롤백 뒤에만 기록합니다.

모든 rollback attempt의 `ExpandedChangeSets`에는 하나 이상의 실제 변경 세트가 있어야 하며 Go 모델과 JSON Schema가 빈 범위를 모두 거부합니다.

`ambiguous`에서의 전이는 복구 절차가 현재 상태를 다시 수집하여 `Before` 또는 후행 상태와 일치함을 증명한 경우에만 허용합니다. 운영자가 상태 문자열만 강제로 바꾸는 기능은 제공하지 않습니다.

### 자원 참조와 정규 키

```go
type ResourceRef struct {
    Kind ResourceKind `json:"kind"`
    ID   string       `json:"id"`
}

type CanonicalResource struct {
    Reference ResourceRef `json:"reference"`
    Key       string      `json:"key"`
    AliasKeys []string    `json:"alias_keys,omitempty"`
}
```

- 파일 ID는 정리된 절대 경로여야 하며 NUL과 상위 경로 이탈을 거부합니다.
- 파일 작업은 기본적으로 마지막 심볼릭 링크를 따라가지 않습니다. 링크 자체를 바꿀지 링크 대상 파일을 바꿀지 계획에 명시해야 합니다.
- 파일의 기본 키는 `file:<absolute-path>`입니다.
- 기존 파일은 `inode:<device>:<inode>`를 별칭 키로 추가하여 하드 링크 충돌을 검출합니다.
- 서비스 이름은 systemd가 정규화한 완전한 unit 이름을 사용하며 기본 키는 `service:<unit-name>`입니다.
- 같은 별칭 키를 공유하는 자원은 같은 자원으로 취급합니다.

### 파일 스냅샷과 백업

```go
type FileSnapshot struct {
    Path              string    `json:"path"`
    Exists            bool      `json:"exists"`
    FileType          string    `json:"file_type"`
    Mode              uint32    `json:"mode"`
    UID               int       `json:"uid"`
    GID               int       `json:"gid"`
    Size              int64     `json:"size"`
    SHA256            string    `json:"sha256,omitempty"`
    LinkTarget        string    `json:"link_target,omitempty"`
    Device            uint64    `json:"device"`
    Inode             uint64    `json:"inode"`
    NLink             uint64    `json:"nlink"`
    ParentDevice      uint64    `json:"parent_device"`
    ParentInode       uint64    `json:"parent_inode"`
    XAttrDigest       string    `json:"xattr_digest,omitempty"`
    ACLDigest         string    `json:"acl_digest,omitempty"`
    SELinuxContext    string    `json:"selinux_context,omitempty"`
    MetadataDigest    string    `json:"metadata_digest,omitempty"`
    CapturedAt        time.Time `json:"captured_at"`
}

type BackupArtifact struct {
    ID             string `json:"id"`
    ContentPath    string `json:"content_path,omitempty"`
    MetadataPath   string `json:"metadata_path"`
    ContentSize    int64  `json:"content_size"`
    ContentSHA256  string `json:"content_sha256,omitempty"`
    MetadataSHA256 string `json:"metadata_sha256"`
    Durable        bool   `json:"durable"`
}
```

일반 파일의 `SHA256`은 원본 바이트 전체에 대해 계산하며 필수입니다. 심볼릭 링크는 링크 문자열을, 디렉터리는 복원 대상 메타데이터를 해시합니다. 모델은 파일이 없는 `Exists=false` 선행 상태도 표현할 수 있지만, 현재 처리기는 존재하는 단일 링크 일반 파일의 `file_metadata`만 허용합니다.

UID와 GID의 `0`, 빈 파일의 크기 `0`은 유효한 값이므로 핵심 메타데이터 필드에 `omitempty`를 사용하지 않습니다. `Exists=false`일 때만 나머지 필드의 0값을 비존재 상태로 해석합니다.

`Mode`는 권한 비트뿐 아니라 setuid, setgid, sticky bit를 보존할 수 있어야 합니다. 복원 시 `chown`이 특수 권한 비트를 지울 수 있으므로 소유자·그룹을 먼저 적용하고 권한을 나중에 적용합니다.

ACL, 확장 속성, SELinux 컨텍스트를 자동으로 복원할 수 없는 플랫폼에서는 해당 메타데이터가 존재하는 파일의 내용 교체를 지원한다고 표시하지 않습니다. 미래의 내용 변경 처리기는 실제 값을 `metadata.json`에 저장하고 저널에는 무결성 확인값만 두어야 합니다.

현재 내장 조치 정의는 파일 내용을 바꾸지 않는 `file_metadata` 작업만 생성합니다. POSIX ACL 또는 SELinux context 이외의 확장 속성이 있는 파일은 계획 전에 거부합니다. 적용과 복원은 승인된 inode를 한 번 열어 같은 파일 descriptor에서 `fchown`, `fchmod`, `fsync`, 재수집을 수행합니다. 경로를 다시 열어 이름이 같은 다른 inode를 변경하지 않습니다. 비정상 종료의 부분 상태는 내용, inode, 부모, 링크와 SELinux identity가 기존 스냅샷과 같고, 단일 `fchown` 경계인 `(UID,GID)` 쌍 전체가 Before 또는 Desired 중 하나이며, 별도 `fchmod` 경계인 mode가 Before 또는 Desired 중 하나일 때만 안전한 metadata 전이로 판정합니다. 서로 다른 전·후 상태에서 UID와 GID를 섞은 소유권은 외부 변경으로 간주합니다. 그 밖의 상태는 `recovery_required`입니다.

미래에 내용을 교체하는 파일 처리기를 추가하더라도 `NLink`가 2 이상이면 일반 rename 기반 교체가 하드 링크 관계를 끊을 수 있으므로 전용 하드 링크 처리기 없이는 `UNSUPPORTED`로 중단해야 합니다. 현재 권한과 소유권 변경도 안전 범위를 단순화하기 위해 `NLink == 1`인 일반 파일만 같은 inode에서 처리합니다.

미래의 일반 파일 내용 복원 처리기는 대상과 같은 디렉터리에 안전한 임시 파일을 생성하고, 내용 기록, 동기화, 소유자·그룹, 권한, ACL·확장 속성·SELinux 컨텍스트, 재동기화, 원자적 rename, 부모 디렉터리 동기화 순서로 수행해야 합니다. 현재는 내용 복원과 특수 파일 교체를 지원하지 않습니다.

파일 생성·삭제 처리기를 추가할 경우 선행 상태가 `Exists=false`인 파일의 롤백은 현재 파일이 해당 작업의 검증된 후행 fingerprint와 일치할 때만 unlink하고 부모 디렉터리를 동기화해야 합니다. 선행 상태가 존재하고 후행 상태에서 삭제된 파일은 검증된 백업으로 새 임시 파일을 만든 뒤 원자적으로 복원해야 합니다. 이 작업들은 현재 지원하지 않습니다.

### 서비스 스냅샷

다음 서비스 모델과 롤백 원칙은 서비스 처리기를 추가할 때 적용할 계약이며 현재 실행 가능한 조치 범위가 아닙니다.

```go
type ServiceSnapshot struct {
    Manager          string    `json:"manager"`
    Name             string    `json:"name"`
    LoadState        string    `json:"load_state"`
    ActiveState      string    `json:"active_state"`
    SubState         string    `json:"sub_state"`
    UnitFileState    string    `json:"unit_file_state"`
    Masked           bool      `json:"masked"`
    NeedDaemonReload bool      `json:"need_daemon_reload"`
    ManagerBootID    string    `json:"manager_boot_id"`
    CapturedAt       time.Time `json:"captured_at"`
}
```

서비스 스냅샷은 영구 활성화 상태와 현재 런타임 상태를 분리합니다. PID, CPU 시간처럼 자연스럽게 변하는 값은 동등성 판정에 사용하지 않습니다.

서비스 롤백은 다음 원칙을 지킵니다.

- 원래 비활성이었던 서비스를 임의로 시작하지 않습니다.
- 원래 활성 상태였던 서비스를 복원 과정에서 중지했다면 설정 복원과 `daemon-reload` 이후 다시 시작하고 정상 상태를 검증합니다.
- `masked`, `enabled`, `disabled`, `static`, `indirect` 등의 unit-file 상태를 단순 boolean으로 축소하지 않습니다.
- 부팅이 바뀌어 `ManagerBootID`가 다르면 과거 런타임 상태를 자동 복원하지 않습니다. 영구 상태는 별도로 검증할 수 있지만 런타임 복원은 수동 확인 대상으로 둡니다.
- reload, restart, start, stop은 서로 대체 가능한 역연산으로 가정하지 않습니다. 각 조치 계획에 검증된 롤백 작업을 명시합니다.

### 자원 스냅샷

```go
type ResourceSnapshot struct {
    Reference   CanonicalResource `json:"reference"`
    Fingerprint string            `json:"fingerprint"`
    File        *FileSnapshot     `json:"file,omitempty"`
    Service     *ServiceSnapshot  `json:"service,omitempty"`
}
```

`Fingerprint`는 자동 비교에 사용하는 안정 필드의 정규 표현에 대한 SHA-256입니다. 포인터, 캡처 시각, PID처럼 비결정적인 값은 포함하지 않습니다. 자원 종류와 스냅샷 포인터는 정확히 하나만 일치해야 합니다.

### 개별 작업

```go
type OperationKind string

type RecoveryMode string

const (
    RecoveryStateInferable     RecoveryMode = "state_inferable"
    RecoveryRollbackReplaySafe RecoveryMode = "rollback_replay_safe"
    RecoveryManual             RecoveryMode = "manual"
)

const (
    OperationFileCreate       OperationKind = "file_create"
    OperationFileRemove       OperationKind = "file_remove"
    OperationFileMetadata     OperationKind = "file_metadata"
    OperationServiceEnable    OperationKind = "service_enable"
    OperationServiceDisable   OperationKind = "service_disable"
    OperationServiceMask      OperationKind = "service_mask"
    OperationServiceUnmask    OperationKind = "service_unmask"
    OperationServiceStart     OperationKind = "service_start"
    OperationServiceStop      OperationKind = "service_stop"
    OperationServiceReload    OperationKind = "service_reload"
    OperationServiceRestart   OperationKind = "service_restart"
    OperationDaemonReload     OperationKind = "daemon_reload"
)

type OperationRecord struct {
    ID             string             `json:"id"`
    Sequence       int                `json:"sequence"`
    RollbackSequence int              `json:"rollback_sequence"`
    Kind           OperationKind      `json:"kind"`
    RecoveryMode   RecoveryMode       `json:"recovery_mode"`
    State          OperationState     `json:"state"`
    Resource       CanonicalResource  `json:"resource"`
    ExpectedBefore ResourceSnapshot   `json:"expected_before"`
    Before         ResourceSnapshot   `json:"before"`
    Desired        ResourceSnapshot   `json:"desired"`
    ObservedAfter  *ResourceSnapshot  `json:"observed_after,omitempty"`
    ObservedRollback *ResourceSnapshot `json:"observed_rollback,omitempty"`
    Backup         *BackupArtifact    `json:"backup,omitempty"`
    ApplyIntentAt  *time.Time         `json:"apply_intent_at,omitempty"`
    AppliedAt      *time.Time         `json:"applied_at,omitempty"`
    RollbackIntentAt *time.Time       `json:"rollback_intent_at,omitempty"`
    RolledBackAt   *time.Time         `json:"rolled_back_at,omitempty"`
    Error          *JournalError      `json:"error,omitempty"`
}
```

`ExpectedBefore`는 승인 화면에 표시한 현재 상태이고 승인된 계획 해시에 포함되는 불변 적용 전제 조건입니다. 준비 단계에서 다시 수집한 `Before`의 fingerprint와 파일·부모 inode가 이 값과 다르면 기존 승인을 폐기합니다. `Desired`는 적용 전에 계산된 목표 상태이고 승인된 계획 해시에 포함됩니다. `ObservedAfter`는 apply 시도 뒤 다시 수집한 실제 상태입니다. 성공 작업에서는 `Desired` 증적이고, rollback intent가 없는 `failed` 작업에서는 정확히 `Before`인 무효과 증적입니다. `ObservedRollback`은 롤백 직후 다시 수집한 실제 상태이며, 같은 자원을 수정한 이전 작업을 이어서 롤백할 때 정확한 전제 조건으로 사용합니다. 현재 `file_metadata`의 적용·검증 성공은 fingerprint와 파일·부모 inode가 `Desired`와 정확히 일치해야 하고, 롤백 완료는 같은 기준으로 `Before`와 정확히 일치해야 합니다.

`apply_intent_durable` 작업에는 적용 완료 시각, 후행 관측 또는 롤백 흔적이 존재할 수 없습니다. `applied`와 `verified` 작업은 `ObservedAfter`와 0이 아닌 `AppliedAt`을 함께 가져야 합니다. 이 시간·관측 불변식은 Go 검증기와 journal schema에서 동일하게 강제합니다.

`state_inferable`은 현재 스냅샷으로 부작용 발생 여부를 판정할 수 있는 작업입니다. restart, reload, daemon-reload처럼 전후 안정 상태가 같을 수 있는 작업은 `rollback_replay_safe` 또는 `manual`이어야 합니다. `rollback_replay_safe`는 순방향 재실행을 허용한다는 뜻이 아니라, 비정상 종료 후 검증된 롤백 보상 작업만 다시 수행할 수 있다는 뜻입니다.

### 변경 세트

```go
type ChangeSet struct {
    ID             string             `json:"id"`
    RuleID         string             `json:"rule_id"`
    RuleIdentity   RemediationRuleIdentity `json:"rule_identity"`
    RecipeIdentity RemediationRecipeIdentity `json:"recipe_identity"`
    Sequence       int                `json:"sequence"`
    Risk           RemediationRisk    `json:"risk"`
    State          ChangeSetState     `json:"state"`
    RollbackGroup  string             `json:"rollback_group,omitempty"`
    DependsOn      []string           `json:"depends_on,omitempty"`
    Resources      []CanonicalResource `json:"resources"`
    Before         []ResourceSnapshot `json:"before"`
    After          []ResourceSnapshot `json:"after,omitempty"`
    Operations     []OperationRecord  `json:"operations"`
    DryRun         string             `json:"dry_run"`
    ExpectedImpact string             `json:"expected_impact"`
    Approval       *Approval          `json:"approval,omitempty"`
    PreparedAt     *time.Time         `json:"prepared_at,omitempty"`
    AppliedAt      *time.Time         `json:"applied_at,omitempty"`
    VerifiedAt     *time.Time         `json:"verified_at,omitempty"`
    RolledBackAt   *time.Time         `json:"rolled_back_at,omitempty"`
    Error          *JournalError      `json:"error,omitempty"`
}
```

하나의 점검 항목 조치는 하나의 변경 세트입니다. `RuleIdentity`에는 현재 내장 규칙에서 해석한 title, category, severity, evaluator, verification, binding source, reference를 저장하고, `RecipeIdentity`에는 recipe ID, 전체 platform selector와 canonical recipe 정의 SHA-256을 저장합니다. 조치 recipe selector는 정확한 배포판 `id`와 `version`을 필수로 하며 범위형 `version_major`는 허용하지 않습니다. 두 identity는 계획 해시에 포함하며 승인·적용 직전에 현재 내장 데이터와 정확히 다시 비교합니다. 변경 세트 안의 모든 선행 상태와 백업을 먼저 저장한 뒤 작업을 `Sequence` 오름차순으로 적용합니다. 롤백은 `RollbackSequence` 오름차순으로 수행합니다.

단순 파일 작업은 역순 보상을 기본값으로 생성할 수 있지만 이를 모든 변경 세트에 강제하지 않습니다. 설정 파일 복원, `daemon-reload`, 서비스 상태 복원처럼 안전한 보상 순서가 적용 순서의 단순 역순이 아닌 경우가 있으므로 각 작업에 검증된 롤백 순서를 명시합니다. 두 순서는 변경 세트 안에서 각각 중복될 수 없으며 계획 해시에 포함합니다.

예를 들어 systemd unit 또는 drop-in을 바꾸고 서비스를 재시작하는 변경 세트의 롤백은 파일 복원, `daemon-reload`, 원래 런타임 상태 복원 순서여야 합니다. 적용 순서를 기계적으로 뒤집어 새 설정 상태에서 서비스를 먼저 재시작하지 않습니다.

`ChangeSet.Before`는 각 고유 자원의 변경 세트 시작 시점 상태이고 `ChangeSet.After`는 변경 세트 전체 검증 뒤의 최종 상태입니다. `OperationRecord.Before`, `Desired`, `ObservedAfter`는 작업 사이의 중간 상태를 기록합니다. 준비 단계에서 다시 수집한 `Before`의 fingerprint는 `ExpectedBefore`와 같아야 하며, 같은 자원의 다음 작업 `Before`는 직전 작업의 `Desired`와 같아야 합니다.

같은 변경 세트에서 한 파일의 내용을 여러 번 교체하는 계획은 하나의 최종 원자적 교체 작업으로 합칩니다. 중간 바이트를 별도 아티팩트로 보존하지 않은 반복 내용 교체는 롤백 가능하다고 판정하지 않습니다.

같은 변경 세트에 속한 일부 작업만 사용자 요청으로 롤백하지 않습니다. 변경 세트가 롤백의 최소 논리 단위입니다.

기존 `Approval`에는 승인한 계획을 고정하기 위한 `PlanDigest`를 추가합니다.

```go
type Approval struct {
    Source     string    `json:"source"`
    TemplateID string    `json:"template_id,omitempty"`
    PlanDigest string    `json:"plan_digest"`
    ApprovedAt time.Time `json:"approved_at"`
}
```

`ChangeSet.Before`, `ChangeSet.After`와 작업별 스냅샷이 같은 자원의 서로 다른 단계임을 명확히 검증합니다. 변경 세트의 최초 `Before`는 그 자원의 첫 작업 `Before`와 같고, 최종 `After`는 마지막 작업 `ObservedAfter`와 같아야 합니다.

### 충돌 그래프

```go
type ConflictReason string

const (
    ConflictSharedResource    ConflictReason = "shared_resource"
    ConflictExplicitDependency ConflictReason = "explicit_dependency"
    ConflictRollbackGroup     ConflictReason = "rollback_group"
)

type ConflictEdge struct {
    From      string         `json:"from"`
    To        string         `json:"to"`
    Reason    ConflictReason `json:"reason"`
    Resources []string       `json:"resources,omitempty"`
}

type ConflictGraph struct {
    Nodes []string       `json:"nodes"`
    Edges []ConflictEdge `json:"edges"`
}
```

간선 `A -> B`는 B의 적용 또는 유효성이 A의 적용 결과에 의존하므로 B를 먼저 롤백해야 A를 안전하게 롤백할 수 있다는 뜻입니다.

그래프는 승인 전에 다음 절차로 생성합니다.

1. 변경 세트를 적용 `Sequence` 순서로 정렬합니다.
2. 각 자원 키와 별칭 키별로 마지막 작성자를 기억합니다.
3. 같은 키의 이전 작성자 A와 현재 작성자 B 사이에 `A -> B` 공유 자원 간선을 추가합니다.
4. `DependsOn`의 각 선행 항목에서 현재 항목으로 명시적 의존 간선을 추가합니다.
5. 같은 `RollbackGroup`에 속한 변경 세트는 롤백 시 하나의 결합 노드로 취급합니다.
6. 그룹을 축약한 그래프에 순환이 있으면 계획 오류로 중단합니다.

그래프, 자원 키, 적용 순서는 계획 해시에 포함합니다. 승인 후 그래프가 달라지면 다시 dry-run과 승인을 받아야 합니다.

### 롤백 시도와 오류

```go
type RollbackTrigger string

const (
    RollbackUserRequest      RollbackTrigger = "user_request"
    RollbackApplyFailure     RollbackTrigger = "apply_failure"
    RollbackVerifyFailure    RollbackTrigger = "verification_failure"
    RollbackCrashRecovery    RollbackTrigger = "crash_recovery"
)

type RollbackOutcome string

const (
    RollbackSucceeded RollbackOutcome = "succeeded"
    RollbackPartial   RollbackOutcome = "partially_succeeded"
    RollbackFailed    RollbackOutcome = "failed"
    RollbackBlocked   RollbackOutcome = "blocked"
)

type RollbackAttempt struct {
    ID                 string          `json:"id"`
    Scope              RollbackScope   `json:"scope"`
    Trigger            RollbackTrigger `json:"trigger"`
    RequestedChangeSets []string       `json:"requested_change_sets,omitempty"`
    ExpandedChangeSets  []string       `json:"expanded_change_sets"`
    CascadeApproved     bool           `json:"cascade_approved"`
    Outcome             RollbackOutcome `json:"outcome,omitempty"`
    StartedAt           time.Time       `json:"started_at"`
    CompletedAt         *time.Time      `json:"completed_at,omitempty"`
    Errors              []JournalError  `json:"errors,omitempty"`
}

type JournalError struct {
    Code       string       `json:"code"`
    Phase      string       `json:"phase"`
    ChangeSetID string      `json:"change_set_id,omitempty"`
    OperationID string      `json:"operation_id,omitempty"`
    Resource   *ResourceRef `json:"resource,omitempty"`
    Message    string       `json:"message"`
    Retryable  bool         `json:"retryable"`
    OccurredAt time.Time    `json:"occurred_at"`
}
```

최소 오류 코드는 다음을 포함합니다.

```text
journal_corrupt
journal_revision_conflict
unsupported_schema
host_mismatch
boot_changed
lock_unavailable
backup_missing
backup_hash_mismatch
precondition_failed
external_change_detected
unsupported_resource
apply_failed
verification_failed
rollback_dependency_conflict
rollback_failed
service_state_unavailable
persist_failed
cancel_failed
recovery_ambiguous
```

### 실행 저널

```go
type FailurePolicy string

const (
    FailureRollbackItem FailurePolicy = "rollback_item"
    FailureRollbackRun  FailurePolicy = "rollback_run"
)

type HostIdentity struct {
    MachineIDHash string `json:"machine_id_hash"`
    SystemRoot    string `json:"system_root"`
    RootDevice    uint64 `json:"root_device"`
    RootInode     uint64 `json:"root_inode"`
    BootID        string `json:"boot_id"`
}

type RemediationJournal struct {
    SchemaVersion       int               `json:"schema_version"`
    Revision            uint64            `json:"revision"`
    RunID               string            `json:"run_id"`
    ScanRunID           string            `json:"scan_run_id"`
    ScanToolVersion     string            `json:"scan_tool_version"`
    ScanToolCommit      string            `json:"scan_tool_commit"`
    RuleSetVersion      string            `json:"rule_set_version"`
    Platform            PlatformInfo      `json:"platform"`
    RemediationBuild    RemediationBuildIdentity `json:"remediation_build"`
    State               RunState          `json:"state"`
    FailurePolicy       FailurePolicy     `json:"failure_policy"`
    PlanDigest          string            `json:"plan_digest"`
    Host                HostIdentity      `json:"host"`
    StartedAt           time.Time         `json:"started_at"`
    UpdatedAt           time.Time         `json:"updated_at"`
    ChangeSets          []ChangeSet       `json:"change_sets"`
    ConflictGraph       ConflictGraph     `json:"conflict_graph"`
    RollbackAttempts    []RollbackAttempt `json:"rollback_attempts,omitempty"`
    UnresolvedChangeSets []string         `json:"unresolved_change_sets,omitempty"`
    Warnings            []string          `json:"warnings,omitempty"`
    Error               *JournalError     `json:"error,omitempty"`
}
```

`MachineIDHash`는 원본 machine-id의 SHA-256이며 원문을 저장하지 않습니다. 시스템 루트의 device/inode와 함께 저널이 다른 호스트 또는 다른 오프라인 루트에 적용되는 것을 방지합니다. `BootID` 변경은 파일 롤백을 막지는 않지만 서비스 런타임 상태 자동 복원을 제한합니다.

`ScanToolVersion`과 `ScanToolCommit`은 입력 보고서를 만든 도구 identity입니다. `RemediationBuild`는 계획을 만든 현재 조치 실행 파일의 version, commit, modified 여부, 안정적으로 열린 실행 파일의 SHA-256을 별도로 저장합니다. `Platform`은 감사용 전체 플랫폼 정보를 보존합니다. 호환성 gate는 hostname, 표시 이름, kernel warning처럼 무관한 변동값이 아니라 공통 identity helper로 OS, family, ID, version, architecture, verified support를 정확히 비교하며, 권한은 별도로 현재 root인지 확인합니다. 적용은 dev, unknown 또는 modified 빌드에서 거부합니다.

사용자 요청 롤백도 dev, unknown 또는 modified 빌드에서 거부합니다. 단, 원본 바이너리의 결함을 수정한 정식 릴리스로 복구할 수 있어야 하므로 `RemediationBuild`의 완전 일치를 요구하지 않습니다. 현재 코드가 journal `schema_version`과 기록된 작업 종류를 지원하고, 동일 호스트·필요한 boot identity·백업 무결성·자원 writer chain을 모두 검증할 때만 복원합니다. `recover`는 대상 자원을 변경하지 않으므로 이 릴리스 gate와 분리합니다.

`FailurePolicy`는 dry-run에 표시하고 승인된 계획에 포함합니다. 변경 세트 내부 실패는 정책과 관계없이 해당 변경 세트를 먼저 원상 복원합니다. `rollback_run`이면 그 뒤 이미 검증된 앞선 변경 세트도 전체 역순으로 롤백합니다.

실패 정책을 암묵적으로 선택하지 않습니다. 계획에 `rollback_item` 또는 `rollback_run`이 명시되지 않았으면 승인을 받을 수 없습니다.

## 계획과 승인

계획 단계에서는 실제 변경을 수행하지 않습니다.

1. 조치 가능한 `FAIL` 결과와 검증된 플랫폼 처리기만 선택합니다.
2. 변경 세트, 작업 순서, 목표 스냅샷, 자원 키를 생성합니다.
3. 중복 ID, 중복 순서, 지원하지 않는 자원, 잘못된 경로를 거부합니다.
4. 공유 자원 충돌 그래프를 생성하고 순환 여부를 확인합니다.
5. dry-run, 영향, 위험도, 실패 정책, 롤백 범위와 제약을 생성합니다.
6. 실행 저널을 `planned`로 원자 저장합니다.
7. 다음 항목을 정규화하여 `PlanDigest`를 계산합니다.
   - 변경 세트와 작업 ID, 적용 순서, 롤백 순서
   - 작업 종류, 복구 모드, 목표 상태
   - 승인 화면에 표시한 현재 상태 fingerprint와 적용 전제 조건
   - 정규 자원 키와 충돌 그래프
   - 위험도와 실패 정책
   - scan run ID와 scan 도구 version/commit, 규칙 버전, exact platform, remediation build identity, 호스트 식별자
   - 각 변경 세트의 resolved rule provenance와 recipe ID/selector identity
8. 사용자 또는 템플릿 승인을 정확한 `PlanDigest`에 결합해 기록합니다.

`PlanDigest`에는 계획 이후 채워지는 `Before`, `ObservedAfter`, `ObservedRollback`, 백업 경로, 상태, revision, 실행 시각, 오류를 포함하지 않습니다. 승인 시점의 현재 상태인 `ExpectedBefore`는 반드시 포함합니다. 반대로 사용자가 승인한 변경 내용과 범위를 바꿀 수 있는 필드는 반드시 포함합니다.

승인 뒤 현재 상태 재확인에서 dry-run에 표시한 현재값, 영향, 목표 또는 작업이 달라지면 기존 승인을 폐기하고 새 계획을 생성합니다. 단순히 저널의 `PlanDigest`를 갱신해 기존 승인을 재사용하지 않습니다.

## 선행 기록

선행 기록은 변경 직전 상태를 복원하기 위해 필요한 모든 정보의 집합입니다. 각 변경 세트에는 다음 항목이 빠짐없이 있어야 합니다.

- 정규화된 자원 참조와 별칭 키
- 변경 세트 적용 직전의 `ResourceSnapshot`
- 내용 또는 메타데이터가 바뀌는 자원의 검증된 `BackupArtifact`
- 작업별 `Desired` 상태와 검증 비교 모드
- 파일 소유자, 그룹, 전체 모드, 내용 해시, 링크 대상, 관리 대상 ACL·확장 속성·SELinux 정보
- 서비스의 unit-file 상태, mask 상태, 런타임 active/sub 상태, systemd manager boot ID
- 선행 기록을 수집한 시각과 그 기록이 영속화된 journal revision

선행 기록은 scan 결과를 그대로 재사용하지 않습니다. scan 이후 상태가 바뀔 수 있으므로 각 변경 세트를 적용하기 직전에 다시 수집합니다. 선행 기록과 백업을 모두 검증한 revision이 WAL에 영속화된 상태만 `prepared`로 인정합니다.

## 변경 세트 준비와 적용 알고리즘

여러 변경 세트가 같은 자원을 수정할 수 있으므로 모든 실행 시작 시점의 원본을 한 번만 백업해서는 안 됩니다. 각 변경 세트의 `Before`는 바로 앞 변경 세트가 끝난 뒤, 해당 변경 세트를 적용하기 직전의 상태여야 합니다. 그래야 전체 롤백에서 B의 선행 상태를 복원한 다음 A의 선행 상태를 복원하는 연쇄가 성립합니다.

### 준비

각 변경 세트에 대해 다음 절차를 수행합니다.

1. 현재 호스트와 저널의 호스트 식별자가 일치하는지 확인합니다.
2. 모든 대상 자원을 `lstat` 또는 처리기별 안전한 방식으로 다시 수집합니다.
3. 이전 변경 세트의 예상 결과와 현재 상태가 다르면 외부 변경으로 중단합니다.
4. 변경 세트의 모든 자원에 대한 선행 스냅샷을 수집합니다.
5. 필요한 모든 내용과 메타데이터 백업을 생성하고 무결성을 재검증합니다.
6. 선행 스냅샷과 백업 아티팩트를 저널에 기록합니다.
7. 변경 세트를 `prepared`로 전이하고 영속화합니다.

하나라도 실패하면 첫 작업을 수행하지 않습니다.

### 적용

각 작업은 다음 절차를 따릅니다.

1. 현재 상태가 작업의 `Before`와 같은지 다시 비교합니다.
2. 작업 상태를 `apply_intent_durable`로 전이하고 저널을 영속화합니다.
3. 처리기의 적용 연산을 한 번 수행합니다.
4. 적용 연산의 반환 오류 여부와 관계없이 대상 자원을 다시 수집합니다.
5. 현재 상태가 `Desired`와 같으면 `ObservedAfter`를 저장하고 작업을 `applied`로 전이합니다. 적용 연산이 오류를 반환했다면 부작용은 발생한 것으로 기록한 뒤 변경 세트 내부 롤백을 시작합니다.
6. 현재 상태가 `Before`와 같으면 부작용이 발생하지 않은 적용 실패로 기록합니다.
7. 현재 상태가 `Before`와 `Desired` 어느 쪽과도 같지 않으면 부분 부작용 또는 외부 변경을 구분할 수 없으므로 작업과 변경 세트를 `recovery_required`로 전이합니다.

명령이 오류를 반환했다는 사실만으로 부작용이 없었다고 가정하지 않습니다. 반대로 명령이 성공을 반환해도 실제 자원이 목표 상태와 같지 않으면 성공으로 기록하지 않습니다.

모든 작업이 적용되면 변경 세트를 `applied`, 이어서 `verifying`으로 전이합니다. 자원 후행 상태와 원래 점검 evaluator의 `PASS`가 모두 성공해야 변경 세트와 작업을 같은 revision에서 `verified`로 전이합니다. 전체 항목 적용 뒤에는 공유 자원의 마지막 작성자 상태와 전체 대상 evaluator를 다시 검사합니다. 특정 실패 항목을 확정할 수 있는 evaluator 실패는 승인된 failure policy를 따르고, 실패 대상을 특정할 수 없는 실행 전체 자원 검증 실패는 실행 전체를 안전하게 롤백합니다.

변경 세트 검증이 성공한 revision에서 적용된 모든 작업도 `verified`로 전이합니다. 작업은 `verified`인데 변경 세트는 `verifying`인 식의 절반짜리 완료 상태를 별도 revision으로 만들지 않습니다.

적용 실패 시 이미 적용된 작업을 `RollbackSequence` 순서로 롤백합니다. 변경 세트 내부 롤백이 완전히 성공하면 변경 세트는 `rolled_back`이 되고 실행 실패에는 해결되지 않은 변경이 없다고 기록합니다. 내부 롤백이 일부라도 실패하면 `partially_rolled_back` 또는 `recovery_required`로 전이합니다.

## 항목별 롤백 가능 조건

항목별 롤백은 다음 조건을 모두 만족해야 합니다.

1. 저널의 스키마, WAL digest 연결, 최신 revision이 유효합니다.
2. 저널이 현재 호스트와 시스템 루트에 속합니다.
3. 정상 사용자 롤백에서는 대상 변경 세트가 `applied` 또는 `verified`이며 아직 롤백되지 않았습니다. 비정상 종료 뒤 재시도에서는 `recover`가 현재 상태를 확정한 `applying`, `verifying`, `rolling_back`, `apply_failed`, `rollback_failed`, `partially_rolled_back`, `recovery_required`도 영속 `Before`, 검증된 백업과 안전한 rollback work가 있을 때만 허용합니다.
4. 대상 변경 세트의 모든 작업에 지원되는 자원 처리기와 검증된 롤백 연산이 있습니다.
5. 필요한 백업 아티팩트가 존재하고 크기와 SHA-256이 일치합니다.
6. 같은 롤백 그룹의 모든 활성 변경 세트를 함께 선택했습니다.
7. 대상의 활성 후속 의존 변경 세트가 없습니다. 있으면 단독 롤백을 금지합니다.
8. 각 대상 자원의 현재 상태가 그 자원의 마지막 활성 작성자가 기록한 후행 상태와 같습니다.
9. 처리 중인 다른 조치나 복구 실행이 없습니다.
10. 서비스 런타임 상태 복원이 필요하면 systemd manager boot ID가 일치합니다.

후속 변경 세트가 있으면 두 선택만 허용합니다.

- 항목별 롤백을 거부하고 충돌 항목과 자원을 사용자에게 보여줍니다.
- 사용자가 cascade를 명시적으로 승인하면 대상의 모든 활성 후손과 같은 롤백 그룹을 폐쇄 집합에 포함합니다.

후속 변경을 보존하기 위해 선행 변경만 제거한 뒤 후속 변경을 재적용하는 rebase 방식은 초기 구현에서 허용하지 않습니다.

### 항목별 롤백 절차

1. 배타 잠금을 획득하고 최신 저널을 다시 읽습니다.
2. 대상과 cascade 폐쇄 집합을 계산합니다.
3. 전체 폐쇄 집합에 대해 백업, 호스트, 부팅, 현재 상태, 처리기 지원 여부를 사전 검증합니다.
4. 검증 중 하나라도 실패하면 실제 복원을 시작하지 않고 `blocked` 시도를 기록합니다. 외부 변경, 백업 손상, 저널 불일치처럼 복구가 필요한 원인은 blocked attempt, 실행의 `rolling_back`, 대상의 복구 상태, 오류와 미해결 범위를 같은 WAL revision에 기록한 뒤 `recovery_required`로 닫습니다.
5. 새 `RollbackAttempt`를 만들고 실행을 `rolling_back`으로 영속화합니다.
6. 충돌 그래프의 역위상 순서로 변경 세트를 선택하고, 같은 순위에서는 큰 적용 순서를 먼저 처리합니다.
7. 각 변경 세트의 적용된 작업을 `RollbackSequence` 오름차순으로 복원합니다.
8. 복원 후 현재 상태가 `Before`와 같은지 다시 수집해 확인합니다.
9. 모든 대상이 성공하면 시도를 `succeeded`로 종료합니다.
10. 범위 밖에 남은 활성 변경 세트와 작업이 모두 `verified`이면 실행은 `completed_with_rollbacks`, 남아 있지 않으면 `rolled_back`으로 전이합니다. 범위 안팎에 준비·적용·검증·롤백 중간 상태 또는 미해결 부작용이 있으면 `recovery_required`가 우선합니다.

## 실행 전체 롤백

정상 실행 전체 롤백 대상은 `applied` 또는 `verified` 상태이고 아직 롤백되지 않은 모든 변경 세트입니다. 비정상 종료 뒤에는 `recover`가 확정한 rollback work가 있는 실패·중간 상태도 대상에 포함합니다. 이미 정상 롤백된 변경 세트는 자원 writer chain 검증 문맥에는 포함하되 실제 복원은 멱등하게 건너뜁니다.

전체 롤백 전에 모든 대상에 대해 백업 무결성과 현재 상태를 검사합니다. 외부 변경이 확인된 자원을 무조건 원본으로 덮어쓰지 않습니다. 사전 검사에서 모호한 상태가 발견되면 실제 롤백을 시작하지 않고 `recovery_required`로 전이합니다.

롤백 순서는 충돌 그래프의 역위상 순서이며, 의존성이 없는 노드끼리는 적용 `Sequence` 내림차순입니다. 자동 조치는 병렬로 롤백하지 않습니다.

변경 세트 B의 롤백에 실패했고 간선 `A -> B`가 있다면 B가 여전히 A의 결과에 의존할 수 있으므로 A를 롤백해서는 안 됩니다. 다음 절차를 따릅니다.

1. 실패한 변경 세트와 실패 원인을 기록합니다.
2. 충돌 그래프에서 실패 노드의 아직 처리하지 않은 모든 선행 노드를 `rollback_blocked`로 표시합니다.
3. 실패 노드와 의존 관계가 없는 나머지 분기는 계속 복원합니다.
4. 같은 롤백 그룹의 실패는 그룹 전체 실패로 취급합니다.
5. 완료 뒤 해결되지 않은 변경 세트 ID를 `UnresolvedChangeSets`에 기록합니다.

모든 대상이 검증된 선행 상태로 복원되면 `rolled_back`입니다. 하나 이상 복원되고 하나 이상 실패 또는 차단되면 `partially_rolled_back`입니다. 복원을 전혀 시작하지 못했거나 첫 복원부터 모두 실패했지만 현재 상태가 확정되어 있으면 `rollback_failed`입니다. 현재 상태 자체가 모호하거나 저널·백업의 신뢰성을 확인할 수 없으면 다른 상태보다 `recovery_required`가 우선합니다.

## 외부 변경과 비교 규칙

배타 잠금은 다른 OpenCIIP 프로세스만 막습니다. 관리자, 패키지 관리자, 서비스 관리 도구 등 외부 주체의 변경은 계속 가능하므로 각 부작용 직전과 롤백 직전에 비교 후 교체 방식으로 확인합니다.

- 적용 직전 현재 상태는 기록된 `Before`와 같아야 합니다.
- 롤백 직전 현재 상태는 해당 자원의 마지막 활성 작성자가 기록한 `ObservedAfter`와 같아야 합니다.
- 이미 복원된 후속 writer가 있으면 그 `ObservedRollback`을 바로 앞 writer의 영속 `ObservedAfter`와 연결해 연속 suffix를 검증합니다. live 상태를 이미 복원된 후속 writer의 after와 직접 비교하지 않습니다.
- `Before`와 `ObservedAfter` 사이의 부분 metadata 상태는 해당 작업의 rollback intent가 이번 요청 전에 이미 WAL에 영속화된 중단 복구에서만 허용합니다. 새 intent를 기록한 직후 발견된 부분 상태는 외부 변경으로 처리합니다.
- 파일 내용, 유형, 소유자, 그룹, 권한, 링크 대상, 관리 대상 메타데이터 중 하나라도 다르면 외부 변경입니다.
- 서비스는 load, active, sub, unit-file, mask 상태 중 해당 작업이 관리하는 필드를 비교합니다.
- 외부 변경이 있으면 자동으로 병합하거나 덮어쓰지 않습니다.

inode는 교체 작업에서 정상적으로 바뀔 수 있으므로 내용 동등성에 항상 포함하지 않습니다. 다만 작업 직전 부모 디렉터리와 대상 inode가 스냅샷 수집 이후 바뀌었는지 확인하여 TOCTOU 공격과 경로 교체를 탐지합니다.

## 비정상 종료 복구

프로그램 시작 또는 조치 명령 시작 시 비종료 상태의 저널을 탐색합니다. 미완료 실행이 있으면 새 자동 조치를 막고 실행 ID, 마지막 확정 단계, 해결되지 않은 자원, 권장 복구 명령을 표시합니다. 읽기 전용 점검은 계속 허용할 수 있습니다.

복구 절차는 다음과 같습니다.

1. 배타 잠금을 획득합니다.
2. WAL을 검증하고 마지막 유효 revision으로 저널을 복원합니다.
3. 호스트와 시스템 루트 식별자를 검증합니다.
4. 모든 백업 아티팩트의 존재와 해시를 검증합니다.
5. 비종료 작업의 현재 자원 상태를 수집합니다.
6. 아래 판정표로 실제 부작용 발생 여부를 결정합니다.
7. 모호한 작업이 없으면 정합화된 assessment와 자동 롤백 가능 여부를 출력합니다. `recover`는 live 자원을 변경하지 않으며, 확인된 적용분의 복원은 새 rollback preview, 현재 revision의 digest와 별도 사용자 승인을 거쳐 실행합니다.

| 마지막 영속 상태 | 현재 상태가 `Before` | 현재 상태가 `Desired` 또는 `ObservedAfter` | 둘 다 아님 |
|---|---|---|---|
| `apply_intent_durable` | 적용되지 않은 것으로 확정 | 완료·후행 관측·rollback intent가 없는 `state_inferable` 작업만 적용된 것으로 확정하고 후행 스냅샷 보완 | 기본은 `recovery_required`; 같은 미완료 작업의 원자적 부분 metadata 전이만 적용된 롤백 후보로 확정 |
| `applied` 또는 `verified` | 승인된 rollback attempt 범위가 있고 전체 `Before`와 정확히 같으면 롤백 완료로 감사 기록, 아니면 외부 롤백 또는 기록 불일치로 수동 확인 | 적용된 상태로 확정 | `recovery_required` |
| `rollback_intent_durable` | 롤백 성공으로 확정 | 롤백 미수행으로 확정하고 재시도 가능 | `recovery_required` |

`apply_intent_durable` 또는 rollback intent가 없는 `ambiguous`·`failed` 작업이 정확히 `Before`이면 실제 부작용이 없었던 작업으로 정합화합니다. 정확한 현재 스냅샷을 `ObservedAfter`에 무효과 증적으로 영속화하고 작업은 `failed`, 변경 세트는 `apply_failed`, 적용 중이던 실행은 `failed`로 종결합니다. 이 증명이 있는 작업은 rollback work에서 제외하며 rollback intent, rollback attempt 또는 `ObservedRollback`을 새로 만들지 않습니다. 반대로 기존 rollback intent가 있는 `failed` 작업이 정확히 `Before`이면 중단된 실제 롤백의 완료로 정합화합니다. `rolled_back`은 기존의 영속 rollback intent나 승인된 rollback attempt 범위가 실제 복원을 증명하는 경우에만 기록합니다.

무효과 전환은 `AppliedAt`이 없고 기존 `ObservedAfter`가 없거나 이미 정확한 `Before`인 순방향 미확정 작업에만 허용합니다. 한 번 `applied`와 `Desired` 관측을 영속화한 작업이 승인 범위 밖에서 `Before`로 바뀌어 `ambiguous`가 된 경우에는 다음 `recover`에서도 그 이력을 지우거나 무효과로 낮추지 않습니다.

현재 상태가 `Desired`이거나 원본 inode에서 `Before`와 `Desired`의 원자적 metadata 단계만 섞인 경우 이를 중단된 순방향 적용으로 추론하는 것은 durable apply intent와 백업은 있지만 `AppliedAt`, `ObservedAfter`, rollback intent가 한 번도 기록되지 않은 `state_inferable` 작업에만 허용합니다. 이미 적용 완료 시각이나 후행 관측이 있는 작업이 나중에 다른 목표·부분 상태로 바뀌면, 두 번째 `recover`에서도 최초 적용 중단으로 재해석하지 않고 `recovery_required`를 유지합니다.

한 번 영속화된 무효과 작업은 자원 writer가 아닙니다. 후속 복구에서는 live frontier와 다시 비교하거나 `logicalCurrent`를 소비하지 않고 `NotApplied`로 건너뛰며, 같은 자원의 앞선 실제 writer와 롤백 suffix 검증을 방해하지 않습니다.

무효과 증적을 기록한 직후 실패 정책 처리 전에 다시 중단되어도 항목 롤백 정책은 앞선 `verified` 변경을 그대로 보존하고 실행을 `failed`로 닫습니다. 실행 전체 롤백 정책에서 앞선 `verified` 변경이 남아 있으면 이를 미해결 롤백 범위로 기록한 `recovery_required`로 전환하며, `recover`가 직접 복원하지 않고 새 rollback preview와 승인을 요구합니다.

같은 정책은 더 이른 중단에도 적용합니다. 실행이 `applying` 또는 `verifying`이지만 모든 변경 세트가 안정된 `planned`, `verified`, 안전한 `apply_failed`뿐이면 비검증 활성 부작용은 없습니다. 항목 정책은 앞선 `verified`를 보존한 `failed`로 닫고, 실행 전체 정책만 남은 `verified`를 미해결 롤백 범위로 전환합니다.

실행 전체 롤백 정책으로 생성된 이 미해결 범위를 항목 롤백으로 축소할 수 없습니다. 항목 closure가 모든 미해결 ID를 포함하지 않으면 미리보기와 실행을 모두 거부하고 실행 전체 롤백을 요구합니다.

`Before`와 `Desired`가 모두 현재 상태와 일치하는 작업은 상태 비교만으로 수행 여부를 판정할 수 없습니다. `state_inferable` 작업에서 이런 계획은 유효하지 않습니다. `rollback_replay_safe` 작업은 순방향 성공으로 확정하지 않고, 관련 자원의 상태를 원복한 뒤 계획된 보상 작업만 재실행할 수 있습니다. `manual` 작업은 `recovery_required`로 남깁니다.

서비스 상태를 읽을 수 없거나 부팅 ID가 달라 런타임 상태 비교가 불가능하면 `recovery_required`입니다.

비정상 종료 후 순방향 적용을 자동 재개하지 않습니다. 사용자가 새 dry-run을 확인하고 명시적으로 재개하는 별도 기능을 구현하기 전까지 복구의 기본 방향은 확정된 적용분의 안전한 롤백입니다.

작업이 `applied`까지 영속화됐지만 변경 세트 검증 전에 중단된 경우처럼 비검증 적용분이 남으면 실행을 `recovery_required`로 전환하고 해당 변경 세트를 미해결 범위로 기록합니다. `recover`는 이를 순방향으로 완료하거나 직접 복원하지 않으며 새 rollback preview와 승인을 요구합니다.

`apply_intent_durable`, `ambiguous`, 또는 rollback intent도 무효과 증적도 없는 `failed` 작업은 롤백 미리보기와 사전 검사에서 거부하고 먼저 `recover`를 요구합니다. 따라서 현재 상태가 우연히 `Before`라는 이유만으로 사용자 롤백이 새 rollback intent와 성공 기록을 만들 수 없습니다.

롤백 중 다시 비정상 종료되면 `rollback_intent_durable` 상태와 현재 자원 비교로 완료·미완료·모호 상태를 확정합니다. 중단된 attempt는 현재 결과에 따라 그 attempt 자체를 성공·부분 성공·실패로 닫고, rollback work가 남으면 새 미리보기와 승인을 요구합니다. 이미 완료된 실패·부분 attempt나 별도 attempt 표식 없이 복원이 정확히 끝난 운영자 조치 상태를 사후 확정할 때는 새 `crash_recovery` attempt를 기록해 감사 이력을 보존합니다.

기존 롤백 시도의 모든 대상이 `planned` 또는 증명된 무효과 실패이고 실제 `rolled_back` 작업이 하나도 없으면 새 crash-recovery attempt를 만들지 않습니다. 미완료 attempt만 `blocked`로 닫고 대상 변경 세트를 `apply_failed`, 실행을 `failed`로 정합화합니다. 이미 완료된 attempt는 이력을 변경하지 않고 무효과 정합화 경고를 남깁니다.

이 판정은 attempt 대상 범위와 실행 전체 종결 가능성을 분리합니다. 대상이 전부 무효과여도 범위 밖에 적용 중·복구 필요 상태가 있거나 실행 전체 정책상 남은 `verified` 변경을 복원해야 하면 attempt는 성공으로 만들지 않되 실행은 미해결 ID를 가진 운영자 조치 상태로 유지합니다.

롤백 그룹이나 writer 문맥 때문에 attempt 범위에 포함된 순수 `planned` 변경 세트는 무효과 대상과 함께 중립 범위로 인정하되 그대로 `planned`로 보존합니다. 기존 미해결 ID는 무조건 이월하지 않고 복구 시점의 현재 변경 세트 상태와 failure policy로 다시 계산합니다.

부분 metadata 재개는 중단 전에 존재했던 rollback intent가 있을 때만 가능합니다. 후속 writer가 이미 복원된 공유 자원에서는 그 writer들의 `ObservedRollback -> 이전 writer ObservedAfter` 체인을 먼저 검증하고, 활성 frontier의 부분 상태는 해당 frontier의 영속 after를 anchor로 검사합니다.

## 부분 실패 상태와 보고

실행 결과는 적용 오류와 복원 결과를 분리해 보고합니다.

| 상태 | 의미 | 자동 변경 추가 허용 |
|---|---|---|
| `failed` | 현재 실패 항목에는 미해결 부작용이 없으며, 항목 정책에서는 앞선 `verified` 변경이 보존될 수 있음 | 새 계획을 만든 뒤 가능 |
| `rollback_failed` | 롤백 대상이 남아 있고 실패 지점과 현재 상태는 확정됨 | 금지, 재시도 또는 수동 조치 필요 |
| `partially_rolled_back` | 일부는 복원됐고 일부는 실패·차단되어 남음 | 금지, 재시도 또는 수동 조치 필요 |
| `recovery_required` | 현재 상태, 저널 또는 백업을 신뢰성 있게 확정할 수 없음 | 금지, 수동 확인 필요 |

보고서에는 다음 내용을 반드시 포함합니다.

- 실행 ID, scan run ID, 계획 digest, failure policy
- 요청한 롤백 범위와 cascade 확장 범위
- 변경 세트별 적용·검증·롤백 상태
- 자원별 선행·후행 fingerprint와 백업 경로 및 해시
- 실패·차단된 자원과 기계 판독 가능한 오류 코드
- 복원이 계속된 독립 분기와 중단된 의존 분기
- 해결되지 않은 변경 세트와 다음 수동 확인 절차

민감한 파일 내용과 백업 내용은 보고서에 포함하지 않습니다.

## Go 인터페이스 계약

### 저널 저장소

```go
type JournalStore interface {
    Root() string
    Create(ctx context.Context, journal *model.RemediationJournal) error
    Load(ctx context.Context, runID string) (*model.RemediationJournal, error)
    Inspect(ctx context.Context, runID string) (journal.Inspection, error)
    ListRecoverable(ctx context.Context) ([]model.RemediationJournal, error)

    // Update는 expectedRevision이 최신 revision과 같을 때만 한 번 갱신합니다.
    // mutate가 성공한 뒤 WAL fsync와 journal.json 원자 교체까지 끝나야 반환합니다.
    Update(
        ctx context.Context,
        runID string,
        expectedRevision uint64,
        mutate func(*model.RemediationJournal) error,
    ) (*model.RemediationJournal, error)
}

// 새 상태 루트를 만들 수 있는 계획·실행 경로에서 사용합니다.
func Acquire(ctx context.Context, stateRoot string) (*Handle, error)

// 이미 초기화된 상태 루트만 잠그며 새 lock 파일을 만들지 않습니다.
func AcquireExisting(ctx context.Context, stateRoot string) (*Handle, error)

func (h *Handle) Path() string
func (h *Handle) Release() error
func (h *Handle) Close() error
```

revision 불일치는 덮어쓰기 재시도가 아니라 최신 상태를 다시 읽고 상태 전이를 재평가해야 하는 동시성 오류입니다.

프로덕션 workflow가 호출하는 `NewWithStore`는 내구성 검증을 거친 구체 `*journal.Store`만 받습니다. 임의 `JournalStore` 주입 경로는 오케스트레이터 패키지 내부 테스트 seam으로만 두며 다른 패키지에서 실제 파일 부작용에 사용할 수 없습니다.

### 백업 저장소

```go
type BackupSource struct {
    Resource model.CanonicalResource
    Snapshot model.ResourceSnapshot
    Content  io.ReadCloser
    Metadata []byte
}

type BackupStore interface {
    Put(
        ctx context.Context,
        runID string,
        changeSetID string,
        source BackupSource,
    ) (model.BackupArtifact, error)

    Verify(ctx context.Context, runID string, artifact model.BackupArtifact) error
    OpenContent(ctx context.Context, runID string, artifact model.BackupArtifact) (io.ReadCloser, error)
    ReadMetadata(ctx context.Context, runID string, artifact model.BackupArtifact) ([]byte, error)
}
```

`BackupSource.Content`는 내용 백업이 필요 없으면 nil일 수 있습니다. `Put`은 전달받은 스트림의 소유권을 넘겨받아 성공·실패와 관계없이 닫습니다. 백업 저장소가 경로를 다시 열어 스냅샷과 다른 inode를 복사하지 않도록 자원 처리기가 검증된 파일 descriptor 기반 스트림을 제공합니다.

### 자원 처리기

```go
type CompareMode string

const (
    CompareApplyPrecondition    CompareMode = "apply_precondition"
    CompareApplyResult          CompareMode = "apply_result"
    CompareRollbackPrecondition CompareMode = "rollback_precondition"
    CompareRollbackResult       CompareMode = "rollback_result"
)

type ResourceHandler interface {
    Kind() model.ResourceKind
    Normalize(ctx context.Context, ref model.ResourceRef) (model.CanonicalResource, error)
    Capture(ctx context.Context, resource model.CanonicalResource) (model.ResourceSnapshot, error)
    BackupRequired(operation model.OperationRecord) bool
    OpenBackup(
        ctx context.Context,
        resource model.CanonicalResource,
        snapshot model.ResourceSnapshot,
    ) (BackupSource, error)

    Equivalent(
        expected model.ResourceSnapshot,
        observed model.ResourceSnapshot,
        mode CompareMode,
    ) (bool, string)

    Apply(ctx context.Context, operation model.OperationRecord) error
    Rollback(
        ctx context.Context,
        operation model.OperationRecord,
        artifact *model.BackupArtifact,
    ) error
}
```

처리기는 임의 셸 문자열을 받지 않습니다. 실행 파일과 인자를 분리한 검증된 명령 또는 안전한 시스템 호출만 사용합니다.

### 충돌 그래프

```go
type ConflictPlanner interface {
    Build(changeSets []model.ChangeSet) (model.ConflictGraph, error)

    ItemRollbackClosure(
        graph model.ConflictGraph,
        target string,
        active map[string]bool,
        cascade bool,
    ) ([]string, error)

    ReverseRollbackOrder(
        graph model.ConflictGraph,
        targets []string,
        sequences map[string]int,
    ) ([]string, error)

    BlockedPredecessors(
        graph model.ConflictGraph,
        failed string,
        pending map[string]bool,
    ) []string
}
```

### 조치와 복구 오케스트레이터

```go
type PlanRequest struct {
    RunID            string
    ScanRunID        string
    ScanToolVersion  string
    ScanToolCommit   string
    RuleSetVersion   string
    Platform         model.PlatformInfo
    RemediationBuild model.RemediationBuildIdentity
    FailurePolicy    model.FailurePolicy
    Host             model.HostIdentity
    ChangeSets       []model.ChangeSet
}

type FileContentSource interface {
    Content(ctx context.Context, runID, changeSetID, operationID string) ([]byte, error)
}

type RunContentDeleter interface {
    DeleteRunContent(ctx context.Context, runID string) error
}

type RollbackPreview struct {
    RunID               string
    Revision            uint64
    Scope               model.RollbackScope
    RequestedChangeSets []string
    ExpandedChangeSets  []string
    ExecutionOrder      []string
    CascadeRequired     bool
    PreviewDigest       string
}

type ApplyGuard func(
    ctx context.Context,
    journal *model.RemediationJournal,
) error

type ApplyVerifier func(
    ctx context.Context,
    journal *model.RemediationJournal,
    changeSetIDs []string,
) (failedChangeSets []string, err error)

type RemediationManager interface {
    Plan(ctx context.Context, request PlanRequest) (*model.RemediationJournal, error)
    Approve(ctx context.Context, runID string, approval model.Approval) error
    Cancel(ctx context.Context, runID string) error
    ApplyWithVerifier(
        ctx context.Context,
        runID string,
        guard ApplyGuard,
        verifier ApplyVerifier,
    ) error

    PreviewRollbackItem(
        ctx context.Context,
        runID string,
        changeSetID string,
    ) (RollbackPreview, error)

    PreviewRollbackRun(
        ctx context.Context,
        runID string,
    ) (RollbackPreview, error)

    RollbackItem(
        ctx context.Context,
        runID string,
        changeSetID string,
        cascadeApproved bool,
        previewDigest string,
    ) (model.RollbackAttempt, error)

    RollbackRun(ctx context.Context, runID string, previewDigest string) (model.RollbackAttempt, error)
    Recover(ctx context.Context, runID string) (RecoveryAssessment, error)
}

type RecoveryAssessment struct {
    RunID               string
    LastValidRevision   uint64
    ConfirmedApplied    []string
    ConfirmedRolledBack []string
    NotApplied          []string
    Ambiguous           []string
    AutomaticRollbackPossible bool
    Reasons             []string
}
```

`RunID`가 비어 있으면 관리자가 충돌하기 어려운 새 ID를 생성합니다. 미래의 정규 파일 내용 교체 작업은 민감정보를 저널에 평문으로 넣지 않고 `FileContentSource`에서 읽으며, 반환 바이트의 크기와 SHA-256이 승인된 `Desired`와 다르면 intent 기록 전에 적용을 중단합니다. 현재의 metadata-only Plan/Apply와 상태 조회·적용분 복구·롤백은 content source 없이 동작하며, 실제 내용 교체 작업이 포함된 경우에만 content source를 요구합니다.

상태 조회용 `OpenStatus`는 기존 state root만 검증하고 `LoadReadOnly`/`Inspect`로 WAL을 읽습니다. 불완전한 마지막 WAL 레코드를 보고할 수는 있지만 truncate나 snapshot reconcile을 수행하지 않습니다. `OpenRecovery`도 기존 state root만 열고 platform, rules, recipe 초기화 없이 host/file rollback을 사용할 수 있어야 합니다. payload 저장소를 안전하게 열 수 있으면 cancel 복구용 deleter를 선택적으로 연결하고, payload가 손상됐으면 일반 파일 rollback/recovery는 계속 허용하되 cancel 복구는 삭제 실패를 보고하고 `cancel_failed`를 유지해야 합니다. 명시적인 `OpenCancellation`은 payload 저장소를 열 수 없으면 취소를 시작하지 않습니다.

`PreviewRollbackItem`과 `PreviewRollbackRun`은 저널을 바꾸지 않고 현재 revision의 요청 항목, 활성 대상, cascade 폐쇄 집합, 검증 문맥, 역순 실행 순서와 canonical digest를 반환합니다. 항목·전체 실행 롤백은 cascade 여부와 관계없이 실행 시점에 같은 revision과 범위로 digest를 다시 계산해 constant-time 비교하며, 하나라도 달라졌으면 부작용 없이 새 preview를 요구합니다. 항목 preview가 cascade 필요로 판정되면 별도의 cascade 승인도 함께 전달해야 합니다.

`Cancel`은 apply가 시작되지 않은 `planned` 또는 `approved` 실행만 `canceling`으로 먼저 기록한 뒤 `payloads/<runID>`만 원자적인 tombstone으로 격리·동기화·삭제합니다. 저널과 백업은 보존합니다. 삭제 실패는 `cancel_failed`와 오류를 남기며 `canceled`로 축소하지 않습니다.

### 작업 실행 의사 코드

```go
func applyOperation(ctx context.Context, runID string, opID string) error {
    journal, err := store.Load(ctx, runID)
    if err != nil {
        return err
    }
    op := journal.Operation(opID)

    current, err := handler.Capture(ctx, op.Resource)
    if err != nil {
        return recordRecoveryRequired(journal, opID, err)
    }
    if ok, reason := handler.Equivalent(op.Before, current, CompareApplyPrecondition); !ok {
        return recordPreconditionFailure(journal, opID, reason)
    }

    journal, err = store.Update(ctx, runID, journal.Revision, func(j *model.RemediationJournal) error {
        j.Operation(opID).State = OperationApplyIntentDurable
        return validateTransition(j)
    })
    if err != nil {
        return err
    }

    applyErr := handler.Apply(ctx, op)
    observed, captureErr := handler.Capture(ctx, op.Resource)
    if captureErr != nil {
        return recordRecoveryRequired(journal, opID, captureErr)
    }

    desired, desiredReason := handler.Equivalent(op.Desired, observed, CompareApplyResult)
    before, beforeReason := handler.Equivalent(op.Before, observed, CompareApplyPrecondition)

    if desired {
        journal, err = store.Update(ctx, runID, journal.Revision, func(j *model.RemediationJournal) error {
            target := j.Operation(opID)
            target.ObservedAfter = &observed
            target.State = OperationApplied
            if applyErr != nil {
                target.Error = newJournalError("apply_failed", applyErr)
            }
            return validateTransition(j)
        })
        if err != nil {
            return err
        }
        if applyErr != nil {
            return newAppliedWithError(opID, applyErr)
        }
        return nil
    }

    if before {
        return recordApplyFailureWithoutSideEffect(journal, opID, applyErr, beforeReason)
    }
    return recordAmbiguous(journal, opID, desiredReason)
}
```

부작용 직후 상태 저장이 실패해도 선행 `apply_intent_durable` 기록이 남아 있으므로 복구 시 현재 자원을 비교해 적용 여부를 판정할 수 있습니다.

### 롤백 작업 의사 코드

```go
func rollbackOperation(ctx context.Context, runID string, opID string) error {
    journal, err := store.Load(ctx, runID)
    if err != nil {
        return err
    }
    op := journal.Operation(opID)
    resumeExistingIntent := op.RollbackIntentAt != nil

    if handler.BackupRequired(op) {
        if op.Backup == nil {
            return recordRollbackBlocked(journal, opID, "backup_missing")
        }
        if err := backupStore.Verify(ctx, runID, *op.Backup); err != nil {
            return recordRollbackBlocked(journal, opID, err.Error())
        }
    }
    current, err := handler.Capture(ctx, op.Resource)
    if err != nil {
        return recordRecoveryRequired(journal, opID, err)
    }

    if ok, _ := handler.Equivalent(op.Before, current, CompareRollbackResult); ok {
        return markRolledBack(journal, opID)
    }
    if op.ObservedAfter == nil {
        return recordRecoveryRequired(journal, opID, errors.New("missing observed-after state"))
    }
    if ok, reason := handler.Equivalent(*op.ObservedAfter, current, CompareRollbackPrecondition); !ok {
        return recordPreconditionFailure(journal, opID, reason)
    }

    journal, err = store.Update(ctx, runID, journal.Revision, func(j *model.RemediationJournal) error {
        j.Operation(opID).State = OperationRollbackIntentDurable
        return validateTransition(j)
    })
    if err != nil {
        return err
    }

    rollbackErr := handler.Rollback(ctx, op, op.Backup)
    restored, captureErr := handler.Capture(ctx, op.Resource)
    if captureErr != nil {
        return recordRecoveryRequired(journal, opID, captureErr)
    }

    if ok, _ := handler.Equivalent(op.Before, restored, CompareRollbackResult); ok {
        return markRolledBackWithDiagnostic(journal, opID, rollbackErr)
    }
    if ok, _ := handler.Equivalent(*op.ObservedAfter, restored, CompareRollbackPrecondition); ok {
        if rollbackErr == nil {
            rollbackErr = errors.New("rollback returned success but resource was not restored")
        }
        return recordRollbackFailure(journal, opID, rollbackErr)
    }
    return recordAmbiguous(journal, opID, "rollback result matches neither before nor after")
}
```

실제 구현에서는 `require` 실패를 구조화 오류로 기록하고, 상태와 WAL revision을 보존해야 합니다.

`resumeExistingIntent`는 새 intent를 쓰기 전에 캡처해야 합니다. 처리기는 이 값이 참일 때만 `Before`와 영속 after 사이의 안전한 부분 metadata 상태를 중단된 롤백으로 받아들입니다. 방금 기록한 새 intent를 근거로 사전 외부 변경을 허용하면 안 됩니다.

## 구현 검증 계약

현재 `file_metadata` 구현은 최소한 다음 사례를 자동 테스트해야 합니다.

- 상태 루트의 직접 block-backed `xfs`·`ext4` 허용과 NFS·CIFS·tmpfs·overlay·FUSE·알 수 없는 filesystem magic 거부
- mountinfo type/magic 또는 block device major:minor 불일치, loop·ramdisk, bind·subdirectory mount와 container·isolated mount namespace 거부
- 상태 루트 생성 전 가장 가까운 기존 부모 검사와 생성 후 최종 root 재검사
- 각 상태 타입의 허용·금지 전이
- WAL 마지막 레코드 절단, digest 불일치, revision 누락
- 백업 쓰기·동기화·해시 검증 실패 시 변경 미수행
- 부작용 직전, 부작용 직후, 후행 상태 저장 직전의 강제 종료
- 롤백 의도 저장 직후와 복원 직후의 강제 종료
- 같은 파일을 수정하는 A, B의 단독 A 롤백 거부와 cascade 역순
- 독립 분기 롤백 지속과 실패 노드 선행 분기 차단
- 외부 파일 변경, 심볼릭 링크 교체, 부모 디렉터리 교체 탐지
- 같은 inode에서 권한·소유권 변경과 복원, `chown` 뒤 mode 재적용
- 내용·inode·부모·링크·확장 속성·SELinux context 변동 거부
- 다중 하드 링크 파일 metadata 조치 거부
- 전체 성공, 롤백 실패, 부분 롤백, 복구 필요 상태의 보고서 표현
- 적용 전 취소의 tombstone 재시도, 삭제 실패와 저널·백업 보존
- 읽기 전용 status가 불완전 WAL tail을 수정하지 않는지 확인
- stale rollback preview digest와 승인하지 않은 cascade 거부

Rocky Linux 9.8 amd64 일반 서버 설치의 임시 일반 파일에서 같은 inode의 mode 축소와 백업된 원래 mode 복원 smoke를 통과했습니다. 내장 대상 경로의 실제 변경, 항목별·실행 전체 롤백 end-to-end, 최소 설치와 arm64 검증은 아직 수행하지 않았으므로 플랫폼과 조치 정의는 `pending`을 유지합니다. 오류 주입 테스트는 저널·백업 저장소와 자원 처리기 인터페이스의 fixture 또는 fake 구현으로 각 영속화 경계를 재현할 수 있어야 합니다.

파일 생성·내용 교체·삭제 또는 서비스 처리기를 추가할 때는 그 기능을 CLI나 사용자 문서에 노출하기 전에 하드 링크, ACL·확장 속성·SELinux context, 서비스 활성·비활성·masked 상태와 재부팅 후 런타임 복원 제한을 별도의 실제 VM 및 오류 주입 테스트로 검증해야 합니다.
