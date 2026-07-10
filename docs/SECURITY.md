# 보안 구현 원칙

## 명령 실행

- 가능한 경우 실행 파일과 인자를 분리합니다.
- `sh -c`, `bash -c` 사용을 최소화합니다.
- 사용자 입력을 명령 문자열에 직접 결합하지 않습니다.
- 모든 외부 명령에 timeout을 적용합니다.
- stdout과 stderr를 분리합니다.
- 종료 코드와 실행 시간을 수집합니다.
- locale 차이를 고려합니다.
- 사용자 정의 값의 형식을 검증합니다.
- 필요한 경우 `--`를 사용해 옵션 인젝션을 방지합니다.
- 점검 명령은 코드에 등록된 허용 목록과 `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`의 신뢰 가능한 실행 파일만 사용합니다.
- 실행 환경은 상속하지 않고 고정된 `PATH`, `LANG=C`, `LC_ALL=C` 등 최소 환경만 전달합니다.
- 명령의 자식 프로세스도 timeout과 취소 범위에 포함합니다.
- stdout과 stderr에는 각각 크기 제한을 적용하고 제한 도달 여부를 증적에 기록합니다.

## 셸 인젝션 방지

사용자 입력, 파일 경로, 계정명, 서비스명, 사용자 정의 규칙 값을 셸 문자열에 직접 삽입하지 않습니다.

사용자 정의 규칙에서 임의 명령 실행을 허용할 경우 명령어와 인자를 분리된 구조로 저장합니다.

## 임시 파일

- 예측 가능한 고정 파일명을 사용하지 않습니다.
- 안전한 임시 파일 생성 함수를 사용합니다.
- 생성 직후 적절한 권한을 적용합니다.
- 작업 종료 후 정리합니다.
- 민감정보가 포함된 임시 파일은 가능한 한 만들지 않습니다.

## 심볼릭 링크 방어

- 중요 파일 수정 전 심볼릭 링크 여부를 확인합니다.
- 백업 경로를 기존 파일로 재사용하지 않습니다.
- 파일 유형, 소유자, 권한을 검증합니다.
- 파일 내용을 교체하는 기능을 추가할 경우 같은 디렉터리의 안전한 임시 파일과 원자적 rename을 사용합니다. 현재 내장 조치는 파일 내용을 교체하지 않습니다.
- 대상 경로가 예상한 디렉터리 내부인지 확인합니다.
- 조치 전후 inode와 파일 유형 변경을 검토합니다.
- 보고서와 상태 저장소는 경로 이탈을 차단하는 rooted 파일 API를 사용합니다.
- Linux 읽기 전용 시스템 수집은 고정한 대상 루트 directory descriptor와 `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`를 사용합니다. 대상 루트 내부의 절대 심볼릭 링크는 정상 구성으로 해석하되 루트 이탈과 `/proc` magic link 추적은 거부하고, 필요한 커널 기능을 확인할 수 없으면 위험한 경로 기반 fallback 없이 중단합니다.
- 일반 파일은 열린 descriptor에서 유형과 크기를 확인한 뒤 제한된 길이만 읽고, 읽기 전후 device·inode·소유권·mode·크기·mtime·ctime·link count를 다시 비교합니다. 수집 중 변경된 파일의 내용과 이전 metadata를 한 snapshot처럼 보고하지 않습니다.
- 현재 `file_metadata` 조치는 심볼릭 링크를 따르지 않고 승인한 inode를 한 번 열어 같은 file descriptor에서 `fchown`, `fchmod`, `fsync`와 후행 상태 수집을 수행합니다. 경로와 부모가 계속 같은 inode를 가리키는지도 확인합니다.

## 조치 상태와 승인

- 계획 digest에는 호스트, 플랫폼, 규칙·조치 정의 identity, 실행 파일 identity, 자원과 선행·목표 상태, 충돌 그래프를 포함합니다. 조치 정의 identity에는 `pending`·`verified`·`rejected` 상태, 검증 환경, 검증 시각과 증적 SHA-256 목록이 포함됩니다.
- 승인과 적용 직전에 현재 플랫폼, 규칙·조치 정의와 실행 파일 identity를 다시 확인합니다. 조치 정의는 중복되지 않는 정규화된 검증 환경, RFC 3339 검증 시각과 하나 이상의 중복되지 않는 소문자 SHA-256 증적 digest를 가진 `verified` 상태만 허용하며 `pending`과 `rejected`는 거부합니다.
- 사용자 요청 롤백은 `dev`, `unknown`, 수정된 빌드를 거부합니다. 다만 수정 릴리스로 장애를 복구할 수 있도록 원본 실행 파일 digest 일치 대신 지원 journal schema·작업 종류, 호스트, 백업과 현재 writer chain을 검증합니다.
- 프로덕션 오케스트레이터 생성자는 검증된 디스크 journal store만 받아, 내구성 없는 임의 저장소가 apply intent를 성공으로 가장하지 못하게 합니다.
- 적용 완료 전까지 전역 조치 잠금을 유지하고 원래 evaluator가 `PASS`를 확인하지 못하면 승인된 실패 정책으로 롤백합니다.
- 각 변경 세트는 자원 검증과 해당 evaluator의 `PASS`가 모두 끝난 뒤에만 `verified`로 기록하고, 실행 종료 전 마지막 작성자 상태와 전체 evaluator를 다시 검사합니다.
- 부작용 전에 write-ahead intent를 파일과 부모 디렉터리까지 동기화합니다.
- 부작용 뒤 취소된 요청을 그대로 상태 기록에 사용하지 않습니다. 취소 신호를 분리한 새 제한 시간 context로 후행 수집, WAL 기록과 안전한 롤백을 수행하고, 저장 오류 뒤에는 권위 있는 WAL을 다시 읽어 커밋 여부를 확인합니다.
- 부분 metadata 롤백 재개는 이전 rollback intent가 이미 영속화된 작업에만 허용합니다. 새 rollback intent를 방금 기록했다는 사실로 사전 외부 변경을 중단된 롤백처럼 취급하지 않습니다.
- 현재 `Desired` 또는 부분 metadata를 중단된 순방향 적용으로 추론할 때는 `state_inferable` 작업의 durable apply intent와 백업 외에 `AppliedAt`, `ObservedAfter`, rollback intent가 모두 없어야 합니다. 이미 완료·관측된 적용이 이후 다른 상태로 바뀌면 외부 변경 가능성을 보존하고 자동 복원하지 않습니다.
- 부분 metadata 판정은 시스템 호출의 원자 경계를 따릅니다. `(UID,GID)`는 단일 `fchown` 결과이므로 Before 또는 Desired의 완전한 쌍이어야 하며, 별도 `fchmod`로 바뀌는 mode만 독립적으로 Before 또는 Desired를 허용합니다.
- 상태 조회는 WAL을 truncate하거나 snapshot을 덮어쓰지 않는 읽기 전용 경로를 사용합니다.
- 사용자 요청 롤백 미리보기는 기존 lock과 WAL을 읽기만 하며, 불완전 WAL tail이 있으면 `recover` 전까지 거부합니다. 실행 시에는 현재 revision의 digest와 범위를 다시 검증합니다.
- 적용 전 취소는 미사용 payload namespace만 삭제하며 저널과 백업을 보존합니다.
- 조치 상태 루트는 Linux에서 `fstatfs`, `/proc/self/mountinfo`, sysfs block-device graph를 함께 확인해 검증된 영속 로컬 block device에 마운트된 `xfs` 또는 `ext4`만 허용합니다. device-mapper와 MD는 모든 backing leaf가 NVMe·SCSI·virtio·Xen·MMC 계열 영속 로컬 장치로 확인될 때만 허용하고, loop·zram·ramdisk·NBD·RBD·DRBD·AoE와 명백한 원격 transport, 알 수 없는 virtual leaf는 거부합니다. 네트워크·휘발·overlay·FUSE·특수·알 수 없는 파일 시스템과 bind/container, PID 1과 분리된 mount namespace를 거부하며, 현재 `/`와 `/proc/1/root`의 device/inode identity가 다르거나 확인할 수 없으면 chroot로 간주합니다. 생성 전 기존 부모와 생성 후 최종 루트를 각각 검증합니다.

## 네트워크 동작

기본 점검과 조치 과정에서 외부 네트워크 요청을 수행하지 않습니다.

기본 기능에 포함하지 않는 항목:

- 최신 버전 확인
- 가이드 자동 다운로드
- CVE 데이터 조회
- 텔레메트리
- 결과 자동 전송
- 외부 API 호출

나중에 추가하더라도 다음을 지켜야 합니다.

- 기본 비활성화
- 사용자 동의
- 전송 데이터 명시
- timeout
- TLS 검증
- 오프라인 모드 유지

## 파일 권한

보고서, 증적, 백업 파일에는 민감정보가 포함될 수 있습니다.

권장 기본값:

```text
디렉터리: 0700
파일: 0600
```
