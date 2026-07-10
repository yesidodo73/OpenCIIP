# Rocky Linux 9.8 Unix 서버 점검 구현·검증 매트릭스

## 목적과 범위

이 문서는 2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드의 Unix 서버 `U-01`부터 `U-67`까지에 대한 Rocky Linux 9.8 구현과 남은 검증 범위를 기록합니다.

이 문서는 지원 완료 선언이 아닙니다. 모든 evaluator는 구현되어 있으나 Rocky Linux 9.8 플랫폼과 U-01~U-67의 실효 규칙 바인딩은 아직 `pending`입니다. VM에서 검증하지 않은 명령, 패키지 기본값, 파일 경로와 서비스 구성은 검증 예정 사항이며, VM 증적 없이 해당 범위를 `verified`로 전환하면 안 됩니다.

현재 구현에는 다음 원칙을 적용합니다.

- 가이드의 판단 기준을 우선하며, 가이드 문구가 모순되거나 Rocky Linux 9.8 기본 구성과 충돌하면 추측하지 않고 `UNKNOWN`으로 남깁니다.
- 단순 문자열 검색보다 실효 설정, 전체 include/drop-in 해석, 런타임 상태를 우선합니다.
- 서비스 설치 여부만으로 활성 상태를 판단하지 않습니다. service, socket, timer, 프로세스, 리스닝 소켓과 실효 설정을 함께 확인합니다.
- 파일 모드는 숫자 크기 비교가 아니라 허용 비트 마스크로 비교합니다. POSIX ACL과 심볼릭 링크 대상도 함께 확인합니다.
- 외부 네트워크 요청은 기본적으로 수행하지 않습니다. 최신 버전, 외부 ACL, 원격 배너처럼 로컬 증적만으로 확정할 수 없는 항목은 `UNKNOWN`입니다.
- 수집 명령 실패, 권한 부족, 파싱 실패는 `UNKNOWN`이 아니라 `ERROR`입니다.
- 서비스나 기능이 설치되지 않아 실제로 적용 대상이 아니면 `NOT_APPLICABLE`을 사용합니다. 가이드가 파일 부재 자체를 양호로 명시한 항목은 예외적으로 `PASS`로 둡니다.

## 자동화 수준

- `automatic`: Rocky Linux 9.8에서 지원하는 구성이라면 로컬의 객관적 증적으로 자동 확정할 수 있습니다.
- `conditional`: 기관 정책, 허용 목록, 예외 목록, 서비스 종류 또는 신뢰할 수 있는 기준 데이터가 있어야 자동 확정할 수 있습니다.
- `manual`: 기술 증적은 수집할 수 있지만 필요성이나 적정성을 사람이 판단해야 합니다. 기본 결과는 `UNKNOWN`입니다.

## 자동 조치 등급

- `safe`: 변경 대상과 검증 방법이 명확하고 서비스 영향이 작습니다.
- `caution`: 접근 또는 서비스 동작에 영향을 줄 수 있어 영향 확인이 필요합니다.
- `dangerous`: 인증 차단, 원격 접속 단절, 서비스 중단, 데이터 소유권 변경 등의 위험이 큽니다.
- `unsupported`: 일반화된 자동 조치를 제공하지 않습니다.

모든 등급에서 `docs/REMEDIATION.md`의 dry-run, 승인, 백업, 변경 후 검증, 항목별 또는 실행 전체 롤백을 생략하지 않습니다.

## 공통 Rocky Linux 9.8 수집 기준

- 플랫폼: `/etc/os-release`, `uname`, `rpm --eval '%{_arch}'`, PID 1 및 systemd 버전으로 정확히 식별합니다.
- 계정과 그룹: 파일 직접 파싱과 함께 `getent` 결과를 사용하되 NSS/SSSD 조회 실패를 빈 결과로 취급하지 않습니다.
- PAM: `authselect current`, `authselect check`와 선택된 프로필 원본을 확인합니다. `/etc/pam.d/system-auth`, `password-auth`, `postlogin`의 `/etc/authselect/...` 절대 심볼릭 링크는 대상 루트 내부에서 안전하게 해석하며, authselect 관리 파일을 직접 수정하는 조치는 만들지 않습니다.
- systemd: `systemctl show`, `systemctl cat`, `FragmentPath`, `DropInPaths`, unit-file enablement와 socket activation을 확인합니다. `/usr/lib/systemd/system`, `/run/systemd/system`, `/etc/systemd/system`의 우선순위를 반영합니다.
- 네트워크: `ss`의 리스닝 상태, firewalld의 runtime/permanent 구성, nftables 실효 ruleset을 분리해 수집합니다. firewalld 기본 zone의 런타임 값은 단독 `--get-default-zone`으로, 영구 값은 `firewalld.conf`의 `DefaultZone`과 문서화된 기본값으로 확인합니다. 외부 방화벽 통제는 별도 증적 없이는 확정하지 않습니다.
- 파일 시스템: `findmnt`로 실제 로컬 영속 파일 시스템을 먼저 열거하고 각 마운트별로 교차 파일 시스템을 넘지 않게 검색합니다. `/proc`, `/sys`, `/run`, 컨테이너 overlay와 네트워크 파일 시스템을 무조건 로컬 결과에 섞지 않습니다.
- 민감정보: `/etc/shadow`, SNMP community, TSIG key, 메일 인증 정보 등은 원문을 보고서에 남기지 않고 판정에 필요한 파생 정보만 기록합니다.

판정 경계 표기에서 `P`, `F`, `U`, `N/A`는 각각 `PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE`을 뜻합니다.

## 1. 계정 관리

| 항목 | 자동화 | Rocky Linux 9.8 실효 설정·파일·명령 | evaluator ID | 판정 경계와 주의점 | 자동 조치 |
|---|---|---|---|---|---|
| U-01 root 계정 원격 접속 제한 | `conditional` | `systemctl show sshd`, `ss -lntp`, `sshd -T -C user=root,host=<호스트>,addr=<허용 출발지>`; sshd include와 모든 `Match` 블록; Telnet service/socket/xinetd와 리스너 | `unix.account.remote_root_login` | P: 모든 실제 SSH/Telnet 경로에서 root 직접 로그인이 차단됨. F: 하나라도 허용됨. U: 출발지별 `Match`를 완전히 열거할 수 없거나 지원하지 않는 원격 터미널 구현. N/A: 원격 터미널 서비스가 전혀 없음. `sshd -T` 단일 기본 출력만으로 확정하지 않습니다. | `caution` |
| U-02 비밀번호 관리정책 설정 | `conditional` | `authselect current`, `authselect check`; `/etc/security/pwquality.conf`, `pwquality.conf.d`; `/etc/security/pwhistory.conf`; `/etc/login.defs`; 선택된 PAM 프로필; `getent passwd`, 대상 로컬 계정의 `chage -l` | `unix.account.password_policy` | P: 최소 8자, 숫자·대문자·소문자·특수문자 각 1자, root 강제, 이력 4회 이상, 최소 1일·최대 90일이 신규 정책과 기존 적용 계정 모두에 충족하고, 정책 모듈을 통과한 동일 토큰이 모든 지원 password writer에 전달됨. F: 객관적으로 약한 값 또는 정책보다 먼저 확정적으로 실행되는 로컬 writer. U: 외부 IdP 정책, 동적·알 수 없는 PAM writer, 토큰 전달이나 기존 계정 범위를 확인하지 못함. N/A: 없음. 가이드 예시의 `PASS_MIN_DAYS 0`과 최종 권고 1일이 충돌하므로 1일을 기준으로 하고 근거를 기록합니다. | `dangerous` |
| U-03 계정 잠금 임계값 설정 | `automatic` | `authselect current/check`의 `with-faillock`; `/etc/security/faillock.conf`; 선택된 `system-auth`·`password-auth`; PAM include 순서와 제어 흐름 | `unix.account.lockout_threshold` | P: 모든 적용 인증 경로에 유효 `deny` 1~10과 `authfail` 기록이 있고, 문서화된 `preauth+authfail+account` 또는 `authfail+authsucc` 성공·실패 분기를 우회 없이 확인함. F: 미설정, 10 초과 또는 필수 기록 모듈 부재. U: custom PAM 제어 흐름, include/substack 경계나 숫자 jump를 결정적으로 해석할 수 없음. N/A: 비밀번호 인증 경로와 적용 계정이 전혀 없는 경우에만 사용. RHEL 9 계열에서는 authselect 관리 여부를 무시한 직접 PAM 검색을 금지합니다. | `dangerous` |
| U-04 비밀번호 파일 보호 | `automatic` | `/etc/passwd`, `/etc/shadow`; `pwck -r`; 각 passwd 두 번째 필드와 shadow 대응 관계 | `unix.account.shadow_password` | P: 로컬 계정 비밀번호가 shadow에만 저장되고 passwd 필드에는 `x`, 잠금 또는 비밀번호 없음 표지만 존재. F: passwd에 해시나 비밀번호 자료가 직접 존재. U: 대체 계정 저장소라 로컬 구조를 확정할 수 없음. N/A: 없음. 읽기 권한 실패는 ERROR입니다. | `dangerous` |
| U-05 root 이외의 UID가 0 금지 | `automatic` | `/etc/passwd`와 `getent passwd` 전체를 UID 기준으로 그룹화 | `unix.account.uid_zero_unique` | P: UID 0이 root 한 계정뿐임. F: root 이외 UID 0 계정 존재. U: NSS 조회가 불완전하거나 충돌함. N/A: 없음. 로컬 파일만 보고 SSSD/NSS 계정을 누락하지 않습니다. | `dangerous` |
| U-06 사용자 계정 su 기능 제한 | `conditional` | `/etc/pam.d/su` 전체 PAM include; `pam_wheel.so use_uid` 또는 명시 그룹; `getent group`; `stat`·ACL `/usr/bin/su` | `unix.account.su_restriction` | P: PAM 또는 실행 권한으로 승인 그룹만 `su` 가능. F: 일반 사용자가 제한 없이 사용 가능. U: custom PAM 조건이나 허용 그룹을 해석할 수 없음. N/A: root 외 로그인 가능 계정이 없을 때. 실행 파일 권한만 또는 PAM 한 줄만으로 확정하지 않습니다. | `caution` |
| U-07 불필요한 계정 제거 | `manual` | `getent passwd`; 마스킹된 `/etc/shadow` 파생 상태(`state`, `algorithm`, 최소·최대 일수); 완전한 기관 승인 계정 목록 | `unix.account.unnecessary_accounts` | P: 승인 계정 목록과 정확히 일치하고 계정 상태 증적이 완전함. F: 승인 목록에 없는 계정이 존재. U: 승인 목록이나 shadow 상태 증적이 없거나 불완전함. N/A: 없음. Rocky Linux 9.8의 `passwd`에는 전체 계정 상태를 조회하는 `-a` 옵션이 없으며, 최근 로그인 기록은 현재 수집하지도 삭제 근거로 사용하지도 않습니다. | `unsupported` |
| U-08 관리자 그룹에 최소한의 계정 포함 | `manual` | `getent group root wheel`; sudoers가 참조하는 그룹; SSSD/외부 권한 그룹; 승인 관리자 목록 | `unix.account.admin_group_membership` | P: 승인 관리자 목록과 정확히 일치. F: 사람이 불필요한 관리자 구성원을 확정. U: 승인 목록 또는 외부 그룹 정보를 확보하지 못함. N/A: 없음. Rocky에서 `root` 그룹과 실제 sudo 관리자 권한은 동일하지 않으므로 둘 다 증적으로 수집합니다. | `unsupported` |
| U-09 계정이 존재하지 않는 GID 금지 | `manual` | `getent group`, `getent passwd`; 그룹 멤버·primary GID; 해당 GID 소유 파일 검색; 승인 그룹 목록 | `unix.account.unnecessary_groups` | P: 무계정 그룹도 서비스·파일 소유·향후 할당 근거까지 검토되어 모두 필요함. F: 사람이 불필요하다고 확정. U: 멤버가 없다는 사실만 확인했거나 소유 파일 검색이 불완전. N/A: 없음. 빈 그룹을 자동으로 취약 판정하지 않습니다. | `unsupported` |
| U-10 동일한 UID 금지 | `automatic` | `/etc/passwd` 및 `getent passwd`를 UID별 그룹화 | `unix.account.duplicate_uid` | P: 모든 UID가 유일함. F: 둘 이상의 계정이 같은 UID 사용. U: NSS 조회 불완전. N/A: 없음. UID 0 중복은 U-05에도 별도 보고합니다. | `dangerous` |
| U-11 사용자 Shell 점검 | `conditional` | `getent passwd`; `/etc/shells`; `/etc/login.defs`의 시스템 UID 범위; RPM이 만든 계정 정보와 기관 서비스 계정 목록 | `unix.account.service_shell` | P: 로그인 불필요가 확인된 계정은 `/sbin/nologin` 또는 `/bin/false`. F: 로그인 불필요가 확인된 계정에 대화형 shell. U: 계정 역할을 알 수 없음. N/A: 적용할 서비스 계정이 없음. 가이드의 고정 계정명 목록을 Rocky에 그대로 적용하지 않습니다. | `caution` |
| U-12 세션 종료 시간 설정 | `conditional` | `/etc/profile`, `/etc/bashrc`, 실제 source되는 `/etc/profile.d/*.sh`와 sh/bash 사용자 시작 파일의 정적 우선순위 해석 | `unix.account.session_timeout` | P: 분석 가능한 모든 sh/bash 대화형 context의 최종 `TMOUT`이 1~600초이고 export·readonly 상태. F: 확정적인 최종값 부재, 0, 600초 초과, export 또는 readonly 누락. U: 명령 치환·동적 조건, 미지원 shell(csh 포함) 또는 불완전 source graph. N/A: 대화형 계정 없음. 사용자 시작 파일을 root 권한으로 source하여 검사하지 않습니다. | `caution` |
| U-13 안전한 비밀번호 암호화 알고리즘 사용 | `automatic` | `/etc/login.defs`의 `ENCRYPT_METHOD`; 선택된 authselect PAM의 `pam_unix`; 마스킹한 `/etc/shadow` 해시 접두부 | `unix.account.password_hash` | P: 도달 가능한 `pam_unix` 신규 정책과 모든 비잠금 로컬 해시가 SHA-2 이상이며, 선행 성공 또는 대체 writer 경로가 로컬 해시 정책을 우회하지 않음. F: DES, MD5, Blowfish 등 가이드상 취약 알고리즘. U: 알 수 없는 접두부·writer·PAM 제어 흐름, 외부 인증 또는 신규 정책과 기존 해시가 불일치. N/A: 로컬 비밀번호 해시가 전혀 없음. Rocky 9.8의 실제 기본 해시와 yescrypt 지원 여부는 VM 검증이 필요합니다. | `dangerous` |

## 2. 파일 및 디렉터리 관리

| 항목 | 자동화 | Rocky Linux 9.8 실효 설정·파일·명령 | evaluator ID | 판정 경계와 주의점 | 자동 조치 |
|---|---|---|---|---|---|
| U-14 root 홈, 패스 디렉터리 권한 및 패스 설정 | `conditional` | `getent passwd root`; `/etc/profile`, `/etc/bashrc`, `/etc/profile.d/*.sh`, `/root/.bash_profile`, `/root/.bashrc`의 PATH 할당 우선순위; 현재 프로세스 환경은 참고만 사용 | `unix.file.root_path` | P: root의 최종 PATH에 `.`이 앞이나 중간에 없고 빈 구성요소도 없음. F: 앞·중간의 `.` 또는 `::`처럼 현재 디렉터리를 뜻하는 빈 항목. U: 동적 명령 치환이나 조건부 분기로 최종값 불명. N/A: 없음. 가이드는 마지막의 `.`을 허용하지만 위험 참고정보를 함께 표시합니다. 사용자 파일을 실행하여 검사하지 않습니다. | `caution` |
| U-15 파일 및 디렉터리 소유자 설정 | `automatic` | `findmnt -rn -o TARGET,FSTYPE,OPTIONS`; 각 로컬 영속 마운트에서 `find <mount> -xdev`의 `-nouser`, `-nogroup`; NSS 상태 | `unix.file.orphaned_owner` | P: 완전한 검색에서 orphan 없음. F: 소유자나 그룹이 존재하지 않는 항목 발견. U: 일부 마운트 미검색, NSS 장애 또는 네임스페이스 밖 ID일 가능성. N/A: 검색 가능한 로컬 영속 파일 시스템이 없음. 후보 삭제 여부는 별도 판단입니다. | `dangerous` |
| U-16 `/etc/passwd` 파일 소유자 및 권한 설정 | `automatic` | `lstat`·`stat`, `getfacl -cp /etc/passwd`, 파일 유형과 SELinux context; 허용 비트 마스크 `0644` | `unix.file.passwd_permissions` | P: 일반 파일, root 소유, 허용 비트 `0644`의 부분집합이며 추가 ACL 쓰기 권한 없음. F: 소유자·파일 유형·모드·ACL 중 하나라도 위반. U: 지원하지 않는 ACL/파일 시스템. N/A: 없음. 파일 누락 또는 읽기 실패는 ERROR입니다. | `safe` |
| U-17 시스템 시작 스크립트 권한 설정 | `automatic` | `systemctl list-unit-files`; `systemctl show`의 `FragmentPath`, `DropInPaths`; `systemctl cat`; `/etc`, `/run`, `/usr/lib/systemd/system`의 실제 대상; 활성 legacy rc 스크립트 | `unix.file.startup_permissions` | P: 활성·enabled unit의 모든 fragment/drop-in과 사용 중인 시작 스크립트가 root 소유이고 비소유자 쓰기 없음. F: 하나라도 일반 사용자 쓰기 또는 비-root 소유. U: transient/generated unit, 끊어진 링크, custom generator를 완전히 해석하지 못함. N/A: systemd 기반 Rocky에서는 없음. 심볼릭 링크 자체가 아니라 해석된 대상 파일을 검사합니다. | `caution` |
| U-18 `/etc/shadow` 파일 소유자 및 권한 설정 | `automatic` | `lstat`·`stat`, `getfacl -cp /etc/shadow`, SELinux context; 허용 비트 마스크 `0400` | `unix.file.shadow_permissions` | P: 일반 파일, root 소유, 허용 비트 `0400`의 부분집합이고 추가 ACL 접근 없음. F: 명백한 초과 권한 또는 비-root 소유. U: Rocky 9.8의 패키지 기본 group/context와 충돌이 확인될 때. N/A: 없음. 실제 Rocky 기본 모드는 VM 검증이 필요합니다. | `safe` |
| U-19 `/etc/hosts` 파일 소유자 및 권한 설정 | `automatic` | `lstat`·`stat`, ACL, SELinux context `/etc/hosts`; 허용 비트 마스크 `0644` | `unix.file.hosts_permissions` | P: root 소유 일반 파일이고 허용 비트 `0644` 이내. F: 비-root 소유, 초과 모드 또는 쓰기 ACL. U: 설정 관리자가 특수 파일로 제공하여 안전성을 확정 못함. N/A: 없음. | `safe` |
| U-20 `/etc/(x)inetd.conf` 파일 소유자 및 권한 설정 | `automatic` | xinetd/inetd unit·프로세스; 실제 main config 경로; `/etc/inetd.conf`, `/etc/xinetd.conf`, `/etc/xinetd.d/*`; `stat`, ACL | `unix.file.inetd_permissions` | P: 사용되는 모든 설정 파일이 root 소유이고 허용 비트 `0600` 이내. F: 활성 구성 파일 하나라도 위반. U: custom config 경로나 include를 해석 못함. N/A: inetd/xinetd와 해당 설정이 없음. 파일 하나만 안전하고 include가 취약한 경우 PASS가 아닙니다. | `safe` |
| U-21 `/etc/(r)syslog.conf` 파일 소유자 및 권한 설정 | `automatic` | `systemctl cat/show rsyslog`; `rsyslogd -N1`; `/etc/rsyslog.conf`와 실제 `$IncludeConfig` 대상; 각 파일 stat·ACL | `unix.file.syslog_permissions` | P: 로드되는 모든 rsyslog 설정이 root/bin/sys 허용 소유자이고 허용 비트 `0640` 이내. F: 사용 중인 파일 위반. U: 동적 include나 custom daemon 인자를 해석 못함. N/A: rsyslog/syslog를 사용하지 않고 journald만 사용. 구문 검증 실패는 ERROR입니다. | `caution` |
| U-22 `/etc/services` 파일 소유자 및 권한 설정 | `automatic` | `lstat`·`stat`, ACL, SELinux context `/etc/services`; 허용 비트 마스크 `0644` | `unix.file.services_permissions` | P: root/bin/sys 허용 소유자이고 허용 비트 `0644` 이내. F: 소유자 또는 권한 위반. U: 특수 파일·지원하지 않는 ACL. N/A: 없음. | `safe` |
| U-23 SUID, SGID, Sticky bit 설정 파일 점검 | `conditional` | 로컬 영속 마운트별 `find -xdev -type f`의 SUID/SGID 비트; sticky 디렉터리는 별도 inventory; `rpm -qf`, `rpm -V`, 패키지 서명; 기관 `path\|sha256\|mode` 기준선 | `unix.file.special_bits` | P: 검색이 완전하고 모든 SUID/SGID 파일이 완전한 기관 기준선과 정확히 일치. F: 기준선과 다른 파일 또는 명시적으로 불필요한 특수 권한. U: 패키지 서명·무결성만 확인됨, custom·미소유 파일, 불완전 검색 또는 기관 기준선 부재. N/A: 없음. 패키지 기본값은 기관의 업무상 승인 여부를 대신하지 않으며 sticky bit는 제목만 보고 제거하지 않습니다. | `dangerous` |
| U-24 사용자, 시스템 환경변수 파일 소유자 및 권한 설정 | `automatic` | 적용 계정의 홈과 `.profile`, `.bash_profile`, `.bashrc`, `.kshrc`, `.cshrc`, `.login`, `.exrc`, `.netrc` 등; stat·ACL | `unix.file.user_environment_permissions` | P: 각 파일 소유자가 root 또는 해당 계정이고 소유자 외 쓰기 권한 없음. F: 다른 소유자 또는 비소유자 쓰기. U: 원격 홈, 특수 ACL, 지원하지 않는 shell 파일. N/A: 적용 파일이 없음. `.netrc` 내용은 민감정보로 저장하지 않습니다. | `caution` |
| U-25 world writable 파일 점검 | `conditional` | 로컬 영속 마운트별 일반 파일 world-write 검색; 파일 유형·mount option·패키지 소유·기관 예외 목록 | `unix.file.world_writable` | P: 후보 없음 또는 모든 후보가 승인 예외. F: 사유 없는 world-writable 일반 파일. U: 예외 목록 부재, 소유 목적 불명 또는 일부 마운트 미검색. N/A: 검색 대상 영속 파일 시스템 없음. 디렉터리와 sticky bit는 이 항목의 일반 파일 판정에 섞지 않습니다. | `dangerous` |
| U-26 `/dev`에 존재하지 않는 device 파일 점검 | `conditional` | `/dev`의 같은 파일 시스템에서 regular file inventory; `/dev/shm`, `/dev/mqueue` 등 별도 mount 제외; udev 정보와 프로세스 사용 여부 | `unix.file.invalid_device_nodes` | P: 승인되지 않은 일반 파일이 없음. F: 사람이 불필요하거나 위장 파일이라고 확정한 후보. U: regular file의 생성 주체·용도를 확인하지 못함. N/A: 후보 없음이 아니라 PASS로 처리. `major/minor가 없다`는 이유만으로 자동 삭제하지 않습니다. | `dangerous` |
| U-27 `$HOME/.rhosts`, `hosts.equiv` 사용 금지 | `automatic` | rlogin/rsh/rexec unit·socket·listener; `/etc/hosts.equiv`; 적용 홈의 `.rhosts`; stat·ACL과 신뢰 항목 parser | `unix.file.rhosts_trust` | P: r 서비스가 설치됐지만 완전히 비활성화되었거나, 활성 시 모든 파일이 올바른 소유자·`0600` 이내이고 `+` 신뢰 없음. F: 활성 서비스와 함께 조건 하나라도 위반. U: custom 신뢰 백엔드나 일부 홈 미접근. N/A: r 서비스 구성요소가 없음. | `caution` |
| U-28 접속 IP 및 포트 제한 | `conditional` | `ss -lntup`; `firewall-cmd` runtime/permanent의 active zone·service·port·rich rule·policy; `nft list ruleset`; 기관 허용 IP/포트와 외부 방화벽 증적 | `unix.network.ingress_restriction` | P: 모든 원격 리스너가 승인 출발지/포트로 현재와 재부팅 후 모두 제한됨. F: 정책보다 넓게 허용되거나 통제가 없음. U: 허용 목록 부재, 외부 ACL만 주장, runtime/permanent 불일치 또는 여러 방화벽 동시 사용. N/A: 원격 리스닝 서비스가 전혀 없음. 방화벽 변경은 관리 세션을 끊을 수 있습니다. | `dangerous` |
| U-29 `hosts.lpd` 파일 소유자 및 권한 설정 | `automatic` | `/etc/hosts.lpd`의 lstat·stat·ACL과 print service 사용 여부 | `unix.file.hosts_lpd_permissions` | P: 파일이 없거나 root 소유이고 허용 비트 `0600` 이내. F: 존재하면서 소유자·모드·ACL 위반. U: custom 경로의 lpd가 별도 파일을 사용함. N/A: 사용하지 않습니다. 가이드가 파일 부재를 명시적으로 양호로 정의하므로 부재는 PASS입니다. | `safe` |
| U-30 UMASK 설정 관리 | `conditional` | `/etc/profile`, `/etc/bashrc`, `/etc/profile.d/*.sh`, `/etc/login.defs`, 각 지원 shell·사용자 시작 파일의 우선순위; systemd `UMask`는 별도 참고 | `unix.file.umask` | P: 모든 적용 로그인 shell의 최종 umask에 `0022` 비트가 포함되어 022 이상으로 제한됨. F: 하나라도 group/other write를 막지 않는 약한 값. U: 동적·조건부 설정, 파일 간 충돌 또는 미지원 shell. N/A: 없음. 숫자 대소가 아니라 비트 포함 관계로 비교합니다. | `caution` |
| U-31 홈 디렉토리 소유자 및 권한 설정 | `conditional` | `getent passwd`의 적용 계정과 홈; lstat·stat·ACL; 승인된 공유 홈 정책 | `unix.file.home_permissions` | P: 홈 소유자가 해당 계정이고 다른 사용자에게 쓰기 권한 없음. F: 비소유 계정 또는 명백한 비소유자 쓰기. U: 공유 홈·공용 그룹 ACL의 적정성을 정책 없이 결정 못함. N/A: 홈 디렉터리 비적용이 명시된 계정. 누락 홈은 U-32로 판정합니다. | `caution` |
| U-32 홈 디렉토리로 지정한 디렉토리의 존재 관리 | `conditional` | `getent passwd`; 각 홈 경로 lstat; shell·계정 유형·서비스 패키지와 승인 예외 목록 | `unix.file.home_exists` | P: 홈이 필요한 모든 계정의 디렉터리가 존재. F: 홈이 필요한 것으로 확인된 계정의 경로 누락. U: nologin/system 계정의 placeholder 홈 필요성을 알 수 없음. N/A: 기관 정책으로 홈 비적용이 승인된 계정만 개별 제외. 누락을 자동으로 계정 삭제나 디렉터리 생성으로 연결하지 않습니다. | `dangerous` |
| U-33 숨겨진 파일 및 디렉토리 검색 및 제거 | `manual` | 로컬 영속 마운트의 숨김 항목 inventory; 패키지 소유, 생성·수정 시각, 소유자, 실행 권한, 해시; 정상 baseline | `unix.file.suspicious_hidden` | P: 사람이 전체 후보를 검토해 불필요·의심 항목이 없다고 확인. F: 악성 또는 불필요하다고 확정한 항목 존재. U: 기본값이며 이름이 숨김이라는 사실만 수집. N/A: 검색 대상 영속 파일 시스템 없음. 숨김 이름을 휴리스틱으로 취약 판정하지 않습니다. | `unsupported` |

## 3. 서비스 관리

| 항목 | 자동화 | Rocky Linux 9.8 실효 설정·파일·명령 | evaluator ID | 판정 경계와 주의점 | 자동 조치 |
|---|---|---|---|---|---|
| U-34 Finger 서비스 비활성화 | `automatic` | finger 관련 service/socket unit, xinetd include, 프로세스와 TCP 79 리스너; 패키지·unit 이름은 VM 검증 필요 | `unix.service.finger_disabled` | P: 구성요소는 있으나 service/socket이 disabled·inactive이고 리스너가 없음. F: 어떤 경로로든 활성 또는 리스닝. U: 알 수 없는 super-server나 custom unit. N/A: finger 서버 구성요소가 없음. 클라이언트 패키지 설치만으로 FAIL 처리하지 않습니다. | `caution` |
| U-35 공유 서비스에 대한 익명 접근 제한 설정 | `conditional` | vsftpd/proftpd 실효 설정; Samba `testparm -s`; NFS `exportfs -v`와 exports; 활성 서비스·리스너 | `unix.service.anonymous_share` | P: FTP·Samba의 guest/anonymous 경로가 차단되고, NFS 사용 시 검증된 규칙으로 비인가 공유가 없음을 확정. F: 명시적인 익명 FTP, Samba guest share 또는 인증·client 제한 없이 공개된 NFS export. U: 미지원 서버 또는 Rocky NFS 규칙 검증 전의 `root_squash`·`all_squash`·`anonuid` 조합. N/A: 공유 서비스가 없음. `anonuid`/`anongid`는 익명 UID/GID를 지정할 뿐 접근을 단독으로 활성화하지 않으므로 문자열 존재만으로 FAIL 처리하지 않습니다. | `caution` |
| U-36 r 계열 서비스 비활성화 | `conditional` | rlogin/rsh/rexec service/socket, xinetd/inetd 설정, 프로세스, TCP 512~514 리스너, `.rhosts`·`hosts.equiv` | `unix.service.r_commands_disabled` | P: 설치됐더라도 모든 r 서비스가 disabled·inactive이고 리스너 없음. F: 승인되지 않은 활성 경로. U: 백업·클러스터 용도 예외가 주장되었으나 보완 통제를 확인하지 못함. N/A: 관련 구성요소 없음. | `caution` |
| U-37 crontab 설정파일 권한 설정 미흡 | `conditional` | `stat`·ACL `/usr/bin/crontab`, `/usr/bin/at`, `/etc/crontab`, `/etc/cron.d`, `/etc/cron.*`, `/var/spool/cron`, `/var/spool/at`, allow/deny 파일; `rpm -V cronie cronie-anacron at` | `unix.service.scheduler_permissions` | P: 적용 명령과 관련 파일이 가이드 허용 권한·소유자를 충족하고 Rocky 패키지 동작과도 일치. F: 일반 사용자에게 명백히 과도한 쓰기/실행 권한. U: 가이드의 `640 이하`와 취약 기준 `640 이상`이 640에서 겹치거나, SUID/SGID 제거가 Rocky 패키지 기본 동작과 충돌. N/A: cron과 at 모두 없음. `at` 미설치 시 해당 하위 대상만 제외합니다. VM에서 RPM 기본 모드와 기능 영향 검증 전에는 자동 조치하지 않습니다. | `dangerous` |
| U-38 DoS 공격에 취약한 서비스 비활성화 | `conditional` | echo/discard/daytime/chargen service/socket/xinetd와 포트 7/9/13/19; NTP/DNS/SNMP/SMTP의 활성 상태와 기관 필요 서비스 목록 | `unix.service.dos_prone_disabled` | P: 네 legacy 응답 서비스가 모두 비활성이고 정책상 불필요한 추가 서비스도 비활성. F: legacy 서비스가 활성 또는 불필요하다고 확정한 서비스가 활성. U: NTP·DNS·SNMP·SMTP 필요성 미확정. N/A: 나열된 구성요소 없음. 가이드 조치문은 NTP까지 비활성화하라고 하지만 U-65는 시각 동기화를 요구하므로 NTP를 일괄 FAIL/중지하지 않습니다. | `dangerous` |
| U-39 불필요한 NFS 서비스 비활성화 | `conditional` | `nfs-server`, 관련 socket/unit·프로세스; `/proc/fs/nfsd`; `exportfs -v`; `/etc/exports`, `/etc/exports.d`; 리스너와 마운트 사용 | `unix.service.nfs_disabled` | P: NFS가 불필요하다고 선언된 서버에서 export와 관련 daemon이 모두 비활성. F: 불필요하다고 확정했지만 export 또는 daemon 활성. U: 활성 NFS의 업무 필요성 또는 client/server 역할 불명. N/A: NFS server 구성요소가 없음. rpcbind나 client helper만으로 NFS server 활성으로 판단하지 않습니다. | `dangerous` |
| U-40 NFS 접근 통제 | `conditional` | `exportfs -v`; `/etc/exports`, `/etc/exports.d/*`; 파일 stat·ACL; 승인 client/network 목록; `root_squash`, `sec`, `ro/rw`, wildcard와 공백 문법 | `unix.service.nfs_access_control` | P: 모든 export가 승인 client로 제한되고 설정 파일이 root 소유·허용 비트 `0644` 이내. F: 접근 통제 부재와 파일 권한 초과가 함께 확인됨. U: 두 조건 중 하나만 위반하거나, wildcard·DNS 이름·보안 flavor의 적정성을 정책 없이 확정 못함. N/A: NFS server/export 없음. 가이드 취약 기준이 두 조건을 `그리고`로 연결하므로 혼합 상태를 임의로 FAIL로 바꾸지 않습니다. | `dangerous` |
| U-41 불필요한 automountd 제거 | `conditional` | `autofs.service`, automount unit·process; `/etc/auto.master`, `/etc/auto.master.d`, 참조 map; 실제 automount mount | `unix.service.autofs_disabled` | P: 불필요하다고 선언된 autofs가 disabled·inactive. F: 불필요한데 활성. U: NFS/Samba/CD-ROM 등의 업무 사용 여부 불명. N/A: autofs 구성요소 없음. map 파일만 있다고 활성으로 확정하지 않습니다. | `dangerous` |
| U-42 불필요한 RPC 서비스 비활성화 | `conditional` | 가이드에 열거된 RPC 관련 unit·socket·process; systemd 의존 관계; 필요 시 로컬 `rpcinfo -p` 증적; NFS 의존 서비스와 승인 목록 | `unix.service.rpc_disabled` | P: 불필요 목록의 daemon이 모두 비활성. F: 승인되지 않은 해당 daemon 활성. U: 숫자 RPC program이나 NFS 의존성의 업무 필요성을 매핑하지 못함. N/A: RPC framework와 대상 daemon 없음. 문자열에 `rpc`가 있다는 이유로 모든 서비스를 중지하지 않습니다. | `dangerous` |
| U-43 NIS, NIS+ 점검 | `automatic` | `ypserv`, `ypbind`, `ypxfrd`, `yppasswdd`, `ypupdated` unit·process·listener·패키지; NIS+ 주장 시 실제 구현 증적 | `unix.service.nis_disabled` | P: NIS 구성요소가 설치됐더라도 disabled·inactive. F: NIS daemon 활성. U: NIS+ 사용을 주장하거나 custom 호환 구현을 사용하며 Rocky 9.8 지원 여부 미검증. N/A: 관련 구성요소 없음. Rocky 9.8에서 NIS+ 제공 여부는 VM/저장소 검증이 필요합니다. | `dangerous` |
| U-44 tftp, talk 서비스 비활성화 | `automatic` | tftp/talk/ntalk service/socket, xinetd/inetd include, 프로세스와 UDP 69·517·518 리스너 | `unix.service.legacy_datagram_disabled` | P: 설치 구성은 있으나 모든 활성 경로가 disabled·inactive이고 리스너 없음. F: 하나라도 활성. U: custom super-server 또는 컨테이너 경계로 리스너 주체 불명. N/A: 관련 서버 구성요소 없음. | `caution` |
| U-45 메일 서비스 버전 점검 | `manual` | 활성 MTA 식별; `postconf mail_version`, `sendmail -d0.1 -bv root`, RPM NEVRA·vendor와 캐시된 보안 advisory 증적 | `unix.service.mail_patch_level` | 현재 구현은 활성 MTA의 증적을 수집한 뒤 신뢰 가능한 최신 기준과 기관 패치 절차의 수동 대조를 요구하므로 U입니다. N/A: MTA 서비스 없음. 자동 P/F 정책 입력 경로가 추가되기 전에는 upstream 숫자나 캐시만으로 확정하지 않습니다. | `dangerous` |
| U-46 일반 사용자의 메일 서비스 실행 방지 | `conditional` | 활성 MTA 종류; Sendmail `PrivacyOptions=restrictqrun`; Postfix `/usr/sbin/postsuper` stat·ACL과 내부 권한 모델; package `rpm -V`; Exim 해당 도구 | `unix.service.mail_queue_restriction` | P: 지원 MTA에서 일반 사용자의 queue 관리 실행이 실효적으로 차단. F: 명백히 무권한 사용자가 queue 관리 가능. U: Postfix package 기본 실행 비트와 가이드의 chmod 예시가 충돌하거나 미지원 MTA. N/A: MTA 없음. Rocky 9.8의 Postfix 기본 모드와 자체 권한 검사를 VM에서 확인하기 전에는 chmod 조치를 만들지 않습니다. | `caution` |
| U-47 스팸 메일 릴레이 제한 | `conditional` | Postfix `postconf -n`·`postconf -d`의 `smtpd_relay_restrictions`, `smtpd_recipient_restrictions`, `mynetworks`, `relay_domains`; Sendmail/Exim 실효 설정; 승인 relay client·domain 목록 | `unix.service.mail_relay` | P: 인증 또는 승인 네트워크·도메인만 relay되고 그 외는 거부. F: 무조건 permit, 넓은 `mynetworks`, open relay 흐름이 명확. U: lookup map·정책 daemon·승인 목록을 해석 못함. N/A: MTA 없음. 설정 한 줄의 존재가 아니라 제한 순서 전체를 평가합니다. | `dangerous` |
| U-48 expn, vrfy 명령어 제한 | `automatic` | Postfix 실효 `disable_vrfy_command`; Sendmail 실효 `PrivacyOptions`의 `noexpn`, `novrfy`; Exim 지원 설정; 활성 MTA 종류 | `unix.service.mail_user_enumeration` | P: 지원 MTA에서 VRFY와 EXPN이 모두 비활성 또는 미구현. F: 하나라도 허용. U: 미지원 MTA나 동적 설정. N/A: MTA 없음. Postfix의 EXPN 미구현은 해당 하위 조건 PASS로 기록합니다. | `caution` |
| U-49 DNS 보안 버전 패치 | `manual` | authoritative DNS 활성 여부; `named -v`, RPM NEVRA·vendor; DNF history; 신뢰 가능한 Rocky 9.8 저장소 metadata·advisory와 패치 운영 증적 | `unix.service.dns_patch_level` | P: 사람이 주기적 관리 절차와 최신 vendor 보안 패치 적용을 확인. F: 정책 부재 또는 신뢰 가능한 기준으로 미적용이 확정. U: 단일 시점의 로컬 버전만 있거나 metadata가 오래됨. N/A: authoritative DNS 서비스 없음. BIND는 backport되므로 upstream 버전 문자열 단순 비교를 금지합니다. | `unsupported` |
| U-50 DNS Zone Transfer 설정 | `conditional` | `named-checkconf -p -x`로 비밀을 가리고 include를 펼친 options/view/zone별 `allow-transfer`; 승인 secondary 목록; 활성 named | `unix.service.dns_zone_transfer` | P: transfer가 `none`이거나 승인 secondary/TSIG로만 제한. F: `any` 또는 모든 사용자에게 허용되는 실효값. U: 명명 ACL·view·key를 승인 목록과 연결하지 못함. N/A: authoritative DNS 없음. global 값만 보고 zone/view override를 누락하지 않습니다. | `dangerous` |
| U-51 DNS 서비스의 취약한 동적 업데이트 설정 금지 | `conditional` | `named-checkconf -p -x`의 zone별 `allow-update`, `update-policy`; ACL·TSIG 참조; 승인 dynamic update 주체; 활성 named | `unix.service.dns_dynamic_update` | P: update 비활성 또는 승인 TSIG/update-policy로 제한. F: `any`, 광범위 unsigned update 등 명백한 무통제. U: 복잡한 policy/ACL을 승인 주체와 매핑 못함. N/A: authoritative DNS 없음. 단순히 `allow-update` 문자열 존재만으로 FAIL 처리하지 않습니다. | `dangerous` |
| U-52 Telnet 서비스 비활성화 | `automatic` | telnet service/socket, xinetd/inetd include, 프로세스와 TCP 23 리스너; SSH 존재는 참고 | `unix.service.telnet_disabled` | P: 설치 구성은 있으나 모든 Telnet 활성 경로가 disabled·inactive이고 리스너 없음. F: Telnet server 활성. U: custom super-server·컨테이너 리스너 주체 불명. N/A: Telnet server 구성요소 없음. telnet client 설치는 대상이 아닙니다. | `caution` |
| U-53 FTP 서비스 정보 노출 제한 | `conditional` | 활성 FTP server 종류; vsftpd `ftpd_banner`, `banner_file`; ProFTPD `ServerIdent` 등 전체 include; 승인 경고 문구와 선택적 loopback probe | `unix.service.ftp_banner` | P: 실제 배너가 승인 경고 문구이며 제품·버전·호스트 정보가 없음. F: 제품/버전 등 불필요 정보가 명백히 노출. U: 동적 배너, 미지원 FTP 구현, 승인 문구 부재 또는 능동 probe 미승인. N/A: FTP 서비스 없음. 설정 파일 문자열만으로 실제 기본 배너를 확정하지 않습니다. | `caution` |
| U-54 암호화되지 않는 FTP 서비스 비활성화 | `conditional` | FTP service/socket·리스너; vsftpd TLS 관련 실효 설정과 include; ProFTPD TLS; SFTP는 sshd 하위 서비스로 분리; 선택적 loopback TLS handshake | `unix.service.plaintext_ftp_disabled` | P: 설치됐지만 평문 FTP가 비활성, 또는 FTPS에서 인증·데이터 채널 TLS가 강제됨. F: 로그인이나 데이터에 평문 FTP를 허용. U: custom server 또는 암호화 강제 여부를 로컬 설정만으로 확정 못함. N/A: FTP server 구성요소 없음. 포트 21 사용만으로 평문이라고 단정하지 않습니다. | `dangerous` |
| U-55 FTP 계정 Shell 제한 | `automatic` | 활성 FTP server가 사용하는 계정과 `getent passwd`; `/sbin/nologin`, `/bin/false`; service account mapping | `unix.service.ftp_account_shell` | P: 모든 FTP 전용 계정이 non-login shell. F: FTP 전용 계정에 대화형 shell. U: 계정이 FTP 전용인지 또는 virtual-user mapping을 확정 못함. N/A: FTP 서비스와 FTP 계정 없음. | `caution` |
| U-56 FTP 서비스 접근 제어 설정 | `conditional` | FTP bind/listener; firewalld runtime/permanent, nftables; vsftpd user/IP control과 PAM; 승인 client IP/host 목록 및 외부 ACL 증적 | `unix.service.ftp_access_control` | P: 모든 FTP endpoint가 승인 source로만 제한. F: 로컬·검증된 외부 통제가 전혀 없거나 정책보다 넓음. U: 허용 목록 부재, 외부 ACL 미검증, DNS 기반 host 규칙 불명. N/A: FTP 서비스 없음. `ftpusers`는 사용자 제한이지 IP 접근 통제의 충분조건이 아닙니다. | `dangerous` |
| U-57 Ftpusers 파일 설정 | `automatic` | 활성 FTP server의 PAM service 이름; `/etc/pam.d/vsftpd` 등 전체 stack; `/etc/vsftpd/ftpusers`, `user_list`; `userlist_enable`, `userlist_deny`; ProFTPD root-login 지시자 | `unix.service.ftp_root_login` | P: 모든 실제 FTP 인증 경로에서 root가 차단. F: 하나라도 root 허용. U: custom PAM/server 또는 목록 의미를 확정 못함. N/A: FTP 서비스 없음. 목록에 root가 있어도 `userlist_deny`와 PAM 연결이 반대이면 PASS가 아닙니다. | `caution` |
| U-58 불필요한 SNMP 서비스 구동 점검 | `automatic` | `snmpd.service`·custom agent, 프로세스, UDP 161/162 리스너; 패키지와 unit/socket enablement | `unix.service.snmp_disabled` | P: 설치 구성은 있으나 SNMP가 disabled·inactive이고 리스너 없음. F: SNMP agent가 활성. U: custom agent 또는 namespace 때문에 활성 여부를 확정 못함. N/A: SNMP agent 구성요소 없음. 가이드의 명시적 기준에 따라 승인된 업무 사용도 기술 판정은 FAIL이며 예외·보완 통제는 별도 최종 평가 근거로 기록합니다. 활성 시 U-59~U-61도 계속 평가합니다. | `dangerous` |
| U-59 안전한 SNMP 버전 사용 | `automatic` | net-snmp main config와 include; `rocommunity`, `rwcommunity`, `com2sec`, `rouser`, `rwuser`, VACM; agent 실행 인자; 민감값 마스킹 | `unix.service.snmp_version` | P: 활성 agent가 v3만 허용. F: v1/v2c community 경로가 하나라도 활성. U: 미지원 agent나 동적으로 로드된 access module. N/A: SNMP agent 없음. v3 사용자 존재만으로 v1/v2c가 비활성이라고 보지 않습니다. | `dangerous` |
| U-60 SNMP Community String 복잡성 설정 | `conditional` | v1/v2c community는 메모리 내에서만 길이·문자군 검사 후 즉시 폐기; v3는 생성·변경 당시 정책 준수 증적 또는 보안 저장소 attestation | `unix.service.snmp_credential_complexity` | P: v1/v2c 값이 public/private가 아니고 영문+숫자 10자 이상 또는 영문+숫자+특수문자 8자 이상이며, v3는 검증 가능한 복잡성 증적이 있음. F: 평문으로 확인 가능한 약한 값. U: v3 기존 비밀번호는 복원 불가하고 증적 없음. N/A: SNMP agent 없음. community 원문·해시를 보고서에 남기지 않습니다. | `dangerous` |
| U-61 SNMP Access Control 설정 | `conditional` | net-snmp `rocommunity`/`rwcommunity` source, `rouser`/`rwuser`, `com2sec`, group/view/access VACM 전체; 승인 manager source·user·OID view 목록; firewalld/nftables | `unix.service.snmp_access_control` | P: 승인 source/user와 필요한 최소 view로 제한. F: 모든 source나 과도한 write/view가 명백히 허용. U: 승인 목록 부재 또는 VACM chain을 결정적으로 해석 못함. N/A: SNMP agent 없음. source 제한 한 줄만 보고 전체 접근 통제를 확정하지 않습니다. | `dangerous` |
| U-62 로그인 시 경고 메시지 설정 | `conditional` | `/etc/issue`, `/etc/issue.net`, `/etc/motd`; sshd 실효 `Banner`; 활성 Telnet·FTP·SMTP의 실효 배너; DNS는 해당 제품의 사용자 노출 문자열과 가이드 적용 의미 확인 | `unix.service.login_warning` | P: 모든 적용 로그인/서비스 endpoint에 승인 경고가 있고 시스템·제품 정보가 없음. F: 적용 endpoint의 경고가 비어 있거나 명백히 정보 노출. U: 승인 문구 부재, 동적 배너 또는 DNS의 `로그온` 의미 불명. N/A: 적용 가능한 로그인 endpoint가 전혀 없는 경우. 단순히 파일이 존재한다는 이유로 PASS 처리하지 않습니다. | `caution` |
| U-63 sudo 명령어 접근 관리 | `conditional` | `/etc/sudoers`, 실제 `#includedir` 파일의 lstat·stat·ACL·SELinux context; `visudo -c`; RPM 기본 모드 검증 | `unix.service.sudoers_permissions` | P: root 소유이고 허용 비트 `0640`의 부분집합이며 include 파일도 안전하고 `visudo -c` 성공. F: root 외 소유 또는 명백한 초과 권한. U: 가이드 양호 문구의 정확히 640과 취약 문구의 640 초과 사이 해석, Rocky의 통상 0440 기본값을 VM에서 확인하지 못함. N/A: sudo 미설치·미사용. 숫자 비교 대신 허용 비트로 평가하며 0440은 검증 후 더 제한적인 값으로 처리할 예정입니다. | `caution` |

## 4. 패치 관리

| 항목 | 자동화 | Rocky Linux 9.8 실효 설정·파일·명령 | evaluator ID | 판정 경계와 주의점 | 자동 조치 |
|---|---|---|---|---|---|
| U-64 주기적 보안 패치 및 벤더 권고사항 적용 | `manual` | `/etc/os-release`, `uname -r`, 설치 RPM NEVRA; DNF history; repository와 metadata 기준 시각; 오프라인 `dnf --cacheonly updateinfo list --security`; 기관 패치 정책·최근 적용 증적 | `unix.patch.policy_and_currency` | P: 사람이 패치 주기·영향 검토 절차와 최신 vendor 권고 반영을 확인. F: 정책이 없거나 신뢰 가능한 최신 기준에서 미적용을 확정. U: 로컬 패키지 목록만 있거나 repository metadata가 오래됨. N/A: 없음. 기본 네트워크 비활성 상태에서 `업데이트 없음`을 최신 상태로 오인하지 않습니다. | `unsupported` |

## 5. 로그 관리

| 항목 | 자동화 | Rocky Linux 9.8 실효 설정·파일·명령 | evaluator ID | 판정 경계와 주의점 | 자동 조치 |
|---|---|---|---|---|---|
| U-65 NTP 및 시각 동기화 설정 | `conditional` | `systemctl show chronyd`; `chronyc tracking`, `chronyc sources -v`, `chronyc sourcestats`; `/etc/chrony.conf`와 실제 `confdir`/`include`; `timedatectl show`; 승인 시간원 목록 | `unix.log.time_sync` | P: chronyd가 활성·부팅 활성이고 승인 시간원에 실제 동기화되며 leap 상태가 정상. F: daemon 비활성, 시간원 미설정 또는 명백히 동기화 정책 미적용. U: 일시적 네트워크 장애, 시작 직후, 승인 시간원 목록 부재 또는 외부 시간원 검증 불가. N/A: 표준 서버 범위에서는 없음. RHEL 9 계열은 chrony가 기본이지만 Rocky 9.8 실제 구성은 VM 검증이 필요합니다. | `caution` |
| U-66 정책에 따른 시스템 로깅 설정 | `manual` | `systemctl show rsyslog systemd-journald`; `rsyslogd -N1`; `/etc/rsyslog.conf`, include; journald storage/forward 설정; 실제 로그 경로 증적 | `unix.log.policy` | F: journald 저장이 명시적으로 꺼지고 대체 rsyslog도 없거나, 활성 백엔드에 기록·전달 동작이 명백히 없음. 그 밖에는 기관 정책과 실제 테스트 이벤트를 자동 입력받지 않으므로 U이며 현재 자동 PASS는 없습니다. N/A: 없음. | `caution` |
| U-67 로그 디렉터리 소유자 및 권한 설정 | `conditional` | 활성 logger·auditd·서비스가 쓰는 실제 로그 경로; `/var/log`의 regular file lstat·stat·ACL; logrotate·tmpfiles 설정; RPM 소유·기본 모드; SELinux context | `unix.log.file_permissions` | P: 적용 로그 파일이 root 소유이고 허용 비트 `0644` 이내. F: 명백한 비-root 소유 또는 초과 권한이며 서비스 요구·승인 예외도 없음. U: Rocky 패키지가 `root:utmp`·0664 같은 다른 모드를 요구하거나 비-root daemon 로그 소유가 필요한 경우, 가이드와 충돌을 검증하지 못함. N/A: 적용 가능한 영속 로그 파일이 없음. `/var/log` 전체를 일괄 chown/chmod하지 않습니다. | `caution` |

## Rocky Linux 9.8 VM 검증 현황과 대기 목록

2026-07-11에 Rocky Linux 9.8 amd64 일반 서버 설치 한 대에서 읽기 전용 전체 점검과 임시 일반 파일 metadata 변경·복원 smoke를 수행했습니다. 전체 점검은 U-01~U-67을 모두 실행해 수집·파싱 `ERROR` 없이 끝났지만, 이 결과만으로 최소 설치·arm64·서비스별 변형까지 포괄하지 않으므로 모든 플랫폼·규칙·조치 정의 상태를 `pending`으로 유지합니다.

다음 항목은 실효 규칙 바인딩을 `verified`로 전환하기 전에 실제 Rocky Linux 9.8 최소 설치와 관련 서비스 설치 VM에서 추가로 확인해야 합니다.

1. `/etc/os-release`, 기본 저장소, 커널, systemd와 authselect 버전 및 amd64/arm64 차이
2. authselect 기본 프로필, `with-faillock`, PAM include 순서, pwquality·pwhistory·faillock의 실제 우선순위
3. 신규 비밀번호의 기본 해시 방식과 `/etc/shadow` 실제 접두부
4. `/etc/shadow`, `/etc/passwd`, `/etc/services`, `/etc/sudoers`의 RPM 기본 소유자·모드·SELinux context
5. cronie와 at의 실행 파일 및 spool/config 기본 모드, SUID/SGID 필요 여부와 `rpm -V` 결과
6. systemd unit의 `FragmentPath`·`DropInPaths` 출력 형식과 generated/transient unit 사례
7. finger, rsh/rlogin/rexec, tftp/talk, xinetd, NIS 관련 패키지와 unit/socket의 Rocky 9.8 저장소 제공 여부
8. firewalld runtime/permanent 출력과 nftables backend, `nftables.service` 동시 사용 탐지
9. nfs-utils의 `/etc/exports.d`, `exportfs -v`, NFSv4-only와 squash 옵션 출력
10. Postfix, Sendmail, BIND, vsftpd/ProFTPD, Samba, net-snmp 설치 시 실제 include 경로와 실효 설정 명령
11. chronyd의 비동기·동기화·시간원 장애 상태별 `chronyc` 출력과 locale 독립 파싱 가능성
12. rsyslog/journald 기본 routing, logrotate 이후 파일 모드, audit·wtmp·btmp·lastlog 등 Rocky 기본 예외

검증 결과에는 이미지/설치 유형, 패키지 NEVRA, 명령 exit code, stdout/stderr, locale, 파일 stat과 실제 판정 결과를 함께 남깁니다. `verified` 전환 전에는 Linux 공통 및 RHEL 9 evaluator를 Rocky Linux 9.8의 `pending` binding으로 예비 실행하되, 예비 `PASS`, `FAIL`, `NOT_APPLICABLE`은 최종 `UNKNOWN(unsupported_configuration)`으로 제한합니다. 수집이나 파싱 자체가 실패한 경우에는 `ERROR`를 유지하며, 실제 VM 증적을 통과한 항목만 `verified`로 전환합니다.

## 남은 VM 검증 우선순위

객관적이고 읽기 전용인 항목부터 설치 유형과 아키텍처별 증적을 확장합니다.

1. U-05, U-10, U-16, U-19, U-22처럼 단일 자료 구조나 파일 속성으로 확정 가능한 항목
2. U-04, U-15, U-17, U-18, U-20, U-21, U-24, U-27, U-29처럼 여러 파일·include 또는 파일 시스템 수집이 필요한 항목
3. U-01~U-03, U-06, U-12, U-13처럼 PAM·authselect·shell 실효 설정 해석이 필요한 항목
4. U-34 이후의 service/socket/listener와 제품별 설정 evaluator
5. 기관 정책과 허용 목록이 필요한 `conditional` 항목
6. 사람이 최종 판정해야 하는 `manual` 항목과 arm64 동등성

각 단계에서 collector와 evaluator를 분리하고, 동일 증적을 여러 항목이 재사용하더라도 항목별 판정 근거와 원본 출처를 별도로 기록합니다.

## 근거 문서

- [KISA·KrCERT/CC 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드](https://www.krcert.or.kr/kr/bbs/view.do?bbsId=B0000127&categoryCode=&menuNo=205021&nttId=71928&pageIndex=1)의 Unix 서버 U-01~U-67. 개발 중 추출한 전체 텍스트는 로컬 비버전 자료이며 공개 저장소에 포함하지 않습니다.
- [Red Hat Enterprise Linux 9 - authselect를 사용한 사용자 인증 구성](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect_configuring-authentication-and-authorization-in-rhel)
- [Red Hat Enterprise Linux 9 - systemd unit 파일 위치와 우선순위](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_systemd_unit_files_to_customize_and_optimize_your_system/using_systemd_unit_files_to_customize_and_optimize_your_system)
- [Red Hat Enterprise Linux 9 - firewalld runtime/permanent 구성](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_firewalls_and_packet_filters/using-and-configuring-firewalld_firewall-packet-filters)
- [Red Hat Enterprise Linux 9 - NFS 서비스 보안](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/securing_networks/securing-network-services_securing-networks)
- [Red Hat Enterprise Linux 9 - chrony를 사용한 시각 동기화](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_basic_system_settings/configuring-time-synchronization_configuring-basic-system-settings)
- [Red Hat Enterprise Linux 9 - rsyslog 구성](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/assembly_configuring-a-remote-logging-solution_security-hardening)
- [ISC BIND 9 named-checkconf 공식 매뉴얼](https://bind9.readthedocs.io/en/stable/manpages.html#named-checkconf-named-configuration-file-syntax-checking-tool)
- [Net-SNMP snmpd.conf 공식 매뉴얼](https://www.net-snmp.org/docs/man/snmpd.conf.html)

RHEL 9 문서는 계열별 구현 근거일 뿐 Rocky Linux 9.8 검증을 대신하지 않습니다. Rocky Linux 9.8 지원 표시는 위 VM 검증을 통과한 기능에만 부여합니다.
