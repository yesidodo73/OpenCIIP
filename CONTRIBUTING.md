<div align="center">

# OpenCIIP에 기여하기

[개발 환경](#개발-환경) · [변경 확인](#변경-확인) · [Linux 배포판 지원](#linux-배포판-지원) · [Pull Request](#pull-request) · [README](README.md)

</div>

OpenCIIP에 관심을 가져주셔서 감사합니다.

작업을 시작하기 전에 같은 내용의 이슈나 pull request가 있는지 확인해 보세요. 보안 취약점은 공개 이슈에 올리지 말고 [SECURITY.md](SECURITY.md)를 확인해주세요.

## 개발 환경

- Go 1.26 이상
- Linux 동작을 확인할 수 있는 환경
- 배포판별 동작을 확인할 때는 해당 운영체제의 VM

의존성을 내려받고 바이너리를 빌드할 수 있습니다.

```bash
go mod download
go build ./cmd/openciip
```

## 변경 확인

변경한 Go 파일은 `gofmt`로 정리해주세요.

```bash
gofmt -w <변경한 Go 파일>
go test ./...
go vet ./...
go build ./cmd/openciip
```

변경 범위에 필요한 명령만 실행해도 됩니다. 실행하지 못한 검증이 있다면 pull request에 함께 적어주세요.

실제 서버의 비밀번호, 키, 토큰, 원본 설정 파일과 식별 가능한 로그는 테스트 자료나 이슈에 넣지 마세요.

## Linux 배포판 지원

새 Linux 배포판이나 버전을 추가할 때는 [OS 지원 가이드와 템플릿](contrib/os-support/README.md)을 사용해주세요. Pull request를 열 때는 [OS 지원 전용 양식](https://github.com/yesidodo73/OpenCIIP/compare?expand=1&template=os-support.md)을 선택하면 필요한 검증 내용을 빠뜨리지 않고 작성할 수 있습니다.

읽기 전용 점검의 `tested` 상태와 자동 조치의 `verified` 상태는 별도로 확인합니다. 새 환경의 자동 조치는 해당 OS·버전·아키텍처에서 적용 후 재점검, 항목별 롤백과 실행 전체 롤백을 확인한 뒤 지원 대상으로 추가합니다.

플랫폼 YAML과 fixture는 자동으로 발견됩니다. 공통 Linux 동작은 상위 계층에 두고, 배포판 파일에는 실제 차이만 작성해주세요.

## Pull Request

Pull request에는 다음 내용을 작성해주세요.

- 해결하려는 문제
- 변경한 내용
- 확인한 환경과 테스트 결과
- 아직 확인하지 못한 부분

가능하면 하나의 pull request에는 한 가지 목적만 담아주세요. 관련 없는 코드 정리나 공개 형식 변경을 함께 섞지 않는 것이 좋습니다.

## 커밋

커밋 메시지는 변경 목적을 짧고 분명하게 작성해주세요.

```text
feat: Linux 공통 점검 추가
fix: include 설정 판정 수정
test: PAM 설정 회귀 사례 추가
docs: 사용 방법 정리
```

## 버전

OpenCIIP는 Semantic Versioning을 사용합니다. 소스에서 빌드한 실행 파일의 버전은 `./openciip version`으로 확인할 수 있습니다.

- 호환되는 버그 수정은 patch 버전을 올립니다.
- 호환되는 기능 추가는 minor 버전을 올립니다.
- 호환성을 깨는 변경은 major 버전을 올립니다.
- 사전 릴리스 기간에는 배포 가능한 변경 묶음마다 `alpha.N` 번호를 올립니다.
- 문서나 테스트만 변경하고 바이너리 동작이 바뀌지 않으면 버전을 올리지 않아도 됩니다.

## 라이선스

별도로 명시하지 않는 한 프로젝트에 제출한 기여에는 저장소의 [Apache License 2.0](LICENSE)이 적용됩니다.
