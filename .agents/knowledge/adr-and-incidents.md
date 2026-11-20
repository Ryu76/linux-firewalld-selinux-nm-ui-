# 장애 복구 이력 및 설계 결정 (ADR)

## ADR-001: Agent Python 3.9 호환 문법 유지
- **배경**: 개발 PC는 Python 3.10+이지만, 배포 대상인 Rocky Linux 9.3 기본 파이썬은 3.9임.
- **결정**: `agent/` 하위 모든 파일은 `str | None` 대신 `Optional[str]` / `Union[...]` 사용.

## INC-001: Rocky 9.3 연결 시 `502 Bad Gateway` 발생
- **원인**: `semanage port -l -C` 등 상태 수집 명령이 실서버에서 약 5초 소요되는데 Controller `httpx` 타임아웃이 3s/5s로 설정되어 조기 실패함.
- **해결**: `controller/main.py` 타임아웃을 `15.0s`로 상향 조정.

## INC-002: SELinux 모드 변경 및 새로고침 시 UI 미반영
- **원인**: 10초/5초 백그라운드 폴링 중 `isLoading` 플래그가 `true`일 때 수동 새로고침이나 `runAction` 후 재조회가 무시됨.
- **해결**: `runAction`과 `refreshAll`은 `loadActiveStatus()`를 직접 호출하고, `fetch`에 `cache: "no-store"` 적용.

## INC-003: 정적 파일 CSS 캐시로 인한 서브 탭 UI 깨짐
- **원인**: 브라우저가 이전 `style.css`를 `304 Not Modified`로 캐시하여 신규 `.subtab` 스타일이 적용되지 않음.
- **해결**: `index.html`에서 `?v=N` 버전 쿼리 관리 및 `.subtab`에 `appearance: none` 적용.
