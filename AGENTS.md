# Linux Access Control Hub — Project Guidelines

## 1. Tech Stack & Architecture
- **Agent (`agent/`)**: FastAPI + Uvicorn (**Python 3.14+** 기준, `uv` + `pyproject.toml` + `uv.lock` 관리)
  - 로컬 개발/테스트는 프로젝트 루트의 `uv` 가상환경(`.venv`) 사용
  - 실서버(`Rocky Linux 9.x`)에서는 OS 기본 Python 3.9와 분리된 전용 `.venv` 환경(`/opt/linux-access-control-hub/.venv`)에서 실행
  - 실서버(`Linux`)에서는 `firewall-cmd`, `semanage`, `setenforce`, `nmcli`, `ss`를 직접 제어 (`live-linux` 모드)
  - 비-리눅스(Windows/macOS)에서는 `MockLinuxBackend`로 자동 전환 (`mock-simulator` 모드)
- **Controller (`controller/`)**: FastAPI + `httpx.AsyncClient` + Vanilla HTML/CSS/JS (`controller/static/`)
- **Tests (`tests/`)**: `pytest` + `fastapi.testclient.TestClient`

## 2. Run & Test Commands
```powershell
# 의존성 동기화 (로컬 개발/테스트 전체)
uv sync --all-extras

# 전체 테스트 실행 (코드 수정 후 필수)
uv run pytest -v

# 로컬 시뮬레이터 실행 (터미널 2개)
uv run uvicorn agent.main:app --host 127.0.0.1 --port 8754
uv run uvicorn controller.main:app --host 127.0.0.1 --port 8000
```

## 3. Hard Rules (절대 준수)
1. **가상환경 및 Python 버전 (`Python 3.14+`, `uv`)**: 로컬 실행·테스트는 `uv`로 관리되는 `.venv`(`uv run`)에서 수행하며, 실서버 Agent는 OS 기본 Python을 건드리지 않고 `.venv` 격리 환경에서 실행합니다.
2. **명령어 인젝션 차단**: `agent/linux_backend.py`에서 `subprocess.run(..., shell=True)` 사용을 금지합니다. 모든 외부 입력은 `agent/schemas.py`에서 정규식으로 검증합니다.
3. **잠금 보호 (`protected_ports`)**: 서버별 고정 보호 포트(SSH `22`, Agent 포트 등) 삭제 시도는 Controller와 Agent 양쪽에서 차단해야 합니다.
4. **민감 정보 보호**: `controller/data/`(`servers.json`, `audit.jsonl`)는 토큰 및 내부 IP를 포함하므로 절대 Git에 커밋하지 않습니다.
5. **지식 베이스 참조**: 과거 장애 원인 및 설계 결정(ADR)은 상시 로드하지 말고, 트러블슈팅이 필요할 때만 `.agents/knowledge/adr-and-incidents.md`를 참조하세요.
6. **컴포넌트별 의존성 분리 (`pyproject.toml` + `uv.lock`)**: 의존성은 `pyproject.toml`의 `[project.optional-dependencies]`(`agent`, `controller`)와 `[dependency-groups]`(`dev`)로 분리하고, 버전은 `uv.lock`으로 잠금 관리합니다.
