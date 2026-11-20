# Linux Access Control Hub — Project Guidelines

## 1. Tech Stack & Architecture
- **Agent (`agent/`)**: FastAPI + Uvicorn (Python **3.9+ 호환** 필수 — Rocky Linux 9.x 기본 파이썬 지원)
  - 실서버(`Linux`)에서는 `firewall-cmd`, `semanage`, `setenforce`, `nmcli`, `ss`를 직접 제어 (`live-linux` 모드)
  - 비-리눅스(Windows/macOS)에서는 `MockLinuxBackend`로 자동 전환 (`mock-simulator` 모드)
- **Controller (`controller/`)**: FastAPI + `httpx.AsyncClient` + Vanilla HTML/CSS/JS (`controller/static/`)
- **Tests (`tests/`)**: `pytest` + `fastapi.testclient.TestClient`

## 2. Run & Test Commands
```powershell
# 전체 테스트 실행 (코드 수정 후 필수)
python -m pytest -v

# 로컬 시뮬레이터 실행 (터미널 2개)
uvicorn agent.main:app --host 127.0.0.1 --port 9100
uvicorn controller.main:app --host 127.0.0.1 --port 8000
```

## 3. Hard Rules (절대 준수)
1. **Python 3.9 호환성 (`agent/`)**: `agent/` 하위 파일에서는 런타임 `X | Y` 유니온 문법 대신 `typing.Optional`, `typing.Union`을 사용합니다.
2. **명령어 인젝션 차단**: `agent/linux_backend.py`에서 `subprocess.run(..., shell=True)` 사용을 금지합니다. 모든 외부 입력은 `agent/schemas.py`에서 정규식으로 검증합니다.
3. **잠금 보호 (`protected_ports`)**: 서버별 고정 보호 포트(SSH `22`, Agent 포트 등) 삭제 시도는 Controller와 Agent 양쪽에서 차단해야 합니다.
4. **민감 정보 보호**: `controller/data/`(`servers.json`, `audit.jsonl`)는 토큰 및 내부 IP를 포함하므로 절대 Git에 커밋하지 않습니다.
5. **지식 베이스 참조**: 과거 장애 원인 및 설계 결정(ADR)은 상시 로드하지 말고, 트러블슈팅이 필요할 때만 `.agents/knowledge/adr-and-incidents.md`를 참조하세요.
