# Linux Access Control Hub — 실행 및 운영 명령어 가이드

프로젝트의 **환경 구성, Controller 실행, 로컬 시뮬레이터, 실서버 배포, 운영 점검, 테스트**에 사용되는 모든 명령어를 정리한 문서입니다.  
로컬 명령어는 프로젝트 루트(`linux-access-control-hub/`) 기준 **Windows PowerShell**에서 실행합니다.

---

## 1. 개발 환경 초기 세팅 (`uv`)

```powershell
# Python 3.14 가상환경(.venv) 생성 및 전체 의존성(agent + controller + dev) 동기화
uv sync --all-extras

# 현재 가상환경 Python 버전 확인
uv run python --version
```

---

## 2. Controller (중앙 웹 대시보드) 실행

실행 후 웹 브라우저에서 **`http://127.0.0.1:8000`** 으로 접속합니다.

### A. PostgreSQL (Docker) 연동 실행 — 권장 표준 모드
Docker Desktop이 실행된 상태에서 아래 명령을 실행합니다.
```powershell
# 1) PostgreSQL 17 컨테이너 백그라운드 실행
docker compose up -d

# 2) Controller 실행
uv run uvicorn controller.main:app --host 127.0.0.1 --port 8000

# (개발 중 코드 수정 시 자동 재시작이 필요할 때)
uv run uvicorn controller.main:app --host 127.0.0.1 --port 8000 --reload
```

### B. 외부(별도 서버) PostgreSQL에 연결할 때
```powershell
Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
docker compose up -d
uv run uvicorn controller.main:app --host 127.0.0.1 --port 8000
```

### C. Docker 없이 경량 파일 DB(SQLite)로 즉시 실행할 때
```powershell
$env:DATABASE_URL="sqlite+aiosqlite:///./controller/data/hub.db"
uv run uvicorn controller.main:app --host 127.0.0.1 --port 8000
```

### D. PostgreSQL Docker 컨테이너 관리
```powershell
# 컨테이너 실행 상태 확인
docker compose ps

# DB 로그 실시간 확인
docker compose logs -f postgres

# 컨테이너 중지 (데이터 볼륨 pgdata 유지)
docker compose down
```

---

## 3. 로컬 Mock Agent 실행 (VM 없이 기능 테스트할 때)

비-리눅스(Windows/macOS)에서 실행하면 자동으로 인메모리 시뮬레이터(`mock-simulator`) 모드로 동작합니다.  
Controller와 별도의 새 PowerShell 터미널을 열어 실행하세요.

```powershell
# 기본 시뮬레이터 실행 (기본 토큰: dev-agent-token)
uv run uvicorn agent.main:app --host 127.0.0.1 --port 8754
```

### 환경변수를 지정하여 실행할 때
```powershell
$env:AGENT_TOKEN="dev-agent-token"
$env:PROTECTED_PORTS="22,8754"
$env:AGENT_REQUIRE_ENCRYPTED="1"   # 평문 제어 요청 차단, 암호화 패킷만 허용
uv run uvicorn agent.main:app --host 127.0.0.1 --port 8754
```

---

## 4. Rocky Linux 9.x 실서버 Agent 배포 및 관리

### A. Windows에서 원클릭 업로드 및 배포 (`upload_agent.ps1`)
서버에 `uv`가 없어도 자동으로 설치하고, `/opt/linux-access-control-hub/.python` 격리 환경(SELinux 호환) 구성부터 `systemd` 재시작·헬스체크까지 한 번에 수행합니다.

```powershell
# 1) 온라인 실서버 배포 (SSH 비밀번호 1회 입력)
powershell -ExecutionPolicy Bypass -File .\deploy\upload_agent.ps1 -ServerIp <SERVER_IP>

# 2) 폐쇄망(오프라인) 실서버 배포 (로컬에서 Linux용 .whl 번들 생성 후 함께 업로드)
powershell -ExecutionPolicy Bypass -File .\deploy\upload_agent.ps1 -ServerIp <SERVER_IP> -Offline

# 3) SSH 계정이나 포트가 기본값(root / 22)과 다를 때
powershell -ExecutionPolicy Bypass -File .\deploy\upload_agent.ps1 -ServerIp <SERVER_IP> -User rocky -SshPort 2222
```

*(오프라인 휠 번들만 미리 생성해 두고 싶을 때)*
```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\build_bundle.ps1
```

### B. 실서버(Rocky Linux) 최초 1회 필수 설정 (SSH 접속 후 실행)
```bash
# 1) SELinux 포트 관리(semanage) 필수 패키지 설치
sudo dnf install -y policycoreutils-python-utils

# 2) 서비스 토큰 변경 (/etc/systemd/system/linux-access-agent.service 내 AGENT_TOKEN 수정)
sudo vi /etc/systemd/system/linux-access-agent.service
sudo systemctl daemon-reload
sudo systemctl restart linux-access-agent

# 3-A) 방화벽에서 접근제어 PC IP만 Agent 포트(8754) 허용 (권장)
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="<접근제어PC_IP>" port port="8754" protocol="tcp" accept'
sudo firewall-cmd --reload

# 3-B) 또는 일반 포트 개방 시
sudo firewall-cmd --permanent --add-port=8754/tcp
sudo firewall-cmd --reload
```

### C. 실서버 Agent 상태 및 로그 점검 명령어
```bash
# systemd 서비스 상태 확인 / 재시작 / 중지
sudo systemctl status linux-access-agent
sudo systemctl restart linux-access-agent
sudo systemctl stop linux-access-agent

# systemd 실시간 실행 로그 확인
sudo journalctl -u linux-access-agent -n 50 --no-pager
sudo journalctl -u linux-access-agent -f

# Agent 암호화 전용 로그 파일 확인 (평문 미노출 확인용)
cat /opt/linux-access-control-hub/agent/logs/agent_encrypted.jsonl
tail -n 30 /opt/linux-access-control-hub/agent/logs/agent.log
```

### D. Windows에서 실서버 Agent 연결 진단
```powershell
# 헬스체크 (인증 불필요)
curl.exe -i -s -m 5 http://<SERVER_IP>:8754/health

# 상태 조회 API 테스트 (토큰 인증 확인)
curl.exe -i -s -m 15 -H "X-Agent-Token: <설정한_토큰>" http://<SERVER_IP>:8754/api/v1/status
```

---

## 5. 테스트 및 코드 검증 명령어

코드를 수정한 뒤 정상 동작 여부를 확인할 때 실행합니다.

```powershell
# 공식 검증 스크립트 실행 (uv Python 버전 확인 + 전체 pytest 실행)
powershell -ExecutionPolicy Bypass -File .\.agents\skills\verify-and-test\scripts\verify.ps1

# pytest 직접 실행
uv run pytest -v

# 프론트엔드 JavaScript 문법 오류 검사
node --check controller/static/app.js
```

---

## 6. 주요 환경변수 요약

| 구분 | 환경변수명 | 기본값 | 설명 |
|---|---|---|---|
| **Controller** | `DATABASE_URL` | `postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/linux_access_hub` | SQLAlchemy 비동기 DB 접속 URL |
| **Controller** | `PROCESS_MONITOR_ENABLED` | `1` | 백그라운드 프로세스 주기적 폴링 활성화 여부 (`0`이면 비활성) |
| **Controller** | `CONTROLLER_LOG_FILE` | `controller/data/controller.log` | Controller 평문 아웃바운드 로그 저장 경로 |
| **Agent** | `AGENT_TOKEN` | `dev-agent-token` | 인증 헤더(`X-Agent-Token`) 및 AES-256-GCM 암호화 키 파생 시크릿 |
| **Agent** | `PROTECTED_PORTS` | `22` | Agent 측 삭제 차단 고정 보호 포트 (쉼표 구분, 예: `22,8754`) |
| **Agent** | `AGENT_REQUIRE_ENCRYPTED` | `0` | `1`로 설정 시 암호화되지 않은 평문 제어 요청 전면 거부 |
| **Agent** | `AGENT_MOCK` | `auto` | `1`: 강제 시뮬레이터, `0`: 강제 실서버 모드, `auto`: OS 자동 판별 |
| **Agent** | `AGENT_LOG_FILE` | `agent/logs/agent.log` | Agent 일반 회전 로그 파일 경로 |
| **Agent** | `AGENT_ENCRYPTED_LOG_FILE` | `agent/logs/agent_encrypted.jsonl` | Agent 암호문(`enc`) 전용 로그 저장 경로 |
