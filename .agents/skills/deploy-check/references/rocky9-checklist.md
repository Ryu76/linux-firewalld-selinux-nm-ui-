# Rocky Linux 9.x Agent 배포 및 점검 체크리스트

## 1. 필수 도구 설치
```bash
sudo dnf install -y policycoreutils-python-utils
curl -LsSf https://astral.sh/uv/install.sh | sh
```
- `policycoreutils-python-utils`: `semanage` 명령 실행에 필수
- `uv`: OS 기본 Python 3.9와 분리된 Python 3.14+ `.venv` 구성에 사용

## 2. Agent 배포 및 서비스 시작
```bash
# 로컬(Windows)에서 폐쇄망 배포 시 휠 번들 생성:
# .\deploy\build_bundle.ps1

scp -r pyproject.toml uv.lock .python-version agent deploy root@<SERVER_IP>:/opt/linux-access-control-hub/
# 서버에서 (최초 배포 시 /etc/systemd/system/linux-access-agent.service 내 AGENT_TOKEN 수정):
sudo bash /opt/linux-access-control-hub/deploy/deploy_agent.sh
```

## 3. 방화벽 및 연결 확인
```bash
sudo firewall-cmd --permanent --add-port=8754/tcp   # 또는 사용하는 Agent 포트
sudo firewall-cmd --reload
ss -tulnp | grep 8754
```

## 4. Windows에서 헬스체크
```powershell
curl.exe -i -s -m 5 http://<SERVER_IP>:8754/health
curl.exe -i -s -m 20 -H "X-Agent-Token: <TOKEN>" http://<SERVER_IP>:8754/api/v1/status
```
