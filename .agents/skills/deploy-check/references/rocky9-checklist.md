# Rocky Linux 9.x Agent 배포 및 점검 체크리스트

## 1. 필수 패키지 설치
```bash
sudo dnf install -y python3-pip policycoreutils-python-utils
sudo pip3 install fastapi uvicorn pydantic
```
- `policycoreutils-python-utils`: `semanage` 명령 실행에 필수

## 2. Agent 배포 및 서비스 시작
```bash
scp -r agent root@<SERVER_IP>:/opt/linux-access-control-hub/
sudo cp /opt/linux-access-control-hub/agent/agent.service /etc/systemd/system/linux-access-agent.service
# Environment="AGENT_TOKEN=..." 값 수정 후:
sudo systemctl daemon-reload
sudo systemctl enable --now linux-access-agent
```

## 3. 방화벽 및 연결 확인
```bash
sudo firewall-cmd --permanent --add-port=9100/tcp   # 또는 사용하는 Agent 포트
sudo firewall-cmd --reload
ss -tulnp | grep 9100
```

## 4. Windows에서 헬스체크
```powershell
curl.exe -i -s -m 5 http://<SERVER_IP>:9100/health
curl.exe -i -s -m 20 -H "X-Agent-Token: <TOKEN>" http://<SERVER_IP>:9100/api/v1/status
```
