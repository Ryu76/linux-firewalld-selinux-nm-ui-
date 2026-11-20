---
name: deploy-check
description: Rocky Linux 9.x 실서버에 Agent를 배포하거나 연결 오류(502, 타임아웃, 인증 실패)를 점검할 때 사용합니다.
---

# Deploy Check Skill

1. `references/rocky9-checklist.md`를 읽어 배포 및 방화벽/SELinux/systemd 점검 항목을 확인합니다.
2. `agent/` 디렉터리가 수정된 경우 `scp -r`로 대상 서버(`/opt/linux-access-control-hub/`)에 반영하고 `sudo systemctl restart linux-access-agent`를 안내합니다.
3. Windows 호스트에서 `/health` 및 `/api/v1/status` 응답을 확인해 연결 정상 여부를 검증합니다.
