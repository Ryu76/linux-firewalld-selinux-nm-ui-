---
name: deploy-check
description: Rocky Linux 9.x 실서버에 Agent를 배포하거나 연결 오류(502, 타임아웃, 인증 실패)를 점검할 때 사용합니다.
---

# Deploy Check Skill

1. `references/rocky9-checklist.md`를 읽어 배포 및 방화벽/SELinux/systemd 점검 항목을 확인합니다.
2. 폐쇄망(오프라인) 서버 배포 시 로컬에서 `deploy/build_bundle.ps1`을 실행해 `uv.lock` 기반 Linux용 `.whl` 번들(`deploy/wheels/`)을 준비합니다.
3. `pyproject.toml`, `uv.lock`, `.python-version`, `agent/`, `deploy/`를 대상 서버(`/opt/linux-access-control-hub/`)에 전송한 뒤 서버에서 `sudo bash deploy/deploy_agent.sh`를 실행해 `uv`로 `.venv` 업데이트 및 `linux-access-agent` 재시작을 수행합니다.
4. Windows 호스트에서 `/health` 및 `/api/v1/status` 응답을 확인해 연결 정상 여부를 검증합니다.
