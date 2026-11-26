---
name: verify-and-test
description: 백엔드(Agent/Controller) 또는 프론트엔드 코드를 수정한 뒤 uv 가상환경(.venv)에서 전체 pytest 테스트를 수행할 때 사용합니다.
---

# Verify and Test Skill

코드 변경 후 아래 절차로 검증합니다.

1. **검증 스크립트 실행**:
   - `scripts/verify.ps1`을 실행해 `uv` 환경(Python 3.14+)에서 `pytest` 전체 통과 여부를 확인합니다.
2. **직접 실행 명령어** (필요 시):
   ```powershell
   uv run pytest -v
   ```
3. **완료 조건**:
   - `tests/test_hub.py`의 모든 테스트가 `PASSED`여야 합니다.
   - `agent/` 수정이 포함된 경우, Rocky Linux 9.x 실서버 재배포(`deploy/deploy_agent.sh`) 안내를 함께 제공합니다.
