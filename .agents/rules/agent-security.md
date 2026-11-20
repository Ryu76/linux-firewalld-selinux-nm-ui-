# Agent Security & Validation Rules

- `agent/main.py`의 모든 제어 엔드포인트(`/api/v1/*`)는 `Depends(verify_token)`을 통해 `X-Agent-Token` 헤더를 검증해야 합니다.
- `agent/schemas.py`에서 IPv4/CIDR(`IP_OR_CIDR_RE`) 및 식별자(`SAFE_NAME_RE`) 검증을 통과하지 못한 입력은 `422 Unprocessable Entity`로 거부합니다.
- `agent/linux_backend.py`는 반드시 리스트 인자(`shell=False`)와 `timeout`을 지정해 `subprocess.run`을 호출합니다.
