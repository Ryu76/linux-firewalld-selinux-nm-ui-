#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/linux-access-control-hub}"
VENV_DIR="${APP_DIR}/.venv"
UV_PYTHON_DIR="${APP_DIR}/.python"
SERVICE_NAME="linux-access-agent"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

export PATH="/usr/local/bin:/root/.local/bin:${HOME:-/root}/.local/bin:${HOME:-/root}/.cargo/bin:${PATH}"
export UV_PYTHON_INSTALL_DIR="${UV_PYTHON_DIR}"
export UV_CACHE_DIR="${APP_DIR}/.uv-cache"

if ! command -v uv >/dev/null 2>&1; then
    if [ -f "${APP_DIR}/deploy/bin/uv" ]; then
        echo "[0/3] Installing bundled offline 'uv' binary to /usr/local/bin/uv..."
        install -m 0755 "${APP_DIR}/deploy/bin/uv" /usr/local/bin/uv
    else
        echo "[0/3] 'uv' not found on server. Auto-installing uv to /usr/local/bin..."
        if command -v curl >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh
        elif command -v wget >/dev/null 2>&1; then
            wget -qO- https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="/usr/local/bin" sh
        else
            echo "[ERROR] Neither 'uv' nor curl/wget found. Copy uv binary to ${APP_DIR}/deploy/bin/uv." >&2
            exit 1
        fi
    fi
fi

echo "Using uv: $(command -v uv) ($(uv --version))"
cd "${APP_DIR}"

# Clean any Windows __pycache__ uploaded via scp
find "${APP_DIR}/agent" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# If existing .venv points to /root/.local (blocked by SELinux under systemd), recreate it under APP_DIR
if [ -L "${VENV_DIR}/bin/python" ]; then
    LINK_TARGET="$(readlink -f "${VENV_DIR}/bin/python" || true)"
    if [[ "${LINK_TARGET}" == /root/* ]]; then
        echo "  -> Recreating .venv under ${APP_DIR} for SELinux systemd compatibility..."
        rm -rf "${VENV_DIR}"
    fi
fi

echo "[1/3] Syncing Python 3.14 & agent packages with uv..."
if [ -d "${APP_DIR}/deploy/wheels" ] && [ -n "$(ls -A "${APP_DIR}/deploy/wheels" 2>/dev/null)" ]; then
    echo "  -> Offline mode: using bundled wheels in ${APP_DIR}/deploy/wheels"
    uv venv --python 3.14 "${VENV_DIR}" --allow-existing
    uv pip install --python "${VENV_DIR}/bin/python" --no-index --find-links="${APP_DIR}/deploy/wheels" -r "${APP_DIR}/deploy/requirements-agent.lock.txt"
else
    echo "  -> Online mode: uv sync --extra agent --no-dev --frozen"
    uv sync --extra agent --no-dev --frozen
fi

# Ensure SELinux allows systemd (init_t) to execute the isolated Python runtime
if command -v chcon >/dev/null 2>&1; then
    chcon -R -t bin_t "${UV_PYTHON_DIR}" >/dev/null 2>&1 || true
    chcon -R -t bin_t "${VENV_DIR}/bin" >/dev/null 2>&1 || true
fi

echo "[2/3] Updating systemd service..."
AGENT_PORT="${AGENT_PORT:-8754}"
if [ ! -f "${SERVICE_FILE}" ]; then
    cp "${APP_DIR}/agent/agent.service" "${SERVICE_FILE}"
    sed -i "s|^ExecStart=.*|ExecStart=${VENV_DIR}/bin/python -m uvicorn agent.main:app --host 0.0.0.0 --port ${AGENT_PORT}|" "${SERVICE_FILE}"
    echo "  -> Installed new ${SERVICE_FILE} on port ${AGENT_PORT} (remember to set AGENT_TOKEN!)"
else
    sed -i "s|^ExecStart=.*|ExecStart=${VENV_DIR}/bin/python -m uvicorn agent.main:app --host 0.0.0.0 --port ${AGENT_PORT}|" "${SERVICE_FILE}"
    echo "  -> Updated ExecStart to ${VENV_DIR}/bin/python on port ${AGENT_PORT} (preserving AGENT_TOKEN)"
fi

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
systemctl restart "${SERVICE_NAME}"

echo "[3/3] Verifying agent health on port ${AGENT_PORT}..."
HEALTH_OK=0
for _ in $(seq 1 10); do
    if curl -sf "http://127.0.0.1:${AGENT_PORT}/health"; then
        HEALTH_OK=1
        break
    fi
    sleep 1
done

if [ "${HEALTH_OK}" -eq 1 ]; then
    echo ""
    echo "[OK] ${SERVICE_NAME} deployed and healthy on port ${AGENT_PORT}."
else
    echo ""
    echo "[ERROR] Health check failed. Service logs:" >&2
    journalctl -u "${SERVICE_NAME}" -n 40 --no-pager >&2 || true
    exit 1
fi
