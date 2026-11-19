# 리눅스 서버 접근 제어 및 네트워크 관리 정리

이 문서는 RHEL / Rocky Linux / CentOS 계열 서버에서 외부 커넥션을 통제하고 네트워크를 관리하는 핵심 도구(`firewalld`, `SELinux`, `nmcli`, `nmtui`)와 패킷 제어 흐름을 정리한 가이드입니다.

---

## 1. 외부 커넥션 제어 구조 (서버 내부 흐름)

보안 장비나 스위치 차단을 제외하고, 외부 패킷이 리눅스 서버에 도착했을 때 서버 내부에서 통제되는 계층 순서입니다.

```text
[외부 요청 패킷 도착]
        │
        ▼
① NIC & 커널 네트워크 파라미터 (sysctl)
   └─ 스푸핑 검증(rp_filter), SYN Flood 방어(tcp_syncookies) 등
        │
        ▼
② 커널 방화벽 (Netfilter: firewalld / nftables / iptables)
   └─ Zone 및 IP·포트·서비스·ICMP 규칙 검사 (DROP / REJECT / ACCEPT)
        │
        ▼
③ 소켓 바인딩 (Listen 주소 & 포트 확인)
   └─ 데몬이 0.0.0.0:포트 로 열려있는지 확인 (127.0.0.1이면 외부 차단)
        │
        ▼
④ SELinux (커널 MAC 보안 모듈)
   └─ 해당 데몬(프로세스)의 포트 사용 및 네트워크 접근 권한 검사
        │
        ▼
⑤ PAM / 호스트·계정 기반 제어
   └─ 접속 허용 IP/계정 검증 (/etc/security/access.conf 등)
        │
        ▼
⑥ 애플리케이션(데몬) 자체 제어 (+ Fail2ban 동적 차단)
   └─ sshd_config, Nginx allow/deny, DB 접근 제어 등
```

---

## 2. 리눅스 방화벽 (`firewalld`)

- **Zone**: 네트워크 신뢰도에 따른 규칙 집합 (`public`, `trusted`, `dmz`, `drop`, `internal` 등)
- **Runtime vs Permanent**:
  - `Runtime`: 즉시 적용되지만 재부팅/리로드 시 사라짐
  - `Permanent` (`--permanent`): 설정 파일에 영구 저장되며 `--reload` 후 반영

```bash
firewall-cmd --state
firewall-cmd --get-default-zone
firewall-cmd --list-all-zones
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-port=8080/tcp
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.10.0/24" port port="22" protocol="tcp" accept'
firewall-cmd --reload
```

---

## 3. SELinux (Security-Enhanced Linux)

임의적 접근 제어(DAC)를 보완하는 **강제적 접근 제어(MAC)** 모듈입니다.

| 모드 | 설명 |
| :--- | :--- |
| **Enforcing** | 정책 위반 시 **차단**하고 로그(`/var/log/audit/audit.log`) 기록 |
| **Permissive** | 차단하지 않고 **경고 로그만 기록** (진단용) |
| **Disabled** | SELinux 비활성화 |

```bash
getenforce
setenforce 0                                  # Permissive 임시 전환 (1: Enforcing)
semanage port -a -t http_port_t -p tcp 8080   # 비표준 포트 허용
setsebool -P httpd_can_network_connect on     # Boolean 영구 변경
```

---

## 4. 네트워크 관리 (`nmcli` & `nmtui`)

### `nmcli` (CLI — 스크립트/자동화용)
```bash
nmcli dev status
nmcli con show
nmcli con mod "ens160" ipv4.addresses 192.168.1.50/24 ipv4.gateway 192.168.1.1 ipv4.dns 8.8.8.8 ipv4.method manual
nmcli con up "ens160"
```

### `nmtui` (TUI — 메뉴 기반 수동 설정용)
- 터미널에서 `nmtui` 실행 → `Edit a connection` / `Activate a connection` / `Set system hostname` 메뉴로 직관적인 설정 가능

---

## 5. 외부 접속 불가 시 실무 점검 순서
1. `ss -tulnp`: 데몬이 `0.0.0.0` 또는 서비스 IP로 Listen 중인가?
2. `firewall-cmd --list-all`: 포트/서비스 또는 출발지 IP가 방화벽에서 허용되었는가?
3. `getenforce` / `ausearch -m avc`: SELinux가 비표준 포트나 프로세스 통신을 차단하고 있지 않은가?
4. 데몬 설정 및 로그(`/var/log/secure` 등): 애플리케이션 자체 IP 제한(`sshd_config`, `pg_hba.conf` 등)에 걸리지 않았는가?
