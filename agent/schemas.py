import re
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator

IP_OR_CIDR_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:/(?:3[0-2]|[12]?\d))?$"
)
SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,64}$")


def validate_ip_or_cidr(value: str) -> str:
    if not IP_OR_CIDR_RE.match(value):
        raise ValueError(f"Invalid IPv4 address or CIDR: {value}")
    return value


def validate_safe_name(value: str) -> str:
    if not SAFE_NAME_RE.match(value):
        raise ValueError(f"Invalid identifier: {value}")
    return value


class FirewallPortRequest(BaseModel):
    zone: str = Field(default="public", description="firewalld zone name")
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    action: Literal["add", "remove"] = "add"
    permanent: bool = True

    @field_validator("zone")
    @classmethod
    def check_zone(cls, v: str) -> str:
        return validate_safe_name(v)


class FirewallServiceRequest(BaseModel):
    zone: str = Field(default="public")
    service: str
    action: Literal["add", "remove"] = "add"
    permanent: bool = True

    @field_validator("zone", "service")
    @classmethod
    def check_names(cls, v: str) -> str:
        return validate_safe_name(v)


class FirewallMasqueradeRequest(BaseModel):
    zone: str = Field(default="public")
    enabled: bool = True
    permanent: bool = True

    @field_validator("zone")
    @classmethod
    def check_zone(cls, v: str) -> str:
        return validate_safe_name(v)


class FirewallForwardPortRequest(BaseModel):
    zone: str = Field(default="public")
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    to_port: int = Field(ge=1, le=65535)
    to_addr: Optional[str] = Field(default=None)
    action: Literal["add", "remove"] = "add"
    permanent: bool = True

    @field_validator("zone")
    @classmethod
    def check_zone(cls, v: str) -> str:
        return validate_safe_name(v)

    @field_validator("to_addr")
    @classmethod
    def check_addr(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != "":
            validated = validate_ip_or_cidr(v)
            if "/" in validated:
                raise ValueError("Forward target address must be a single IP")
            return validated
        return v


class FirewallSourceRequest(BaseModel):
    zone: str = Field(default="public")
    source: str
    action: Literal["add", "remove"] = "add"
    permanent: bool = True

    @field_validator("zone")
    @classmethod
    def check_zone(cls, v: str) -> str:
        return validate_safe_name(v)

    @field_validator("source")
    @classmethod
    def check_source(cls, v: str) -> str:
        return validate_ip_or_cidr(v)


class FirewallInterfaceRequest(BaseModel):
    zone: str = Field(default="public")
    interface: str
    action: Literal["change", "remove"] = "change"
    permanent: bool = True

    @field_validator("zone", "interface")
    @classmethod
    def check_names(cls, v: str) -> str:
        return validate_safe_name(v)


class FirewallIcmpRequest(BaseModel):
    zone: str = Field(default="public")
    icmp_type: str
    action: Literal["add", "remove"] = "add"
    permanent: bool = True

    @field_validator("zone", "icmp_type")
    @classmethod
    def check_names(cls, v: str) -> str:
        return validate_safe_name(v)


class FirewallControlRequest(BaseModel):
    command: Literal["reload", "runtime-to-permanent", "set-default-zone", "panic-on", "panic-off"]
    zone: Optional[str] = None

    @field_validator("zone")
    @classmethod
    def check_zone(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != "":
            return validate_safe_name(v)
        return v


class FirewallRichRuleRequest(BaseModel):
    zone: str = Field(default="public")
    source_ip: str = Field(description="Source IPv4 or CIDR, e.g. 192.168.1.10 or 10.0.0.0/24")
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    rule_action: Literal["accept", "drop", "reject"] = "accept"
    action: Literal["add", "remove"] = "add"
    permanent: bool = True

    @field_validator("zone")
    @classmethod
    def check_zone(cls, v: str) -> str:
        return validate_safe_name(v)

    @field_validator("source_ip")
    @classmethod
    def check_ip(cls, v: str) -> str:
        return validate_ip_or_cidr(v)


class SELinuxModeRequest(BaseModel):
    mode: Literal["Enforcing", "Permissive"]


class SELinuxPortRequest(BaseModel):
    port_type: str = Field(default="http_port_t", description="SELinux port type, e.g. http_port_t")
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    action: Literal["add", "delete"] = "add"

    @field_validator("port_type")
    @classmethod
    def check_type(cls, v: str) -> str:
        return validate_safe_name(v)


class SELinuxBooleanRequest(BaseModel):
    name: str
    value: bool
    persistent: bool = True

    @field_validator("name")
    @classmethod
    def check_name(cls, v: str) -> str:
        return validate_safe_name(v)


class NetworkIPv4Request(BaseModel):
    connection: str = Field(description="NetworkManager connection name, e.g. ens160")
    method: Literal["manual", "auto"] = "manual"
    address: Optional[str] = Field(default=None, description="IPv4/CIDR, e.g. 192.168.1.50/24")
    gateway: Optional[str] = Field(default=None, description="IPv4 gateway, e.g. 192.168.1.1")
    dns: Optional[str] = Field(default=None, description="DNS IPv4, e.g. 8.8.8.8")

    @field_validator("connection")
    @classmethod
    def check_con(cls, v: str) -> str:
        return validate_safe_name(v)

    @field_validator("address")
    @classmethod
    def check_addr(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != "":
            return validate_ip_or_cidr(v)
        return v

    @field_validator("gateway", "dns")
    @classmethod
    def check_single_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v != "":
            validated = validate_ip_or_cidr(v)
            if "/" in validated:
                raise ValueError("Gateway and DNS must be a single IP without CIDR prefix")
            return validated
        return v
