from datetime import datetime, timezone
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

JSONType = JSONB().with_variant(JSON(), "sqlite")
BigIntPKType = BigInteger().with_variant(Integer(), "sqlite")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Server(Base):
    """Managed Linux Agent server registry."""

    __tablename__ = "servers"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    url: Mapped[str] = mapped_column(String(255), nullable=False)
    token: Mapped[str] = mapped_column(String(255), nullable=False)
    group: Mapped[str] = mapped_column(String(40), nullable=False, default="default", index=True)
    protected_ports: Mapped[list[int]] = mapped_column(JSONType, nullable=False, default=lambda: [22])
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class AuditLog(Base):
    """Security & control action audit log."""

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_server_timestamp", "server_id", "timestamp"),
        Index("ix_audit_action_timestamp", "action", "timestamp"),
    )

    id: Mapped[int] = mapped_column(BigIntPKType, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    server_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    server_name: Mapped[str] = mapped_column(String(80), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")


class WatchedProcess(Base):
    """Per-server watched process configuration and recovery policy."""

    __tablename__ = "watched_processes"
    __table_args__ = (
        Index("ix_watched_proc_server_enabled", "server_id", "enabled"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    server_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    process_name: Mapped[str] = mapped_column(String(64), nullable=False)
    check_type: Mapped[str] = mapped_column(String(20), nullable=False, default="process")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    save_log: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    recovery_action: Mapped[str] = mapped_column(String(30), nullable=False, default="alert_only")
    recovery_target: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    check_interval_sec: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    last_status: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_action_detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class ProcessLog(Base):
    """Per-process execution/health log (recorded only when save_log=True)."""

    __tablename__ = "process_logs"
    __table_args__ = (
        Index("ix_proc_log_server_timestamp", "server_id", "timestamp"),
        Index("ix_proc_log_process_timestamp", "process_id", "timestamp"),
    )

    id: Mapped[int] = mapped_column(BigIntPKType, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    server_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    server_name: Mapped[str] = mapped_column(String(80), nullable=False)
    process_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    process_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    action_taken: Mapped[str] = mapped_column(String(30), nullable=False, default="none")
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
