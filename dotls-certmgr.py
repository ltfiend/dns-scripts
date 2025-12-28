#!/usr/bin/env python3
"""dotls_certmgr.py

Maintains TLS cert/key material for BIND DNS-over-TLS (DoT) using Let's Encrypt
via DNS-01 challenge (Certbot). Designed to be run daily (cron/systemd timer).

Key behaviors:
- Checks current cert expiry.
- Renews when remaining lifetime is below threshold (or forced).
- Copies the new fullchain/privkey into an archive directory with timestamped
  versions.
- Atomically updates symlinks that BIND references in named.conf.
- Optionally runs a reload command (rndc reconfig / systemctl reload named).

First-run friendly:
- If /etc/letsencrypt/live/<name>/ doesn't exist yet, the script runs certbot and
  then *discovers* the actual Certificate Path / Private Key Path via
  `certbot certificates`, instead of assuming the live directory already exists.

Config format: TOML (Python 3.11+ includes tomllib).
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import logging
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib  # Python 3.11+
except ImportError:
    print("ERROR: Python 3.11+ required (tomllib missing).", file=sys.stderr)
    sys.exit(2)


# -----------------------------
# Utilities
# -----------------------------

def run(cmd: list[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    logging.debug("Running: %s", " ".join(shlex.quote(c) for c in cmd))
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def atomic_symlink_update(link_path: Path, target_path: Path) -> None:
    link_path.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = link_path.with_name(link_path.name + ".tmp")
    try:
        tmp_path.unlink()
    except FileNotFoundError:
        pass

    os.symlink(str(target_path), str(tmp_path))
    os.replace(str(tmp_path), str(link_path))  # atomic replace on same filesystem


def read_symlink_target(path: Path) -> Path | None:
    if not path.exists() and not path.is_symlink():
        return None
    if not path.is_symlink():
        return path.resolve()
    try:
        return Path(os.readlink(path))
    except OSError:
        return None


def ensure_permissions(path: Path, *, mode: int | None, owner: str | None, group: str | None) -> None:
    if mode is not None:
        os.chmod(path, mode)

    if owner is None and group is None:
        return

    import pwd
    import grp

    uid = -1
    gid = -1

    if owner is not None:
        uid = pwd.getpwnam(owner).pw_uid
    if group is not None:
        gid = grp.getgrnam(group).gr_gid

    os.chown(path, uid, gid)


def parse_notafter_openssl(openssl_bin: str, cert_path: Path) -> dt.datetime:
    """Uses: openssl x509 -in CERT -noout -enddate"""
    cp = run([openssl_bin, "x509", "-in", str(cert_path), "-noout", "-enddate"])
    out = (cp.stdout or "").strip()
    if "notAfter=" not in out:
        raise ValueError(f"Unexpected openssl output: {out!r}")

    end = out.split("notAfter=", 1)[1].strip()
    if end.endswith(" GMT"):
        end = end[:-4].strip()
    return dt.datetime.strptime(end, "%b %d %H:%M:%S %Y").replace(tzinfo=dt.timezone.utc)


def utcnow() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)


def timestamp_slug(now: dt.datetime | None = None) -> str:
    now = now or utcnow()
    return now.strftime("%Y%m%dT%H%M%SZ")


# -----------------------------
# Config
# -----------------------------

@dataclass
class GlobalConfig:
    certbot_bin: str = "/usr/bin/certbot"
    openssl_bin: str = "/usr/bin/openssl"
    lock_file: Path = Path("/run/dotls-certmgr.lock")
    archive_dir: Path = Path("/etc/bind/dotls/archive")
    log_file: Path | None = None
    default_reload_cmd: list[str] | None = None


@dataclass
class CertConfig:
    name: str
    domain: str
    email: str
    cert_symlink: Path
    key_symlink: Path

    renew_if_less_than_days: int = 21
    force_renew_every_days: int | None = None

    certbot_args: list[str] | None = None
    cert_name: str | None = None

    cert_mode: int | None = 0o644
    key_mode: int | None = 0o640
    owner: str | None = None
    group: str | None = None

    reload_cmd: list[str] | None = None


def load_config(path: Path) -> tuple[GlobalConfig, list[CertConfig]]:
    raw = tomllib.loads(path.read_text(encoding="utf-8"))

    g_raw = raw.get("global", {}) or {}
    global_cfg = GlobalConfig(
        certbot_bin=str(g_raw.get("certbot_bin", "/usr/bin/certbot")),
        openssl_bin=str(g_raw.get("openssl_bin", "/usr/bin/openssl")),
        lock_file=Path(g_raw.get("lock_file", "/run/dotls-certmgr.lock")),
        archive_dir=Path(g_raw.get("archive_dir", "/etc/bind/dotls/archive")),
        log_file=Path(g_raw["log_file"]) if "log_file" in g_raw and g_raw["log_file"] else None,
        default_reload_cmd=g_raw.get("default_reload_cmd"),
    )

    certs_raw = raw.get("certs", [])
    if not isinstance(certs_raw, list) or not certs_raw:
        raise ValueError("Config must include at least one [[certs]] entry.")

    certs: list[CertConfig] = []
    for c in certs_raw:
        certs.append(
            CertConfig(
                name=c["name"],
                domain=c["domain"],
                email=c["email"],
                cert_symlink=Path(c["cert_symlink"]),
                key_symlink=Path(c["key_symlink"]),
                renew_if_less_than_days=int(c.get("renew_if_less_than_days", 21)),
                force_renew_every_days=(int(c["force_renew_every_days"]) if "force_renew_every_days" in c else None),
                certbot_args=c.get("certbot_args"),
                cert_name=c.get("cert_name"),
                cert_mode=int(c["cert_mode"], 8) if isinstance(c.get("cert_mode"), str) else c.get("cert_mode", 0o644),
                key_mode=int(c["key_mode"], 8) if isinstance(c.get("key_mode"), str) else c.get("key_mode", 0o640),
                owner=c.get("owner"),
                group=c.get("group"),
                reload_cmd=c.get("reload_cmd"),
            )
        )

    return global_cfg, certs


# -----------------------------
# Core logic
# -----------------------------

def remaining_days(openssl_bin: str, cert_path: Path) -> int:
    exp = parse_notafter_openssl(openssl_bin, cert_path)
    delta = exp - utcnow()
    return max(0, int(delta.total_seconds() // 86400))


def should_renew(*, openssl_bin: str, cert_path: Path | None, cfg: CertConfig, now: dt.datetime) -> tuple[bool, str]:
    if cert_path is None or not cert_path.exists():
        return True, "no current cert found"

    try:
        days_left = remaining_days(openssl_bin, cert_path)
    except Exception as e:
        return True, f"failed to parse current cert expiry ({e})"

    if days_left < cfg.renew_if_less_than_days:
        return True, f"expires soon ({days_left} days left < {cfg.renew_if_less_than_days})"

    if cfg.force_renew_every_days is not None:
        age_days = int((now - dt.datetime.fromtimestamp(cert_path.stat().st_mtime, tz=dt.timezone.utc)).total_seconds() // 86400)
        if age_days >= cfg.force_renew_every_days:
            return True, f"forced rotation ({age_days} days old >= {cfg.force_renew_every_days})"

    return False, "sufficient validity remaining"


def build_certbot_cmd(global_cfg: GlobalConfig, cert_cfg: CertConfig) -> list[str]:
    if not cert_cfg.certbot_args:
        base = [
            "certonly",
            "--non-interactive",
            "--agree-tos",
            "--preferred-challenges", "dns-01",
            "--dns-rfc2136",
            "--dns-rfc2136-credentials", "/etc/letsencrypt/rfc2136.ini",
            "--dns-rfc2136-propagation-seconds", "30",
            "--email", "{email}",
            "-d", "{domain}",
        ]
        if cert_cfg.cert_name:
            base += ["--cert-name", "{cert_name}"]
        return [global_cfg.certbot_bin, *base]

    def expand(s: str) -> str:
        return (
            s.replace("{domain}", cert_cfg.domain)
             .replace("{email}", cert_cfg.email)
             .replace("{cert_name}", cert_cfg.cert_name or cert_cfg.domain)
        )

    args = [expand(a) for a in cert_cfg.certbot_args]
    return [global_cfg.certbot_bin, *args]


def locate_letsencrypt_live_paths(cert_cfg: CertConfig) -> tuple[Path, Path]:
    live_name = cert_cfg.cert_name or cert_cfg.domain
    live_dir = Path("/etc/letsencrypt/live") / live_name
    return live_dir / "fullchain.pem", live_dir / "privkey.pem"


def discover_letsencrypt_paths(global_cfg: GlobalConfig, cert_cfg: CertConfig) -> tuple[Path, Path]:
    """Robust discovery of actual cert/key paths after certbot runs."""
    fc, pk = locate_letsencrypt_live_paths(cert_cfg)
    if fc.exists() and pk.exists():
        return fc, pk

    cp = run([global_cfg.certbot_bin, "certificates"], check=False, capture=True)
    text = (cp.stdout or "") + "\n" + (cp.stderr or "")
    if not text.strip():
        raise FileNotFoundError(
            f"[{cert_cfg.name}] Unable to discover LE paths: `certbot certificates` returned no output."
        )

    blocks = re.split(r"(?m)^\s*Certificate Name:\s*", text)
    candidates: list[dict[str, str]] = []

    for b in blocks[1:]:
        lines = b.splitlines()
        if not lines:
            continue
        cert_name = lines[0].strip()

        domains = ""
        cert_path = ""
        privkey_path = ""

        for line in lines[1:]:
            line = line.strip()
            if line.startswith("Domains:"):
                domains = line.split("Domains:", 1)[1].strip()
            elif line.startswith("Certificate Path:"):
                cert_path = line.split("Certificate Path:", 1)[1].strip()
            elif line.startswith("Private Key Path:"):
                privkey_path = line.split("Private Key Path:", 1)[1].strip()

        if cert_path and privkey_path:
            candidates.append(
                {
                    "cert_name": cert_name,
                    "domains": domains,
                    "cert_path": cert_path,
                    "privkey_path": privkey_path,
                }
            )

    preferred_name = cert_cfg.cert_name
    chosen: dict[str, str] | None = None

    if preferred_name:
        for c in candidates:
            if c["cert_name"] == preferred_name:
                chosen = c
                break

    if chosen is None:
        needle = cert_cfg.domain.strip()
        for c in candidates:
            doms = c["domains"].split()
            if needle in doms:
                chosen = c
                break

    if chosen is None:
        raise FileNotFoundError(
            f"[{cert_cfg.name}] Could not find matching lineage in `certbot certificates`. "
            f"Tip: set cert_name in config and include --cert-name in certbot_args."
        )

    fc_path = Path(chosen["cert_path"])
    pk_path = Path(chosen["privkey_path"])

    if not fc_path.exists() or not pk_path.exists():
        raise FileNotFoundError(
            f"[{cert_cfg.name}] Discovered paths but files not present:\n"
            f"  cert: {fc_path}\n  key:  {pk_path}"
        )

    return fc_path, pk_path


def archive_and_link(*, global_cfg: GlobalConfig, cert_cfg: CertConfig, le_fullchain: Path, le_privkey: Path, dry_run: bool) -> bool:
    if dry_run:
        logging.info("[%s] DRY RUN: would archive from:\n  %s\n  %s", cert_cfg.name, le_fullchain, le_privkey)
        logging.info("[%s] DRY RUN: would update symlinks:\n  %s\n  %s", cert_cfg.name, cert_cfg.cert_symlink, cert_cfg.key_symlink)
        return True

    if not le_fullchain.exists() or not le_privkey.exists():
        raise FileNotFoundError(f"Expected LE files not found: {le_fullchain} / {le_privkey}")

    ts = timestamp_slug()
    dest_dir = global_cfg.archive_dir / cert_cfg.name / ts
    dest_fullchain = dest_dir / "fullchain.pem"
    dest_privkey = dest_dir / "privkey.pem"

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_fullchain.write_bytes(le_fullchain.read_bytes())
    dest_privkey.write_bytes(le_privkey.read_bytes())

    ensure_permissions(dest_fullchain, mode=cert_cfg.cert_mode, owner=cert_cfg.owner, group=cert_cfg.group)
    ensure_permissions(dest_privkey, mode=cert_cfg.key_mode, owner=cert_cfg.owner, group=cert_cfg.group)

    atomic_symlink_update(cert_cfg.cert_symlink, dest_fullchain)
    atomic_symlink_update(cert_cfg.key_symlink, dest_privkey)

    logging.info("[%s] Updated symlinks:\n  cert -> %s\n  key  -> %s", cert_cfg.name, dest_fullchain, dest_privkey)
    return True


def maybe_reload(*, global_cfg: GlobalConfig, cert_cfg: CertConfig, changed: bool, dry_run: bool) -> None:
    if not changed:
        return

    cmd = cert_cfg.reload_cmd or global_cfg.default_reload_cmd
    if not cmd:
        logging.info("[%s] No reload_cmd configured; skipping reload.", cert_cfg.name)
        return

    if dry_run:
        logging.info("[%s] DRY RUN: would run reload: %s", cert_cfg.name, " ".join(shlex.quote(c) for c in cmd))
        return

    cp = run(cmd, check=False, capture=True)
    if cp.returncode == 0:
        logging.info("[%s] Reload command succeeded.", cert_cfg.name)
    else:
        logging.error("[%s] Reload command failed (rc=%d): %s", cert_cfg.name, cp.returncode, (cp.stderr or cp.stdout or "").strip())


def process_cert(*, global_cfg: GlobalConfig, cert_cfg: CertConfig, dry_run: bool, force: bool) -> int:
    now = utcnow()

    current_cert_path = read_symlink_target(cert_cfg.cert_symlink)
    do_renew, reason = should_renew(
        openssl_bin=global_cfg.openssl_bin,
        cert_path=current_cert_path if current_cert_path and current_cert_path.exists() else None,
        cfg=cert_cfg,
        now=now,
    )

    if force:
        do_renew, reason = True, "forced by flag"

    if not do_renew:
        logging.info("[%s] No renewal needed (%s).", cert_cfg.name, reason)
        return 0

    logging.info("[%s] Renewal required (%s).", cert_cfg.name, reason)

    cmd = build_certbot_cmd(global_cfg, cert_cfg)
    if dry_run:
        logging.info("[%s] DRY RUN: would run certbot:\n  %s", cert_cfg.name, " ".join(shlex.quote(c) for c in cmd))
        return 0

    cp = run(cmd, check=False, capture=True)
    if cp.returncode != 0:
        logging.error("[%s] Certbot failed (rc=%d).\nSTDOUT:\n%s\nSTDERR:\n%s", cert_cfg.name, cp.returncode, cp.stdout or "", cp.stderr or "")
        return 2

    logging.info("[%s] Certbot succeeded.")

    le_fullchain, le_privkey = discover_letsencrypt_paths(global_cfg, cert_cfg)

    changed = archive_and_link(
        global_cfg=global_cfg,
        cert_cfg=cert_cfg,
        le_fullchain=le_fullchain,
        le_privkey=le_privkey,
        dry_run=dry_run,
    )

    maybe_reload(global_cfg=global_cfg, cert_cfg=cert_cfg, changed=changed, dry_run=dry_run)
    return 0


def setup_logging(log_file: Path | None, level: str) -> None:
    numeric = getattr(logging, level.upper(), logging.INFO)
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers,
    )


def lock_or_die(lock_path: Path) -> Any:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    f = open(lock_path, "w", encoding="utf-8")
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print(f"Another instance is running (lock: {lock_path}).", file=sys.stderr)
        sys.exit(3)
    return f


def main() -> int:
    ap = argparse.ArgumentParser(description="Manage Let's Encrypt DoT certs for BIND with symlink rotation.")
    ap.add_argument("--config", "-c", required=True, help="Path to TOML config file.")
    ap.add_argument("--dry-run", action="store_true", help="Show what would happen; do not change anything.")
    ap.add_argument("--force", action="store_true", help="Force renewal regardless of current expiry.")
    ap.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARNING, ERROR")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    global_cfg, certs = load_config(cfg_path)

    setup_logging(global_cfg.log_file, args.log_level)

    _lock_handle = lock_or_die(global_cfg.lock_file)

    rc = 0
    for c in certs:
        try:
            rc = max(rc, process_cert(global_cfg=global_cfg, cert_cfg=c, dry_run=args.dry_run, force=args.force))
        except Exception as e:
            logging.exception("[%s] Unexpected error: %s", c.name, e)
            rc = max(rc, 4)

    return rc


if __name__ == "__main__":
    raise SystemExit(main())

