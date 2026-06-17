from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def _decode(data: bytes) -> str:
    for encoding in ("utf-8", "gbk", "mbcs", "latin-1"):
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def run_command(args: list[str], timeout: int = 20, max_output: int = 2_000_000) -> CommandResult:
    try:
        proc = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            timeout=timeout,
        )
        stdout = _decode(proc.stdout[:max_output])
        stderr = _decode(proc.stderr[:max_output])
        truncated = len(proc.stdout) > max_output or len(proc.stderr) > max_output
        if truncated:
            stderr = (stderr + "\n[输出过长，已截断]").strip()
        return CommandResult(args=args, returncode=proc.returncode, stdout=stdout, stderr=stderr)
    except subprocess.TimeoutExpired as exc:
        stdout = _decode((exc.stdout or b"")[:max_output]) if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = _decode((exc.stderr or b"")[:max_output]) if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return CommandResult(args=args, returncode=124, stdout=stdout, stderr=stderr or "命令执行超时", timed_out=True)
    except FileNotFoundError as exc:
        return CommandResult(args=args, returncode=127, stdout="", stderr=str(exc))
    except Exception as exc:
        return CommandResult(args=args, returncode=1, stdout="", stderr=str(exc))
