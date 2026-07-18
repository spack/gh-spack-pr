"""Build execution for queued Spack PR review tasks."""

# pylint: disable=too-many-arguments

from __future__ import annotations

import os
import select
import sys
import termios
import threading
import tty
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, List, Optional

try:
    import pexpect
except ImportError:  # pragma: no cover - fallback for GitHub extension execution from source
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "cli"))
    from _vendor import pexpect

from .domain import BuildResult, BuildTask, TaskStatus
from .external import utc_now
from .state import StateStore


_ACTIVE_CHILDREN: set[Any] = set()
_ACTIVE_CHILDREN_LOCK = threading.Lock()
_INPUT_THREAD: Optional[threading.Thread] = None
_INPUT_STOP = threading.Event()
_INPUT_ORIGINAL_ATTRS: Optional[List[Any]] = None


class PtyBuildRunner:  # pylint: disable=too-few-public-methods
    """Run Spack builds through a PTY while teeing output to a log file."""

    def __init__(self, output_lock: Optional[threading.Lock] = None):
        self.output_lock = output_lock or threading.Lock()

    def run(
        self, command: List[str], log_path: Path, timeout: Optional[int] = None
    ) -> BuildResult:
        """Run a command through a PTY and return a build-shaped result shell."""

        started_at = utc_now()
        child = pexpect.spawn(command[0], command[1:], encoding="utf-8", timeout=timeout)
        with log_path.open("w", encoding="utf-8") as log_file:
            with forward_terminal_input_to(child):
                while True:
                    try:
                        ready, _, _ = select.select([child.child_fd], [], [], 0.1)
                    except (OSError, ValueError):
                        break
                    if not ready:
                        if not child.isalive():
                            break
                        continue
                    if child.child_fd in ready:
                        try:
                            data = child.read_nonblocking(size=4096, timeout=0)
                        except pexpect.TIMEOUT:
                            data = ""
                        except pexpect.EOF:
                            break
                        if data:
                            log_file.write(data)
                            log_file.flush()
                            with self.output_lock:
                                sys.stdout.write(data)
                                sys.stdout.flush()
        child.close()
        ended_at = utc_now()
        exit_code = int(child.exitstatus or child.signalstatus or 0)
        return BuildResult(
            task_id="",
            spec="",
            status=TaskStatus.PASSED if exit_code == 0 else TaskStatus.FAILED,
            command=command,
            exit_code=exit_code,
            started_at=started_at,
            ended_at=ended_at,
            log_path=str(log_path),
        )


def run_task(
    number: int,
    task: BuildTask,
    store: StateStore,
    *,
    spack: str = "spack",
    dry_run: bool = False,
    timeout: Optional[int] = None,
    output_lock: Optional[threading.Lock] = None,
) -> BuildResult:
    """Run or dry-run one queued Spack install task."""

    command = [spack, "install", "-v", "--fail-fast", task.build_spec.spec]
    log_dir = store.log_dir(number)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{task.id}.log"

    if dry_run:
        result = _dry_run_result(task, command, log_path)
    else:
        shell = PtyBuildRunner(output_lock).run(command, log_path, timeout=timeout)
        status = TaskStatus.PASSED if shell.exit_code == 0 else TaskStatus.FAILED
        result = BuildResult(
            task_id=task.id,
            spec=task.build_spec.spec,
            status=status,
            command=command,
            exit_code=shell.exit_code,
            started_at=shell.started_at,
            ended_at=shell.ended_at,
            log_path=str(log_path),
            error_summary=_error_summary(log_path) if status == TaskStatus.FAILED else "",
        )

    result_path = store.write_result(number, result)
    store.finish_task(number, task.id, result.status, str(result_path))
    return result


def run_available_tasks(
    number: int,
    store: StateStore,
    *,
    owner: str,
    spack: str = "spack",
    dry_run: bool = False,
    timeout: Optional[int] = None,
    jobs: int = 1,
    lease_seconds: int = 3600,
) -> List[BuildResult]:
    """Claim and run queued tasks, optionally with multiple PTY-backed workers."""

    results: List[BuildResult] = []
    output_lock = threading.Lock()

    def worker(index: int) -> List[BuildResult]:
        worker_results: List[BuildResult] = []
        worker_owner = f"{owner}-{index}"
        while True:
            task = store.claim_next_task(number, worker_owner, lease_seconds)
            if task is None:
                return worker_results
            result = run_task(
                number,
                task,
                store,
                spack=spack,
                dry_run=dry_run,
                timeout=timeout,
                output_lock=output_lock,
            )
            worker_results.append(result)
            print_result(result)

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as executor:
        futures = [executor.submit(worker, index + 1) for index in range(max(1, jobs))]
        for future in as_completed(futures):
            results.extend(future.result())
    return results


def print_result(result: BuildResult) -> None:
    """Print a concise build result."""

    print(f"{result.task_id}: {result.status.value} {result.spec}")
    if result.log_path:
        print(f"log: {result.log_path}")
    if result.error_summary:
        print(result.error_summary)


def _dry_run_result(task: BuildTask, command: List[str], log_path: Path) -> BuildResult:
    timestamp = utc_now()
    log_path.write_text("Dry run: " + " ".join(command) + "\n", encoding="utf-8")
    return BuildResult(
        task_id=task.id,
        spec=task.build_spec.spec,
        status=TaskStatus.SKIPPED,
        command=command,
        exit_code=0,
        started_at=timestamp,
        ended_at=timestamp,
        log_path=str(log_path),
        error_summary="dry run",
    )


def _error_summary(log_path: Path) -> str:
    markers = ("Error:", "error:", "FAILED", "failed")
    try:
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if any(marker in line for marker in markers):
                return line.strip()[:500]
    except OSError:
        return "failed; log could not be read"
    return "spack install failed"


def default_owner() -> str:
    """Return a stable default owner for queue leases."""

    return f"{os.uname().nodename}-{os.getpid()}"


@contextmanager
def forward_terminal_input_to(child: Any) -> Iterator[None]:
    """Forward raw local terminal input to an active PTY child."""

    if not sys.stdin.isatty():
        yield
        return
    start_terminal_input_forwarder(child)
    try:
        yield
    finally:
        stop_terminal_input_forwarder(child)


def start_terminal_input_forwarder(child: Any) -> None:
    """Register a PTY child and start the shared input forwarder if needed."""

    global _INPUT_THREAD  # pylint: disable=global-statement
    global _INPUT_ORIGINAL_ATTRS  # pylint: disable=global-statement

    with _ACTIVE_CHILDREN_LOCK:
        _ACTIVE_CHILDREN.add(child)
        if _INPUT_THREAD and _INPUT_THREAD.is_alive():
            return
        file_descriptor = sys.stdin.fileno()
        _INPUT_ORIGINAL_ATTRS = termios.tcgetattr(file_descriptor)
        tty.setraw(file_descriptor)
        _INPUT_STOP.clear()
        _INPUT_THREAD = threading.Thread(target=forward_terminal_input, daemon=True)
        _INPUT_THREAD.start()


def stop_terminal_input_forwarder(child: Any) -> None:
    """Unregister a PTY child and stop the shared input forwarder if it is idle."""

    global _INPUT_THREAD  # pylint: disable=global-statement
    global _INPUT_ORIGINAL_ATTRS  # pylint: disable=global-statement

    input_thread = None
    with _ACTIVE_CHILDREN_LOCK:
        _ACTIVE_CHILDREN.discard(child)
        if _ACTIVE_CHILDREN:
            return
        _INPUT_STOP.set()
        input_thread = _INPUT_THREAD
    if input_thread:
        input_thread.join(timeout=1)
    with _ACTIVE_CHILDREN_LOCK:
        if _INPUT_ORIGINAL_ATTRS is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, _INPUT_ORIGINAL_ATTRS)
            _INPUT_ORIGINAL_ATTRS = None
        _INPUT_THREAD = None


def forward_terminal_input() -> None:
    """Read local terminal input and broadcast it to all active PTY children."""

    stdin_fd = sys.stdin.fileno()
    while not _INPUT_STOP.is_set():
        try:
            ready, _, _ = select.select([stdin_fd], [], [], 0.1)
        except (OSError, ValueError):
            return
        if not ready:
            continue
        try:
            user_input = os.read(stdin_fd, 1024)
        except OSError:
            return
        if not user_input:
            continue
        text = user_input.decode("utf-8", errors="ignore")
        with _ACTIVE_CHILDREN_LOCK:
            children = list(_ACTIVE_CHILDREN)
        for child in children:
            if child.isalive():
                child.write(text)
