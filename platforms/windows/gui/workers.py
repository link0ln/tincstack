"""
workers.py — run blocking backend calls (every `tinc`/`tincd` subprocess) off
the Qt thread and deliver the result back through signals.

The original tinc-manager called `tinc.exe` on the GUI thread on every timer
tick and on every toolbar action; a slow or hung control socket froze the
window for up to the subprocess timeout. Everything that shells out now goes
through WorkerPool.run().
"""

from __future__ import annotations

import traceback
from typing import Any, Callable

from PySide6 import QtCore


class Worker(QtCore.QThread):
    done = QtCore.Signal(object)
    failed = QtCore.Signal(str)
    progress = QtCore.Signal(object)

    def __init__(self, fn: Callable[..., Any], *args: Any, parent: QtCore.QObject | None = None,
                 **kwargs: Any) -> None:
        super().__init__(parent)
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self._callbacks: tuple[Any, ...] = ()

    def run(self) -> None:
        try:
            self.done.emit(self._fn(*self._args, **self._kwargs))
        except Exception as e:  # surfaced to the GUI, never lost in a thread
            tb = traceback.format_exc()
            try:
                import diagnostics
                fn_name = getattr(self._fn, "__qualname__", getattr(self._fn, "__name__", repr(self._fn)))
                diagnostics.record_crash_trace(
                    f"Worker exception in {fn_name}: {type(e).__name__}: {e}",
                    tb,
                    kind="WORKER_EXCEPTION",
                )
            except Exception:
                pass
            self.failed.emit(f"{type(e).__name__}: {e}")


class WorkerPool(QtCore.QObject):
    """Owns the running Worker threads (so they are not garbage-collected
    mid-flight) and de-duplicates by tag: a second job with the same tag while
    the first is still running is dropped unless `rerun=True`, in which case
    the latest pending job for that tag runs as soon as the active one finishes."""

    def __init__(self, parent: QtCore.QObject | None = None) -> None:
        super().__init__(parent)
        self._workers: dict[Worker, str | None] = {}
        self._pending: dict[
            str,
            tuple[
                Callable[..., Any],
                tuple[Any, ...],
                dict[str, Any],
                Callable[[Any], None] | None,
                Callable[[str], None] | None,
                Callable[[Any], None] | None,
            ],
        ] = {}

    def busy(self, tag: str) -> bool:
        return tag in self._workers.values()

    @property
    def active(self) -> int:
        return len(self._workers)

    def cancel_pending(self) -> None:
        self._pending.clear()

    def run(self, fn: Callable[..., Any], *args: Any,
            on_done: Callable[[Any], None] | None = None,
            on_error: Callable[[str], None] | None = None,
            on_progress: Callable[[Any], None] | None = None,
            tag: str | None = None, rerun: bool = False,
            **kwargs: Any) -> Worker | None:
        if tag and self.busy(tag):
            if rerun:
                self._pending[tag] = (fn, args, kwargs, on_done, on_error, on_progress)
            return None
        w = Worker(fn, *args, parent=self, **kwargs)
        w._callbacks = (on_done, on_error, on_progress)
        self._workers[w] = tag
        if on_done:
            w.done.connect(on_done)
        if on_error:
            w.failed.connect(on_error)
        if on_progress:
            w.progress.connect(on_progress)
        w.finished.connect(lambda: self._cleanup(w))
        w.start()
        return w

    def _cleanup(self, w: Worker) -> None:
        tag = self._workers.pop(w, None)
        w.deleteLater()
        if tag and tag in self._pending and not self.busy(tag):
            fn, args, kwargs, on_done, on_error, on_progress = self._pending.pop(tag)
            self.run(
                fn,
                *args,
                on_done=on_done,
                on_error=on_error,
                on_progress=on_progress,
                tag=tag,
                **kwargs,
            )

    def wait_all(self, ms: int = 10000) -> bool:
        ok = True
        for w in list(self._workers):
            ok = w.wait(ms) and ok
        return ok
