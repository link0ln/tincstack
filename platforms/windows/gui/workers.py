"""
workers.py — run blocking backend calls (every `tinc`/`tincd` subprocess) off
the Qt thread and deliver the result back through signals.

The original tinc-manager called `tinc.exe` on the GUI thread on every timer
tick and on every toolbar action; a slow or hung control socket froze the
window for up to the subprocess timeout. Everything that shells out now goes
through WorkerPool.run().
"""

from __future__ import annotations

from typing import Any, Callable

from PySide6 import QtCore


class Worker(QtCore.QThread):
    done = QtCore.Signal(object)
    failed = QtCore.Signal(str)

    def __init__(self, fn: Callable[..., Any], *args: Any, parent: QtCore.QObject | None = None,
                 **kwargs: Any) -> None:
        super().__init__(parent)
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self) -> None:
        try:
            self.done.emit(self._fn(*self._args, **self._kwargs))
        except Exception as e:  # surfaced to the GUI, never lost in a thread
            self.failed.emit(f"{type(e).__name__}: {e}")


class WorkerPool(QtCore.QObject):
    """Owns the running Worker threads (so they are not garbage-collected
    mid-flight) and de-duplicates by tag: a second job with the same tag while
    the first is still running is dropped, which is what a periodic sampler
    wants."""

    def __init__(self, parent: QtCore.QObject | None = None) -> None:
        super().__init__(parent)
        self._workers: dict[Worker, str | None] = {}

    def busy(self, tag: str) -> bool:
        return tag in self._workers.values()

    @property
    def active(self) -> int:
        return len(self._workers)

    def run(self, fn: Callable[..., Any], *args: Any,
            on_done: Callable[[Any], None] | None = None,
            on_error: Callable[[str], None] | None = None,
            tag: str | None = None, **kwargs: Any) -> Worker | None:
        if tag and self.busy(tag):
            return None
        w = Worker(fn, *args, parent=self, **kwargs)
        self._workers[w] = tag
        if on_done:
            w.done.connect(on_done)
        if on_error:
            w.failed.connect(on_error)
        w.finished.connect(lambda: self._cleanup(w))
        w.start()
        return w

    def _cleanup(self, w: Worker) -> None:
        self._workers.pop(w, None)
        w.deleteLater()

    def wait_all(self, ms: int = 10000) -> bool:
        ok = True
        for w in list(self._workers):
            ok = w.wait(ms) and ok
        return ok
