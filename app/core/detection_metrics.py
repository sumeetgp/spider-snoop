"""
Detection Metrics
=================
In-process thread-safe telemetry for DLP tuning.

Tracked signals
---------------
  entities_detected_total      Raw regex + Presidio matches (pre-filter)
  entities_validated_total     Matches that passed every gate
  rejections.validator         Luhn / SSN / JWT validator failures
  rejections.entropy           Entropy too low or base64 common content
  rejections.context_gate      requires_context_keywords not met
  rejections.medical_relabel   bank_account → medical_patient_id

Per-type counters              by_type.<entity_type>.detected / .validated
Per-source counters            by_source.<source>.detected / .validated

Inference timing               Rolling 200-sample average per model label
  labels: regex, presidio, ai, scan_total

False-positive ring buffer     Last 100 suppressed-finding samples (FIFO)

Public API
----------
  metrics.inc_entity(entity_type, source, validated)
  metrics.inc_rejection(reason)
  metrics.record_timing(model, ms)
  metrics.log_fp_sample(reason, entity_type, masked_value, context_snippet, extra)
  metrics.snapshot()  → dict   (JSON-serialisable)
  metrics.fp_samples(limit)  → list[dict]
  metrics.reset()
"""
from __future__ import annotations

import collections
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_TIMING_WINDOW = 200  # rolling average window per model


class DetectionMetrics:
    """Thread-safe in-process telemetry store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: collections.Counter = collections.Counter()
        self._timings: Dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=_TIMING_WINDOW)
        )
        self._fp_samples: collections.deque = collections.deque(maxlen=100)
        self._started_at: str = datetime.now(timezone.utc).isoformat()

    # ── Counter helpers ────────────────────────────────────────────────────

    def inc_entity(self, entity_type: str, source: str, validated: bool) -> None:
        """Record one detection event (pre-validation always; post-validation gated)."""
        try:
            with self._lock:
                self._counters["entities_detected_total"] += 1
                self._counters[f"by_type.{entity_type}.detected"] += 1
                self._counters[f"by_source.{source}.detected"] += 1
                if validated:
                    self._counters["entities_validated_total"] += 1
                    self._counters[f"by_type.{entity_type}.validated"] += 1
                    self._counters[f"by_source.{source}.validated"] += 1
        except Exception:
            pass

    def inc_rejection(self, reason: str) -> None:
        """Record a filtered-out match: validator / entropy / context_gate / medical_relabel."""
        try:
            with self._lock:
                self._counters[f"rejections.{reason}"] += 1
        except Exception:
            pass

    # ── Timing ────────────────────────────────────────────────────────────

    def record_timing(self, model: str, ms: float) -> None:
        """Append one timing sample for the given model label."""
        try:
            with self._lock:
                self._timings[model].append(ms)
        except Exception:
            pass

    # ── False-positive sample logging ─────────────────────────────────────

    def log_fp_sample(
        self,
        reason: str,
        entity_type: str,
        masked_value: str,
        context_snippet: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Store one filtered-out sample for post-mortem tuning analysis."""
        try:
            sample = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
                "entity_type": entity_type,
                "masked_value": masked_value,
                "context_snippet": context_snippet[:300],
                "extra": extra or {},
            }
            with self._lock:
                self._fp_samples.append(sample)
        except Exception:
            pass

    # ── Read API ──────────────────────────────────────────────────────────

    def snapshot(self) -> Dict[str, Any]:
        """Return a JSON-serialisable summary of all current metrics."""
        try:
            with self._lock:
                counters = dict(self._counters)
                avg_ms = {
                    model: round(sum(dq) / len(dq), 2)
                    for model, dq in self._timings.items()
                    if dq
                }
                fp_count = len(self._fp_samples)

            rejection_breakdown = {
                k.split(".", 1)[1]: v
                for k, v in counters.items()
                if k.startswith("rejections.")
            }

            by_type: Dict[str, Dict] = {}
            by_source: Dict[str, Dict] = {}
            for k, v in counters.items():
                if k.startswith("by_type."):
                    _, etype, metric = k.split(".", 2)
                    by_type.setdefault(etype, {})[metric] = v
                elif k.startswith("by_source."):
                    _, src, metric = k.split(".", 2)
                    by_source.setdefault(src, {})[metric] = v

            return {
                "started_at": self._started_at,
                "entities": {
                    "detected_total": counters.get("entities_detected_total", 0),
                    "after_validation": counters.get("entities_validated_total", 0),
                    "rejection_breakdown": rejection_breakdown,
                },
                "by_type": by_type,
                "by_source": by_source,
                "avg_inference_ms": avg_ms,
                "false_positive_buffer_size": fp_count,
            }
        except Exception:
            return {"error": "metrics unavailable"}

    def fp_samples(self, limit: int = 50) -> List[Dict]:
        """Return the most-recent FP samples (up to `limit`)."""
        try:
            with self._lock:
                return list(self._fp_samples)[-limit:]
        except Exception:
            return []

    def reset(self) -> None:
        """Clear all counters, timings, and FP buffer."""
        try:
            with self._lock:
                self._counters.clear()
                self._timings.clear()
                self._fp_samples.clear()
                self._started_at = datetime.now(timezone.utc).isoformat()
        except Exception:
            pass


# Global singleton
metrics = DetectionMetrics()
