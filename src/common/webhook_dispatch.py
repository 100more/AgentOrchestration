"""Webhook fanout dispatch controls."""

import copy
import math
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit


INTERNAL_NAME_PARTS = (
    "debug",
    "internal",
    "private",
    "raw",
    "runtime",
    "trace",
)


@dataclass
class WebhookEndpoint:
    id: str
    workspace_id: str
    url: str
    enabled: bool = True
    max_deliveries: int = 100
    window_seconds: int = 60
    version: int = 1
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def public_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "url": self.url,
            "enabled": self.enabled,
            "max_deliveries": self.max_deliveries,
            "window_seconds": self.window_seconds,
            "version": self.version,
        }


DeliverySender = Callable[
    [WebhookEndpoint, Dict[str, Any]],
    Optional[Dict[str, Any]],
]


@dataclass
class DeliveryRecord:
    id: str
    workspace_id: str
    endpoint_id: str
    event_id: str
    attempt: int
    status: str
    reason: str
    payload: Dict[str, Any]
    response: Dict[str, Any]
    callback_payload: Dict[str, Any]
    retry_after: Optional[int] = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        record = {
            "id": self.id,
            "workspace_id": self.workspace_id,
            "endpoint_id": self.endpoint_id,
            "event_id": self.event_id,
            "attempt": self.attempt,
            "status": self.status,
            "reason": self.reason,
            "payload": copy.deepcopy(self.payload),
            "response": copy.deepcopy(self.response),
            "callback_payload": copy.deepcopy(self.callback_payload),
            "created_at": self.created_at,
        }
        if self.retry_after is not None:
            record["retry_after"] = self.retry_after
        return record


class EndpointRateLimiter:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._hits: Dict[Tuple[str, str], List[float]] = {}

    def allow(self, endpoint: WebhookEndpoint) -> Tuple[bool, Optional[int]]:
        now = self._clock()
        key = (endpoint.workspace_id, endpoint.id)
        window_start = now - endpoint.window_seconds
        hits = [
            hit for hit in self._hits.get(key, [])
            if hit > window_start
        ]

        if len(hits) >= endpoint.max_deliveries:
            retry_after = endpoint.window_seconds - (now - hits[0])
            self._hits[key] = hits
            return False, max(1, math.ceil(retry_after))

        self._hits[key] = [*hits, now]
        return True, None

    def reset(self) -> None:
        self._hits.clear()


class WebhookDispatchService:
    """Dispatches webhook fanout with per-endpoint backpressure."""

    def __init__(
        self,
        delivery_sender: Optional[DeliverySender] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._delivery_sender = delivery_sender or self._default_sender
        self._endpoints: Dict[str, WebhookEndpoint] = {}
        self._records: Dict[Tuple[str, str, str, int], DeliveryRecord] = {}
        self._limiter = EndpointRateLimiter(clock)

    def reset(self) -> None:
        self._endpoints.clear()
        self._records.clear()
        self._limiter.reset()

    def register_endpoint(
        self,
        workspace_id: str,
        url: str,
        endpoint_id: Optional[str] = None,
        enabled: bool = True,
        max_deliveries: int = 100,
        window_seconds: int = 60,
    ) -> WebhookEndpoint:
        self._validate_url(url)
        if max_deliveries < 1:
            raise ValueError("max_deliveries must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")

        endpoint = WebhookEndpoint(
            id=endpoint_id or str(uuid.uuid4()),
            workspace_id=workspace_id,
            url=url,
            enabled=enabled,
            max_deliveries=max_deliveries,
            window_seconds=window_seconds,
        )
        if endpoint.id in self._endpoints:
            raise ValueError("Webhook endpoint already exists")
        self._endpoints[endpoint.id] = endpoint
        return copy.deepcopy(endpoint)

    def disable_endpoint(self, endpoint_id: str) -> bool:
        endpoint = self._endpoints.get(endpoint_id)
        if endpoint is None:
            return False
        endpoint.enabled = False
        endpoint.updated_at = time.time()
        return True

    def rotate_endpoint(self, endpoint_id: str) -> Optional[WebhookEndpoint]:
        endpoint = self._endpoints.get(endpoint_id)
        if endpoint is None:
            return None
        endpoint.version += 1
        endpoint.updated_at = time.time()
        return copy.deepcopy(endpoint)

    def dispatch_event(
        self,
        workspace_id: str,
        event_id: str,
        payload: Dict[str, Any],
        endpoint_ids: Optional[Iterable[str]] = None,
        attempt: int = 1,
    ) -> List[DeliveryRecord]:
        if endpoint_ids is None:
            endpoint_ids = [
                endpoint.id for endpoint in self._endpoints.values()
                if endpoint.workspace_id == workspace_id
            ]
        return [
            self.deliver(
                workspace_id=workspace_id,
                endpoint_id=endpoint_id,
                event_id=event_id,
                payload=payload,
                attempt=attempt,
            )
            for endpoint_id in endpoint_ids
        ]

    def deliver(
        self,
        workspace_id: str,
        endpoint_id: str,
        event_id: str,
        payload: Dict[str, Any],
        attempt: int = 1,
        endpoint_version: Optional[int] = None,
    ) -> DeliveryRecord:
        normalized_attempt = max(1, attempt)
        key = (workspace_id, endpoint_id, event_id, normalized_attempt)
        if key in self._records:
            return copy.deepcopy(self._records[key])

        sanitized_payload = scrub_internal_fields(payload)
        endpoint = self._endpoints.get(endpoint_id)
        if endpoint is None:
            return self._store(key, "rejected", "endpoint_not_found")
        if endpoint.workspace_id != workspace_id:
            return self._store(
                key,
                "rejected",
                "endpoint_not_found",
                payload=sanitized_payload,
            )
        if not endpoint.enabled:
            return self._store(
                key,
                "rejected",
                "endpoint_disabled",
                payload=sanitized_payload,
            )
        if (
            endpoint_version is not None
            and endpoint.version != endpoint_version
        ):
            return self._store(
                key,
                "rejected",
                "endpoint_rotated",
                payload=sanitized_payload,
            )

        allowed, retry_after = self._limiter.allow(endpoint)
        if not allowed:
            return self._store(
                key,
                "rejected",
                "endpoint_rate_limited",
                payload=sanitized_payload,
                retry_after=retry_after,
            )

        response = self._delivery_sender(
            copy.deepcopy(endpoint),
            copy.deepcopy(sanitized_payload),
        ) or {"status": "accepted"}
        return self._store(
            key,
            "delivered",
            "accepted",
            payload=sanitized_payload,
            response=scrub_internal_fields(response),
        )

    def _store(
        self,
        key: Tuple[str, str, str, int],
        status: str,
        reason: str,
        payload: Optional[Dict[str, Any]] = None,
        response: Optional[Dict[str, Any]] = None,
        retry_after: Optional[int] = None,
    ) -> DeliveryRecord:
        workspace_id, endpoint_id, event_id, attempt = key
        callback_payload = {
            "endpoint_id": endpoint_id,
            "event_id": event_id,
            "attempt": attempt,
            "status": status,
            "reason": reason,
            "payload": copy.deepcopy(payload or {}),
            "response": copy.deepcopy(response or {}),
        }
        if retry_after is not None:
            callback_payload["retry_after"] = retry_after

        record = DeliveryRecord(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            endpoint_id=endpoint_id,
            event_id=event_id,
            attempt=attempt,
            status=status,
            reason=reason,
            payload=payload or {},
            response=response or {},
            callback_payload=callback_payload,
            retry_after=retry_after,
        )
        self._records[key] = record
        return copy.deepcopy(record)

    @staticmethod
    def _default_sender(
        endpoint: WebhookEndpoint,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {"status": "accepted"}

    @staticmethod
    def _validate_url(url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Webhook endpoint URL must be absolute HTTP(S)")


def scrub_internal_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): scrub_internal_fields(nested)
            for key, nested in value.items()
            if not _is_internal_name(str(key))
        }
    if isinstance(value, list):
        return [scrub_internal_fields(item) for item in value]
    if isinstance(value, tuple):
        return tuple(scrub_internal_fields(item) for item in value)
    return value


def _is_internal_name(name: str) -> bool:
    normalized = name.lower().replace("-", "_")
    return (
        normalized.startswith("_")
        or any(part in normalized for part in INTERNAL_NAME_PARTS)
    )
