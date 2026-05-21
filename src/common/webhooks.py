"""Webhook endpoint validation, fanout controls, and log redaction."""

import copy
import math
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


REDACTED = "[REDACTED]"

SENSITIVE_NAME_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "signature",
    "token",
)

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
    signing_secret: Optional[str] = None
    enabled: bool = True
    max_deliveries: int = 100
    window_seconds: int = 60
    version: int = 1
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def public_dict(self, include_workspace: bool = True) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "url": redact_delivery_value(self.url),
            "enabled": self.enabled,
            "max_deliveries": self.max_deliveries,
            "window_seconds": self.window_seconds,
            "version": self.version,
        }
        if include_workspace:
            data["workspace_id"] = self.workspace_id
        return data


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
    headers: Dict[str, Any]
    response: Dict[str, Any]
    endpoint: Dict[str, Any]
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
            "headers": copy.deepcopy(self.headers),
            "response": copy.deepcopy(self.response),
            "endpoint": copy.deepcopy(self.endpoint),
            "callback_payload": copy.deepcopy(self.callback_payload),
            "created_at": self.created_at,
        }
        if self.retry_after is not None:
            record["retry_after"] = self.retry_after
        return record


DeliverySender = Callable[
    [WebhookEndpoint, Dict[str, Any]],
    Optional[Dict[str, Any]],
]


class EndpointRateLimiter:
    """Workspace and endpoint scoped sliding-window limiter.

    Each event is charged at most once per endpoint. Retry attempts for the
    same event can reuse the original charge, which keeps retry scheduling
    idempotent and prevents double-counting against the bucket.
    """

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._hits: Dict[Tuple[str, str], List[Tuple[float, str]]] = {}
        self._charged_events: Set[Tuple[str, str, str]] = set()

    def allow(
        self,
        endpoint: WebhookEndpoint,
        event_id: str,
    ) -> Tuple[bool, Optional[int]]:
        now = self._clock()
        bucket_key = (endpoint.workspace_id, endpoint.id)
        event_key = (endpoint.workspace_id, endpoint.id, event_id)

        if event_key in self._charged_events:
            self._hits[bucket_key] = self._active_hits(
                bucket_key,
                endpoint.window_seconds,
                now,
            )
            return True, None

        hits = self._active_hits(bucket_key, endpoint.window_seconds, now)
        if len(hits) >= endpoint.max_deliveries:
            retry_after = endpoint.window_seconds - (now - hits[0][0])
            self._hits[bucket_key] = hits
            return False, max(1, math.ceil(retry_after))

        self._hits[bucket_key] = [*hits, (now, event_id)]
        self._charged_events.add(event_key)
        return True, None

    def reset(self) -> None:
        self._hits.clear()
        self._charged_events.clear()

    def _active_hits(
        self,
        bucket_key: Tuple[str, str],
        window_seconds: int,
        now: float,
    ) -> List[Tuple[float, str]]:
        window_start = now - window_seconds
        return [
            hit for hit in self._hits.get(bucket_key, [])
            if hit[0] > window_start
        ]


class WebhookDeliveryService:
    """In-memory guard for webhook delivery dispatch and records.

    The service validates endpoint scope before delivery, persists only
    sanitized records, returns sanitized callback-shaped payloads, and applies
    rate limits before fanout performs delivery work.
    """

    def __init__(
        self,
        delivery_sender: Optional[DeliverySender] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._delivery_sender = delivery_sender or self._default_sender
        self._endpoints: Dict[Tuple[str, str], WebhookEndpoint] = {}
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
        signing_secret: Optional[str] = None,
        enabled: bool = True,
        endpoint_id: Optional[str] = None,
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
            signing_secret=signing_secret,
            enabled=enabled,
            max_deliveries=max_deliveries,
            window_seconds=window_seconds,
        )
        key = (endpoint.workspace_id, endpoint.id)
        if key in self._endpoints:
            raise ValueError("Webhook endpoint already exists")
        self._endpoints[key] = endpoint
        return copy.deepcopy(endpoint)

    def disable_endpoint(
        self,
        endpoint_id: str,
        workspace_id: Optional[str] = None,
    ) -> bool:
        endpoint = self._find_endpoint_for_update(endpoint_id, workspace_id)
        if not endpoint:
            return False
        endpoint.enabled = False
        endpoint.updated_at = time.time()
        return True

    def rotate_endpoint(
        self,
        endpoint_id: str,
        signing_secret: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Optional[WebhookEndpoint]:
        endpoint = self._find_endpoint_for_update(endpoint_id, workspace_id)
        if not endpoint:
            return None
        endpoint.version += 1
        endpoint.signing_secret = signing_secret
        endpoint.updated_at = time.time()
        return copy.deepcopy(endpoint)

    def fanout(
        self,
        workspace_id: str,
        event_id: str,
        payload: Dict[str, Any],
        endpoint_ids: Optional[Iterable[str]] = None,
        headers: Optional[Dict[str, Any]] = None,
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
                headers=headers,
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
        headers: Optional[Dict[str, Any]] = None,
        response: Optional[Dict[str, Any]] = None,
        endpoint_version: Optional[int] = None,
        attempt: int = 1,
    ) -> DeliveryRecord:
        return self._record(
            workspace_id=workspace_id,
            endpoint_id=endpoint_id,
            event_id=event_id,
            attempt=attempt,
            payload=payload,
            headers=headers,
            response=response,
            endpoint_version=endpoint_version,
            requested_status="delivered",
            requested_reason="accepted",
        )

    def record_failure(
        self,
        workspace_id: str,
        endpoint_id: str,
        event_id: str,
        payload: Dict[str, Any],
        failure: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        endpoint_version: Optional[int] = None,
        attempt: int = 1,
    ) -> DeliveryRecord:
        return self._record(
            workspace_id=workspace_id,
            endpoint_id=endpoint_id,
            event_id=event_id,
            attempt=attempt,
            payload=payload,
            headers=headers,
            response=failure,
            endpoint_version=endpoint_version,
            requested_status="failed",
            requested_reason="delivery_failed",
        )

    def schedule_retry(
        self,
        workspace_id: str,
        endpoint_id: str,
        event_id: str,
        payload: Dict[str, Any],
        failure: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        endpoint_version: Optional[int] = None,
        attempt: int = 2,
    ) -> DeliveryRecord:
        return self._record(
            workspace_id=workspace_id,
            endpoint_id=endpoint_id,
            event_id=event_id,
            attempt=attempt,
            payload=payload,
            headers=headers,
            response=failure,
            endpoint_version=endpoint_version,
            requested_status="retry_scheduled",
            requested_reason="retry_scheduled",
        )

    def delivery_log(
        self,
        workspace_id: str,
        endpoint_id: str,
        event_id: str,
        attempt: int = 1,
    ) -> Optional[Dict[str, Any]]:
        record = self._records.get(
            (workspace_id, endpoint_id, event_id, attempt)
        )
        return record.to_dict() if record else None

    def records(
        self,
        workspace_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        records = self._records.values()
        if workspace_id is not None:
            records = [
                record for record in records
                if record.workspace_id == workspace_id
            ]
        return [record.to_dict() for record in records]

    def _record(
        self,
        workspace_id: str,
        endpoint_id: str,
        event_id: str,
        attempt: int,
        payload: Dict[str, Any],
        headers: Optional[Dict[str, Any]],
        response: Optional[Dict[str, Any]],
        endpoint_version: Optional[int],
        requested_status: str,
        requested_reason: str,
    ) -> DeliveryRecord:
        key = (workspace_id, endpoint_id, event_id, attempt)
        if key in self._records:
            return copy.deepcopy(self._records[key])

        endpoint = self._endpoints.get((workspace_id, endpoint_id))
        status = requested_status
        reason = requested_reason
        include_endpoint_workspace = True
        retry_after: Optional[int] = None

        if endpoint is None:
            status = "rejected"
            reason = "endpoint_not_found"
            endpoint_info = {"id": endpoint_id}
        else:
            if not endpoint.enabled:
                status = "rejected"
                reason = "endpoint_disabled"
            elif (
                endpoint_version is not None
                and endpoint.version != endpoint_version
            ):
                status = "rejected"
                reason = "endpoint_rotated"
            endpoint_info = endpoint.public_dict(
                include_workspace=include_endpoint_workspace
            )

        sanitized_payload = redact_delivery_value(payload)
        sanitized_headers = sanitize_headers(headers)
        sanitized_response = redact_delivery_value(response or {})

        if endpoint is not None and status != "rejected":
            allowed, retry_after = self._limiter.allow(endpoint, event_id)
            if not allowed:
                status = "rejected"
                reason = "endpoint_rate_limited"
            elif requested_status == "delivered":
                sender_response = self._delivery_sender(
                    copy.deepcopy(endpoint),
                    copy.deepcopy(sanitized_payload),
                )
                if sender_response is not None:
                    sanitized_response = redact_delivery_value(
                        sender_response
                    )

        callback_payload = {
            "endpoint_id": endpoint_id,
            "event_id": event_id,
            "attempt": attempt,
            "status": status,
            "reason": reason,
            "payload": copy.deepcopy(sanitized_payload),
            "response": copy.deepcopy(sanitized_response),
        }
        if retry_after is not None:
            callback_payload["retry_after"] = retry_after
        callback_payload["endpoint"] = copy.deepcopy(endpoint_info)

        record = DeliveryRecord(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            endpoint_id=endpoint_id,
            event_id=event_id,
            attempt=attempt,
            status=status,
            reason=reason,
            payload=sanitized_payload,
            headers=sanitized_headers,
            response=sanitized_response,
            endpoint=endpoint_info,
            callback_payload=callback_payload,
            retry_after=retry_after,
        )
        self._records[key] = record
        return copy.deepcopy(record)

    def _find_endpoint_for_update(
        self,
        endpoint_id: str,
        workspace_id: Optional[str],
    ) -> Optional[WebhookEndpoint]:
        if workspace_id is not None:
            return self._endpoints.get((workspace_id, endpoint_id))

        matches = [
            endpoint for endpoint in self._endpoints.values()
            if endpoint.id == endpoint_id
        ]
        if len(matches) == 1:
            return matches[0]
        return None

    @staticmethod
    def _default_sender(
        endpoint: WebhookEndpoint,
        payload: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        return None

    @staticmethod
    def _validate_url(url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Webhook endpoint URL must be absolute HTTP(S)")


def sanitize_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    for key, value in (headers or {}).items():
        key_text = str(key)
        if _is_internal_name(key_text):
            continue
        sanitized[key_text] = (
            REDACTED
            if _is_sensitive_name(key_text)
            else redact_delivery_value(value)
        )
    return sanitized


def redact_delivery_value(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: Dict[str, Any] = {}
        for key, nested in value.items():
            key_text = str(key)
            if _is_internal_name(key_text):
                continue
            if _is_sensitive_name(key_text):
                sanitized[key_text] = REDACTED
            else:
                sanitized[key_text] = redact_delivery_value(nested)
        return sanitized
    if isinstance(value, list):
        return [redact_delivery_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_delivery_value(item) for item in value)
    if isinstance(value, str):
        return _redact_url(value)
    return value


def contains_private_values(value: Any, private_values: Iterable[str]) -> bool:
    private_strings = {str(private) for private in private_values}
    if isinstance(value, dict):
        return any(
            str(key) in private_strings
            or contains_private_values(nested, private_strings)
            for key, nested in value.items()
        )
    if isinstance(value, list) or isinstance(value, tuple):
        return any(
            contains_private_values(nested, private_strings)
            for nested in value
        )
    return str(value) in private_strings


def _is_sensitive_name(name: str) -> bool:
    normalized = name.lower().replace("-", "_")
    return any(part in normalized for part in SENSITIVE_NAME_PARTS)


def _is_internal_name(name: str) -> bool:
    normalized = name.lower().replace("-", "_")
    return (
        normalized.startswith("_")
        or any(part in normalized for part in INTERNAL_NAME_PARTS)
    )


def _redact_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        return value

    netloc = parsed.netloc
    if parsed.username or parsed.password:
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        netloc = f"{REDACTED}@{host}"

    query = []
    for key, nested in parse_qsl(parsed.query, keep_blank_values=True):
        if _is_internal_name(key):
            continue
        query.append((key, REDACTED if _is_sensitive_name(key) else nested))

    return urlunsplit(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            urlencode(query),
            parsed.fragment,
        )
    )
