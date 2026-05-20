"""Webhook dispatch-control API routes."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.common.webhook_dispatch import WebhookDispatchService


router = APIRouter(prefix="/webhook-dispatch", tags=["webhook-dispatch"])
webhook_dispatcher = WebhookDispatchService()


class RegisterEndpointRequest(BaseModel):
    workspace_id: str
    url: str
    endpoint_id: Optional[str] = None
    enabled: bool = True
    max_deliveries: int = 100
    window_seconds: int = 60


class DeliveryRequest(BaseModel):
    workspace_id: str
    event_id: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    attempt: int = 1
    endpoint_version: Optional[int] = None


class FanoutRequest(BaseModel):
    workspace_id: str
    event_id: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    endpoint_ids: Optional[List[str]] = None
    attempt: int = 1


@router.post("/endpoints")
async def register_webhook_dispatch_endpoint(
    request: RegisterEndpointRequest,
):
    try:
        endpoint = webhook_dispatcher.register_endpoint(
            workspace_id=request.workspace_id,
            endpoint_id=request.endpoint_id,
            url=request.url,
            enabled=request.enabled,
            max_deliveries=request.max_deliveries,
            window_seconds=request.window_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return endpoint.public_dict()


@router.post("/endpoints/{endpoint_id}/disable")
async def disable_webhook_dispatch_endpoint(endpoint_id: str):
    if not webhook_dispatcher.disable_endpoint(endpoint_id):
        raise HTTPException(
            status_code=404,
            detail="Webhook dispatch endpoint not found",
        )
    return {"status": "disabled", "endpoint_id": endpoint_id}


@router.post("/endpoints/{endpoint_id}/rotate")
async def rotate_webhook_dispatch_endpoint(endpoint_id: str):
    endpoint = webhook_dispatcher.rotate_endpoint(endpoint_id)
    if endpoint is None:
        raise HTTPException(
            status_code=404,
            detail="Webhook dispatch endpoint not found",
        )
    return endpoint.public_dict()


@router.post("/endpoints/{endpoint_id}/deliver")
async def deliver_webhook_dispatch_endpoint(
    endpoint_id: str,
    request: DeliveryRequest,
):
    record = webhook_dispatcher.deliver(
        workspace_id=request.workspace_id,
        endpoint_id=endpoint_id,
        event_id=request.event_id,
        payload=request.payload,
        attempt=request.attempt,
        endpoint_version=request.endpoint_version,
    )
    if record.reason == "endpoint_rate_limited":
        raise HTTPException(status_code=429, detail=record.callback_payload)
    if record.status == "rejected":
        raise HTTPException(status_code=409, detail=record.callback_payload)
    return record.callback_payload


@router.post("/fanout")
async def fanout_webhook_dispatch_event(request: FanoutRequest):
    records = webhook_dispatcher.dispatch_event(
        workspace_id=request.workspace_id,
        event_id=request.event_id,
        payload=request.payload,
        endpoint_ids=request.endpoint_ids,
        attempt=request.attempt,
    )
    return {
        "deliveries": [
            record.callback_payload for record in records
        ]
    }
