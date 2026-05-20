"""Webhook delivery-log API routes."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.common.webhooks import WebhookDeliveryService


router = APIRouter(prefix="/webhooks", tags=["webhooks"])
webhook_delivery_service = WebhookDeliveryService()


class RegisterWebhookEndpointRequest(BaseModel):
    workspace_id: str
    url: str
    signing_secret: Optional[str] = None
    enabled: bool = True
    endpoint_id: Optional[str] = None


class RotateWebhookEndpointRequest(BaseModel):
    signing_secret: Optional[str] = None


class WebhookDeliveryRequest(BaseModel):
    workspace_id: str
    event_id: str
    payload: Dict[str, Any]
    headers: Dict[str, Any] = Field(default_factory=dict)
    response: Dict[str, Any] = Field(default_factory=dict)
    failure: Dict[str, Any] = Field(default_factory=dict)
    endpoint_version: Optional[int] = None
    attempt: int = 1


@router.post("/endpoints")
async def register_webhook_endpoint(
    request: RegisterWebhookEndpointRequest,
):
    try:
        endpoint = webhook_delivery_service.register_endpoint(
            workspace_id=request.workspace_id,
            url=request.url,
            signing_secret=request.signing_secret,
            enabled=request.enabled,
            endpoint_id=request.endpoint_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return endpoint.public_dict()


@router.post("/endpoints/{endpoint_id}/disable")
async def disable_webhook_endpoint(endpoint_id: str):
    if not webhook_delivery_service.disable_endpoint(endpoint_id):
        raise HTTPException(
            status_code=404,
            detail="Webhook endpoint not found",
        )
    return {"status": "disabled", "endpoint_id": endpoint_id}


@router.post("/endpoints/{endpoint_id}/rotate")
async def rotate_webhook_endpoint(
    endpoint_id: str,
    request: RotateWebhookEndpointRequest,
):
    endpoint = webhook_delivery_service.rotate_endpoint(
        endpoint_id,
        signing_secret=request.signing_secret,
    )
    if not endpoint:
        raise HTTPException(
            status_code=404,
            detail="Webhook endpoint not found",
        )
    return endpoint.public_dict()


@router.post("/{endpoint_id}/deliver")
async def record_webhook_delivery(
    endpoint_id: str,
    request: WebhookDeliveryRequest,
):
    if request.failure:
        record = webhook_delivery_service.record_failure(
            workspace_id=request.workspace_id,
            endpoint_id=endpoint_id,
            event_id=request.event_id,
            payload=request.payload,
            failure=request.failure,
            headers=request.headers,
            endpoint_version=request.endpoint_version,
            attempt=request.attempt,
        )
    else:
        record = webhook_delivery_service.deliver(
            workspace_id=request.workspace_id,
            endpoint_id=endpoint_id,
            event_id=request.event_id,
            payload=request.payload,
            headers=request.headers,
            response=request.response,
            endpoint_version=request.endpoint_version,
            attempt=request.attempt,
        )

    if record.status == "rejected":
        raise HTTPException(status_code=409, detail=record.callback_payload)
    return record.callback_payload


@router.post("/{endpoint_id}/retry")
async def schedule_webhook_retry(
    endpoint_id: str,
    request: WebhookDeliveryRequest,
):
    record = webhook_delivery_service.schedule_retry(
        workspace_id=request.workspace_id,
        endpoint_id=endpoint_id,
        event_id=request.event_id,
        payload=request.payload,
        failure=request.failure or request.response,
        headers=request.headers,
        endpoint_version=request.endpoint_version,
        attempt=max(request.attempt, 2),
    )
    if record.status == "rejected":
        raise HTTPException(status_code=409, detail=record.callback_payload)
    return record.callback_payload


@router.get("/{endpoint_id}/deliveries/{event_id}")
async def get_webhook_delivery_log(
    endpoint_id: str,
    event_id: str,
    workspace_id: str,
    attempt: int = 1,
):
    record = webhook_delivery_service.delivery_log(
        workspace_id=workspace_id,
        endpoint_id=endpoint_id,
        event_id=event_id,
        attempt=attempt,
    )
    if not record:
        raise HTTPException(status_code=404, detail="Delivery log not found")
    return record
