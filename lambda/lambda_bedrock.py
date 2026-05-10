import json
import os
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── Config from CDK-injected environment variables ────────────────────────────
REGION = os.environ.get("AWS_REGION_NAME", "us-east-1")
MODEL_ID = os.environ.get("MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")
GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID", "")
GUARDRAIL_VER = os.environ.get("GUARDRAIL_VERSION", "DRAFT")

# Pre-flight deny list: cheap local check before any API call
DENY_LIST = [
    "jailbreak",
    "ignore previous instructions",
    "internal-secret",
    "bypass safety",
    "reveal system prompt",
    "hidden instructions",
]

# Terms used only for risk scoring. These do not always block the request.
HIGH_RISK_TERMS = [
    "jailbreak",
    "ignore previous instructions",
    "bypass",
    "system prompt",
    "hidden instructions",
    "developer message",
    "disable guardrail",
    "remove safety",
]

UNCERTAIN_PHRASES = [
    "i think",
    "maybe",
    "possibly",
    "not sure",
    "i cannot verify",
    "i can't verify",
    "it seems",
    "it appears",
    "may be",
]

bedrock_runtime = boto3.client("bedrock-runtime", region_name=REGION)


def lambda_handler(event, context):
    """
    API Gateway HTTP API → Lambda → Bedrock Guardrail → Claude

    POST /chat
    Body: { "message": "...", "max_tokens": 1024, "system": "..." }
    """
    logger.info("Event: %s", json.dumps(event))
    _log_risk_event("request_received")

    # ── 1. Parse body ─────────────────────────────────────────────────────────
    try:
        body = event.get("body") or "{}"
        if isinstance(body, str):
            body = json.loads(body)

        user_message = body.get("message", "").strip()
        if not user_message:
            _log_risk_event("invalid_request", reason="missing_message")
            return _resp(400, {"error": "'message' field is required."})

        max_tokens = int(body.get("max_tokens", 1024))
        system_prompt = body.get("system", "You are a helpful assistant.")

    except (json.JSONDecodeError, ValueError) as e:
        _log_risk_event("invalid_request", reason="bad_json")
        return _resp(400, {"error": f"Invalid request body: {e}"})

    # ── 2. Local deny-list check ──────────────────────────────────────────────
    lowered = user_message.lower()
    for term in DENY_LIST:
        if term.lower() in lowered:
            risk_score = calculate_risk_score(user_message, blocked_by="deny_list")
            _log_risk_event(
                "input_blocked",
                risk_score=risk_score,
                blocked_by="deny_list",
                reason="deny_list_match",
                matched_term=term,
            )
            return _resp(400, {
                "error": "GUARDRAIL_BLOCKED",
                "reason": "Message contains a disallowed term.",
                "blocked_by": "deny_list",
                "risk_score": risk_score,
            })

    # ── 3. Bedrock guardrail: apply to INPUT before model call ────────────────
    gr = _apply_guardrail(user_message, source="INPUT")
    input_risk_score = calculate_risk_score(
        user_message,
        pii_found=gr.get("pii_found", []),
        blocked_by=gr.get("blocked_by"),
    )
    _log_risk_event(
        "input_checked",
        risk_score=input_risk_score,
        blocked_by=gr.get("blocked_by"),
        pii_found=gr.get("pii_found", []),
        guardrail_action=gr.get("action"),
    )

    if gr["action"] == "GUARDRAIL_INTERVENED":
        _log_risk_event(
            "input_blocked",
            risk_score="High",
            blocked_by=gr.get("blocked_by"),
            reason=gr.get("reason", "Content policy violation."),
            pii_found=gr.get("pii_found", []),
        )
        return _resp(400, {
            "error": "GUARDRAIL_BLOCKED",
            "reason": gr.get("reason", "Content policy violation."),
            "blocked_by": gr.get("blocked_by"),
            "pii_found": gr.get("pii_found", []),
            "risk_score": "High",
        })

    safe_message = gr.get("output_text", user_message)

    # ── 4. Invoke Claude through Bedrock ──────────────────────────────────────
    payload = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [{"role": "user", "content": safe_message}],
    }

    try:
        response = bedrock_runtime.invoke_model(
            modelId=MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(payload),
            guardrailIdentifier=GUARDRAIL_ID,
            guardrailVersion=GUARDRAIL_VER,
            trace="ENABLED",
        )
        resp_body = json.loads(response["body"].read())
        logger.info("Bedrock response: %s", json.dumps(resp_body))

    except Exception as e:
        logger.error("Bedrock error: %s", e)
        _log_risk_event("bedrock_invocation_failed", risk_score="Medium", reason=str(e))
        return _resp(500, {"error": "Bedrock invocation failed.", "detail": str(e)})

    # ── 5. Check if Bedrock blocked the model output during invocation ────────
    if resp_body.get("stop_reason") == "guardrail_intervened":
        _log_risk_event(
            "output_blocked",
            risk_score="High",
            blocked_by="bedrock_output_guardrail",
            reason="Model response blocked by content policy.",
        )
        return _resp(400, {
            "error": "GUARDRAIL_BLOCKED",
            "reason": "Model response blocked by content policy.",
            "blocked_by": "bedrock_output_guardrail",
            "risk_score": "High",
        })

    # ── 6. Extract reply and token usage ──────────────────────────────────────
    try:
        reply = resp_body["content"][0]["text"]
        input_tokens = resp_body["usage"]["input_tokens"]
        output_tokens = resp_body["usage"]["output_tokens"]
    except (KeyError, IndexError):
        _log_risk_event("unexpected_bedrock_response", risk_score="Medium")
        return _resp(502, {"error": "Unexpected Bedrock response shape.", "raw": resp_body})

    # ── 7. Output guardrail: check model response before sending ──────────────
    output_gr = _apply_guardrail(reply, source="OUTPUT")
    _log_risk_event(
        "output_checked",
        risk_score=input_risk_score,
        blocked_by=output_gr.get("blocked_by"),
        guardrail_action=output_gr.get("action"),
    )

    if output_gr["action"] == "GUARDRAIL_INTERVENED":
        _log_risk_event(
            "output_blocked",
            risk_score="High",
            blocked_by=output_gr.get("blocked_by"),
            reason=output_gr.get("reason", "Unsafe model response."),
        )
        return _resp(400, {
            "error": "GUARDRAIL_BLOCKED",
            "reason": output_gr.get("reason", "Unsafe model response."),
            "blocked_by": output_gr.get("blocked_by"),
            "risk_score": "High",
        })

    safe_reply = output_gr.get("output_text", reply)

    # ── 8. Hallucination warning ──────────────────────────────────────────────
    hallucination_flag = has_hallucination_warning(safe_reply)
    if hallucination_flag:
        _log_risk_event(
            "hallucination_warning_triggered",
            risk_score=input_risk_score,
            reason="uncertain_or_unsupported_language_detected",
        )

    # ── 9. Return final safe response ─────────────────────────────────────────
    _log_risk_event(
        "response_returned",
        risk_score=input_risk_score,
        hallucination_warning=hallucination_flag,
    )

    return _resp(200, {
        "reply": safe_reply,
        "model": MODEL_ID,
        "risk_score": input_risk_score,
        "hallucination_warning": hallucination_flag,
        "guardrail": {
            "id": GUARDRAIL_ID,
            "version": GUARDRAIL_VER,
            "input_passed": True,
            "output_passed": True,
        },
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        },
    })


# ── Risk score helper ─────────────────────────────────────────────────────────
def calculate_risk_score(user_message: str, pii_found=None, blocked_by=None) -> str:
    """
    Classifies requests as Low, Medium, or High risk.
    Low: normal request
    Medium: PII detected/anonymized or guardrail signal without blocking
    High: deny-list, prompt attack, harmful content, or blocked request
    """
    pii_found = pii_found or []
    lowered = user_message.lower()

    if blocked_by in ["deny_list", "word_policy", "content_policy", "prompt_attack", "topic_policy"]:
        return "High"

    if any(term in lowered for term in HIGH_RISK_TERMS):
        return "High"

    if pii_found:
        return "Medium"

    if blocked_by in ["pii_policy", "bedrock_guardrail"]:
        return "Medium"

    return "Low"


# ── Hallucination warning helper ──────────────────────────────────────────────
def has_hallucination_warning(reply: str) -> bool:
    """
    Simple warning method for uncertain or unsupported language.
    This does not prove hallucination; it only flags answers that may need review.
    """
    lowered = reply.lower()
    return any(phrase in lowered for phrase in UNCERTAIN_PHRASES)


# ── Risk-event logging helper ─────────────────────────────────────────────────
def _log_risk_event(event_type: str, **kwargs) -> None:
    """Logs all important guardrail and risk events to CloudWatch."""
    log_record = {
        "event_type": event_type,
        **kwargs,
    }
    logger.info("RISK_EVENT: %s", json.dumps(log_record))


# ── Guardrail helper ──────────────────────────────────────────────────────────
def _apply_guardrail(text: str, source: str = "INPUT") -> dict:
    try:
        resp = bedrock_runtime.apply_guardrail(
            guardrailIdentifier=GUARDRAIL_ID,
            guardrailVersion=GUARDRAIL_VER,
            source=source,
            content=[{"text": {"text": text}}],
        )
        action = resp.get("action", "NONE")
        outputs = resp.get("outputs", [])
        assessments = resp.get("assessments", [{}])
        output_text = outputs[0]["text"] if outputs else text
        assessment = assessments[0] if assessments else {}

        blocked_by = "bedrock_guardrail"
        reason = "Content policy violation."
        pii_found = []

        if assessment.get("topicPolicy", {}).get("topics"):
            blocked_by, reason = "topic_policy", "Message is off-topic."

        if assessment.get("contentPolicy", {}).get("filters"):
            blocked_by, reason = "content_policy", "Harmful or toxic content detected."

        if assessment.get("wordPolicy", {}).get("customWords"):
            blocked_by, reason = "word_policy", "Message contains a disallowed word."

        if assessment.get("sensitiveInformationPolicy", {}).get("piiEntities"):
            pii_found = [
                entity.get("type")
                for entity in assessment["sensitiveInformationPolicy"]["piiEntities"]
            ]
            if action == "GUARDRAIL_INTERVENED":
                blocked_by, reason = "pii_policy", "Sensitive personal information detected."

        return {
            "action": action,
            "blocked_by": blocked_by,
            "reason": reason,
            "pii_found": pii_found,
            "output_text": output_text,
        }

    except Exception as e:
        # Fail-open for development so the app still runs if ApplyGuardrail fails.
        # For production, you can change this to fail-closed.
        logger.error("ApplyGuardrail failed (fail-open): %s", e)
        _log_risk_event("apply_guardrail_failed", risk_score="Medium", source=source, reason=str(e))
        return {
            "action": "NONE",
            "blocked_by": None,
            "reason": "Guardrail check failed.",
            "pii_found": [],
            "output_text": text,
        }


# ── Response helper ───────────────────────────────────────────────────────────
def _resp(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }
