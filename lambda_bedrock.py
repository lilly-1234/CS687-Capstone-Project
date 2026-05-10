import json
import os
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── Config from CDK-injected environment variables ────────────────────────────
REGION         = os.environ.get("AWS_REGION_NAME", "us-east-1")
MODEL_ID       = os.environ.get("MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")
GUARDRAIL_ID   = os.environ.get("GUARDRAIL_ID", "")
GUARDRAIL_VER  = os.environ.get("GUARDRAIL_VERSION", "DRAFT")

# Pre-flight deny list (cheap local check before any API call)
DENY_LIST = [
    "jailbreak",
    "ignore previous instructions",
    "internal-secret",
    # ← Add your terms here; CDK word policy is the authoritative enforcer
]

bedrock_runtime = boto3.client("bedrock-runtime", region_name=REGION)


def lambda_handler(event, context):
    """
    API Gateway (HTTP API) → Lambda → Bedrock Guardrail → Claude

    POST /chat
    Body: { "message": "...", "max_tokens": 1024, "system": "..." }
    """
    logger.info("Event: %s", json.dumps(event))

    # ── 1. Parse body ─────────────────────────────────────────────────────────
    try:
        body = event.get("body") or "{}"
        if isinstance(body, str):
            body = json.loads(body)

        user_message = body.get("message", "").strip()
        if not user_message:
            return _resp(400, {"error": "'message' field is required."})

        max_tokens    = int(body.get("max_tokens", 1024))
        system_prompt = body.get("system", "You are a helpful assistant.")

    except (json.JSONDecodeError, ValueError) as e:
        return _resp(400, {"error": f"Invalid request body: {e}"})

    # ── 2. Local deny-list (fast, zero-cost first gate) ───────────────────────
    lowered = user_message.lower()
    for term in DENY_LIST:
        if term.lower() in lowered:
            logger.warning("Deny-list match: '%s'", term)
            return _resp(400, {
                "error"     : "GUARDRAIL_BLOCKED",
                "reason"    : "Message contains a disallowed term.",
                "blocked_by": "deny_list",
            })

    # ── 3. Bedrock guardrail — apply to INPUT before model call ───────────────
    gr = _apply_guardrail(user_message, source="INPUT")
    if gr["action"] == "GUARDRAIL_INTERVENED":
        logger.warning("Guardrail blocked INPUT: %s", gr)
        return _resp(400, {
            "error"     : "GUARDRAIL_BLOCKED",
            "reason"    : gr.get("reason", "Content policy violation."),
            "blocked_by": gr.get("blocked_by"),
            "pii_found" : gr.get("pii_found", []),
        })

    safe_message = gr.get("output_text", user_message)

    # ── 4. Invoke Claude (guardrail also applied server-side) ─────────────────
    payload = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens"       : max_tokens,
        "system"           : system_prompt,
        "messages"         : [{"role": "user", "content": safe_message}],
    }

    try:
        response = bedrock_runtime.invoke_model(
            modelId             = MODEL_ID,
            contentType         = "application/json",
            accept              = "application/json",
            body                = json.dumps(payload),
            guardrailIdentifier = GUARDRAIL_ID,
            guardrailVersion    = GUARDRAIL_VER,
            trace               = "ENABLED",
        )
        resp_body = json.loads(response["body"].read())
        logger.info("Bedrock response: %s", json.dumps(resp_body))

    except Exception as e:
        logger.error("Bedrock error: %s", e)
        return _resp(500, {"error": "Bedrock invocation failed.", "detail": str(e)})

    # ── 5. Check if model output was blocked ──────────────────────────────────
    if resp_body.get("stop_reason") == "guardrail_intervened":
        return _resp(400, {
            "error"     : "GUARDRAIL_BLOCKED",
            "reason"    : "Model response blocked by content policy.",
            "blocked_by": "bedrock_output_guardrail",
        })

    # ── 6. Return reply ───────────────────────────────────────────────────────
    try:
        reply         = resp_body["content"][0]["text"]
        input_tokens  = resp_body["usage"]["input_tokens"]
        output_tokens = resp_body["usage"]["output_tokens"]
    except (KeyError, IndexError) as e:
        return _resp(502, {"error": "Unexpected Bedrock response shape.", "raw": resp_body})

    return _resp(200, {
        "reply": reply,
        "model": MODEL_ID,
        "guardrail": {"id": GUARDRAIL_ID, "version": GUARDRAIL_VER, "passed": True},
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
    })


# ── Guardrail helper ──────────────────────────────────────────────────────────
def _apply_guardrail(text: str, source: str = "INPUT") -> dict:
    try:
        resp        = bedrock_runtime.apply_guardrail(
            guardrailIdentifier=GUARDRAIL_ID,
            guardrailVersion=GUARDRAIL_VER,
            source=source,
            content=[{"text": {"text": text}}],
        )
        action      = resp.get("action", "NONE")
        outputs     = resp.get("outputs", [])
        assessments = resp.get("assessments", [{}])
        output_text = outputs[0]["text"] if outputs else text
        assessment  = assessments[0] if assessments else {}

        blocked_by, reason, pii_found = "bedrock_guardrail", "Content policy violation.", []

        if assessment.get("topicPolicy", {}).get("topics"):
            blocked_by, reason = "topic_policy", "Message is off-topic."
        if assessment.get("contentPolicy", {}).get("filters"):
            blocked_by, reason = "content_policy", "Harmful or toxic content detected."
        if assessment.get("wordPolicy", {}).get("customWords"):
            blocked_by, reason = "word_policy", "Message contains a disallowed word."
        if assessment.get("sensitiveInformationPolicy", {}).get("piiEntities"):
            pii_found = [e["type"] for e in assessment["sensitiveInformationPolicy"]["piiEntities"]]
            if action == "GUARDRAIL_INTERVENED":
                blocked_by, reason = "pii_policy", "Sensitive personal information detected."

        return {"action": action, "blocked_by": blocked_by, "reason": reason,
                "pii_found": pii_found, "output_text": output_text}

    except Exception as e:
        logger.error("ApplyGuardrail failed (fail-open): %s", e)
        return {"action": "NONE", "output_text": text}


# ── Response helper ───────────────────────────────────────────────────────────
def _resp(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type"               : "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }
