import aws_cdk as cdk
from aws_cdk import (
    Stack,
    Duration,
    CfnOutput,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_apigatewayv2 as apigwv2,
    aws_apigatewayv2_integrations as integrations,
    aws_logs as logs,
    aws_bedrock as bedrock,
)
from constructs import Construct


class BedrockAgentStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # ── 1. Bedrock Guardrail ──────────────────────────────────────────────
        guardrail = bedrock.CfnGuardrail(
            self,
            "AgentGuardrail",
            name="bedrock-agent-guardrail",
            description="Blocks harmful content, off-topic requests, denied words, and PII.",

            # Harmful / toxic content policy
            content_policy_config=bedrock.CfnGuardrail.ContentPolicyConfigProperty(
                filters_config=[
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="HATE",         input_strength="HIGH",   output_strength="HIGH"
                    ),
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="INSULTS",      input_strength="HIGH",   output_strength="HIGH"
                    ),
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="SEXUAL",       input_strength="HIGH",   output_strength="HIGH"
                    ),
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="VIOLENCE",     input_strength="HIGH",   output_strength="HIGH"
                    ),
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="MISCONDUCT",   input_strength="HIGH",   output_strength="HIGH"
                    ),
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="PROMPT_ATTACK", input_strength="HIGH",  output_strength="NONE"
                    ),
                ]
            ),

            # Off-topic policy — add/edit topics to match your use case
            topic_policy_config=bedrock.CfnGuardrail.TopicPolicyConfigProperty(
                topics_config=[
                    bedrock.CfnGuardrail.TopicConfigProperty(
                        name="competitor-discussion",
                        definition="Any discussion, comparison, or mention of competitor products.",
                        examples=[
                            "How does this compare to OpenAI?",
                            "Is this better than Google Gemini?",
                        ],
                        type="DENY",
                    ),
                    bedrock.CfnGuardrail.TopicConfigProperty(
                        name="financial-advice",
                        definition="Requests for personalised financial or investment advice.",
                        examples=[
                            "Should I invest in Tesla?",
                            "What stocks should I buy?",
                        ],
                        type="DENY",
                    ),
                ]
            ),

            # Deny list — custom blocked words + managed profanity list
            word_policy_config=bedrock.CfnGuardrail.WordPolicyConfigProperty(
                managed_word_lists_config=[
                    bedrock.CfnGuardrail.ManagedWordsConfigProperty(type="PROFANITY")
                ],
                words_config=[
                    bedrock.CfnGuardrail.WordConfigProperty(text="jailbreak"),
                    bedrock.CfnGuardrail.WordConfigProperty(text="ignore previous instructions"),
                    bedrock.CfnGuardrail.WordConfigProperty(text="internal-secret"),
                    # ← Add your own terms here
                ],
            ),

            # PII detection and redaction
            sensitive_information_policy_config=bedrock.CfnGuardrail.SensitiveInformationPolicyConfigProperty(
                pii_entities_config=[
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type="EMAIL",   action="ANONYMIZE"),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type="PHONE",   action="ANONYMIZE"),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type="US_SOCIAL_SECURITY_NUMBER", action="BLOCK"),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="CREDIT_DEBIT_CARD_NUMBER", action="BLOCK"
                    ),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type="AWS_ACCESS_KEY", action="BLOCK"),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type="AWS_SECRET_KEY", action="BLOCK"),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type="PASSWORD",        action="BLOCK"),
                ],
                regexes_config=[
                    bedrock.CfnGuardrail.RegexConfigProperty(
                        name="employee-id",
                        description="Internal employee ID format EMP-XXXXXX",
                        pattern=r"EMP-\d{6}",
                        action="ANONYMIZE",
                    )
                ],
            ),

            blocked_input_messaging=(
                "Your message was blocked by our content policy. "
                "Please rephrase and try again."
            ),
            blocked_outputs_messaging=(
                "I'm sorry, I can't provide a response to that request."
            ),
        )

        # Publish guardrail version (use "DRAFT" during dev, version in prod)
        guardrail_version = bedrock.CfnGuardrailVersion(
            self,
            "AgentGuardrailVersion",
            guardrail_identifier=guardrail.attr_guardrail_id,
            description="Initial production version",
        )

        # ── 2. Lambda execution role ──────────────────────────────────────────
        lambda_role = iam.Role(
            self,
            "LambdaExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"  # CloudWatch logs
                )
            ],
        )

        # Bedrock permissions — scoped to Claude Sonnet 4.5 inference profile
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["bedrock:InvokeModel", "bedrock:GetInferenceProfile"],
                resources=[
                    f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0",
                    f"arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0",
                    f"arn:aws:bedrock:{self.region}:*:inference-profile/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
                    f"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0",
                    f"arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0",
                    f"arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0",
                ],
            )
        )

        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["bedrock:ApplyGuardrail"],
                resources=[guardrail.attr_guardrail_arn],
            )
        )

        # ── 3. Lambda function ────────────────────────────────────────────────
        log_group = logs.LogGroup(
            self,
            "LambdaLogGroup",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        fn = lambda_.Function(
            self,
            "BedrockAgentFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="lambda_bedrock.lambda_handler",
            code=lambda_.Code.from_asset("lambda"),   # ./lambda/ folder
            role=lambda_role,
            timeout=Duration.seconds(30),
            memory_size=256,
            log_group=log_group,
            environment={
                "GUARDRAIL_ID":      guardrail.attr_guardrail_id,
                "GUARDRAIL_VERSION": guardrail_version.attr_version,
                "MODEL_ID":          "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
                "AWS_REGION_NAME":   self.region,
            },
        )

        # ── 4. API Gateway HTTP API ───────────────────────────────────────────
        access_log_group = logs.LogGroup(
            self,
            "ApiAccessLogGroup",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        http_api = apigwv2.HttpApi(
            self,
            "BedrockHttpApi",
            api_name="bedrock-agent-api",
            cors_preflight=apigwv2.CorsPreflightOptions(
                allow_methods=[apigwv2.CorsHttpMethod.POST, apigwv2.CorsHttpMethod.OPTIONS],
                allow_origins=["*"],          # ← Restrict to your domain in production
                allow_headers=["Content-Type", "Authorization"],
            ),
        )

        lambda_integration = integrations.HttpLambdaIntegration(
            "LambdaIntegration",
            fn,
        )

        http_api.add_routes(
            path="/chat",
            methods=[apigwv2.HttpMethod.POST],
            integration=lambda_integration,
        )

        # Default stage with access logging
        stage = apigwv2.HttpStage(
            self,
            "ProdStage",
            http_api=http_api,
            stage_name="prod",
            auto_deploy=True,
            throttle=apigwv2.ThrottleSettings(
                burst_limit=50,
                rate_limit=100,
            ),
        )

        # ── 5. Outputs ────────────────────────────────────────────────────────
        CfnOutput(self, "OutputApiUrl",
            value=f"{http_api.api_endpoint}/prod/chat",
            description="POST endpoint — send {message} JSON here",
        )
        CfnOutput(self, "OutputGuardrailId",
            value=guardrail.attr_guardrail_id,
            description="Bedrock Guardrail ID",
        )
        CfnOutput(self, "OutputGuardrailVersion",
            value=guardrail_version.attr_version,
            description="Bedrock Guardrail Version",
        )
        CfnOutput(self, "OutputLambdaFunctionName",
            value=fn.function_name,
            description="Lambda function name",
        )
        CfnOutput(self, "OutputLambdaLogGroup",
            value=log_group.log_group_name,
            description="CloudWatch log group for Lambda",
        )
