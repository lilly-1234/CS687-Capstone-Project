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

# Create the main stack class
class BedrockAgentStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        
        # Initialize parent stack
        super().__init__(scope, construct_id, **kwargs)

        # 1. CREATE BEDROCK GUARDRAIL

        # Guardrail protects the LLM from harmful inputs/outputs
        guardrail = bedrock.CfnGuardrail(
            self,
            "AgentGuardrail",
            name="bedrock-agent-guardrail",
            description="Blocks harmful content, off-topic requests, denied words, and PII.",

            # Harmful / toxic content policy
            content_policy_config=bedrock.CfnGuardrail.ContentPolicyConfigProperty(
                
                # Filters for harmful content
                filters_config=[

                    # Hate speech filter
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="HATE",         
                        input_strength="HIGH",   
                        output_strength="HIGH"
                    ),

                    # Insults filter
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="INSULTS",      
                        input_strength="HIGH",   
                        output_strength="HIGH"
                    ),
                    
                    # Sexual content filter
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="SEXUAL",       
                        input_strength="HIGH",   
                        output_strength="HIGH"
                    ),

                    # Violence filter
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="VIOLENCE",     
                        input_strength="HIGH",   
                        output_strength="HIGH"
                    ),

                    # Misconduct filter
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="MISCONDUCT",   
                        input_strength="HIGH",   
                        output_strength="HIGH"
                    ),
                    
                    # Prompt injection protection
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="PROMPT_ATTACK", input_strength="HIGH",  output_strength="NONE"
                    ),
                ]
            ),

            # Off-topic policy
            # Blocks restricted topic
            topic_policy_config=bedrock.CfnGuardrail.TopicPolicyConfigProperty(
                topics_config=[

                     # Block competitor comparisons
                    bedrock.CfnGuardrail.TopicConfigProperty(
                        name="competitor-discussion",
                        definition="Any discussion, comparison, or mention of competitor products.",
                        examples=[
                            "How does this compare to OpenAI?",
                            "Is this better than Google Gemini?",
                        ],
                        type="DENY",
                    ),

                    # Block financial advice
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

                # Custom blocked words
                words_config=[
                    bedrock.CfnGuardrail.WordConfigProperty(text="jailbreak"),
                    bedrock.CfnGuardrail.WordConfigProperty(text="ignore previous instructions"),
                    bedrock.CfnGuardrail.WordConfigProperty(text="internal-secret"),
                ],
            ),

            # PII detection and redaction
            sensitive_information_policy_config=bedrock.CfnGuardrail.SensitiveInformationPolicyConfigProperty(
               
                # PII detection rules
                pii_entities_config=[

                    # Hide emails, phone numbers, block SSN, card numbers
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type="EMAIL",   action="ANONYMIZE"),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type="PHONE",   action="ANONYMIZE"),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type="US_SOCIAL_SECURITY_NUMBER", action="BLOCK"),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(
                        type="CREDIT_DEBIT_CARD_NUMBER", action="BLOCK"
                    ),

                    # Block AWS keys, AWS secret keys, passwords
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type="AWS_ACCESS_KEY", action="BLOCK"),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type="AWS_SECRET_KEY", action="BLOCK"),
                    bedrock.CfnGuardrail.PiiEntityConfigProperty(type="PASSWORD",        action="BLOCK"),
                ],
                
                # Custom regex pattern
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
                "I'm sorry, I can't provide a response."
            ),
        )
        
        # 2. CREATE GUARDRAIL VERSION

        # Publish guardrail version
        guardrail_version = bedrock.CfnGuardrailVersion(
            self,
            "AgentGuardrailVersion",

            # Link to guardrail
            guardrail_identifier=guardrail.attr_guardrail_id,
            description="Initial production version",
        )
        
        # 3. CREATE IAM ROLE FOR LAMBDA
        
        # Lambda execution role
        lambda_role = iam.Role(
            self,
            "LambdaExecutionRole",

            # Lambda service can assume this role
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),

            # Basic logging permissions
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"  # CloudWatch logs
                )
            ],
        )

        # Allow Lambda to invoke Bedrock model
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                
                # Allowed Bedrock actions
                actions=["bedrock:InvokeModel", "bedrock:GetInferenceProfile"],
                
                # Claude model ARNs
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
        
        # Allow Lambda to apply guardrai
        lambda_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["bedrock:ApplyGuardrail"],
                resources=[guardrail.attr_guardrail_arn],
            )
        )

        # 4. CREATE CLOUDWATCH LOG GROUP
        log_group = logs.LogGroup(
            self,
            "LambdaLogGroup",

            # Keep logs for one week
            retention=logs.RetentionDays.ONE_WEEK,

            # Delete logs when stack is removed
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        
        # 5. CREATE LAMBDA FUNCTION
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

        # 6. CREATE API GATEWAY

        # API log group
        access_log_group = logs.LogGroup(
            self,
            "ApiAccessLogGroup",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        
        # Create HTTP API
        http_api = apigwv2.HttpApi(
            self,
            "BedrockHttpApi",
            api_name="bedrock-agent-api",
            
            # Enable CORS
            cors_preflight=apigwv2.CorsPreflightOptions(
                allow_methods=[apigwv2.CorsHttpMethod.POST, apigwv2.CorsHttpMethod.OPTIONS],
                allow_origins=["*"],          # ← Restrict to your domain in production
                allow_headers=["Content-Type", "Authorization"],
            ),
        )
        
        # 7. CONNECT API TO LAMBDA
        lambda_integration = integrations.HttpLambdaIntegration(
            "LambdaIntegration",
            fn,
        )
    
        # Create /chat endpoint
        http_api.add_routes(
            path="/chat",
            methods=[apigwv2.HttpMethod.POST],
            integration=lambda_integration,
        )

        # 8. CREATE API STAGE
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

        # 9. OUTPUT VALUES 
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
