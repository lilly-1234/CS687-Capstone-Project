#!/usr/bin/env python3
import aws_cdk as cdk
from stacks.bedrock_stack import BedrockAgentStack

app = cdk.App()

BedrockAgentStack(
    app,
    "BedrockAgentStack",
    env=cdk.Environment(
        account="396913716336",
        region="us-east-1",
    ),
)

app.synth()
