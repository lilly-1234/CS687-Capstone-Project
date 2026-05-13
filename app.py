#!/usr/bin/env python3

# Import the AWS CDK library
# CDK (Cloud Development Kit) is used to define cloud infrastructure using Python code
import aws_cdk as cdk

# Import the custom stack class from the stacks folder
# This stack contains all AWS resources such as Lambda, API Gateway, Bedrock, etc.
from stacks.bedrock_stack import BedrockAgentStack
from stacks.bedrock_stack import BedrockAgentStack

# Create the CDK application object
# This acts as the root container for all stacks in the project
app = cdk.App()

# Create an instance of the BedrockAgentStack
# Parameters:
#   app  -> Parent CDK application
BedrockAgentStack(
    app,
    "BedrockAgentStack",

    # Define the AWS account and region where resources will be deployed
    env=cdk.Environment(
        account="396913716336",
        region="us-east-1",
    ),
)

#CDK converts Python infrastructure code into deployable CloudFormation templates
app.synth()
