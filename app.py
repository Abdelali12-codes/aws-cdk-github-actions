#!/usr/bin/env python3
import os
import sys
import aws_cdk as cdk
from cdk_stack import CDKStack
import config



cdk_env = cdk.Environment(region=config.REGION, account=config.ACCOUNT)

app = cdk.App()
vpc_stack = CDKStack(app, "CDKStack", env=cdk_env)


app.synth()
