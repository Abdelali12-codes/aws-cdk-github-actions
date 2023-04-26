from aws_cdk import (
    # Duration,
    Stack,
    CfnTag,
    Fn,
    # aws_sqs as sqs,
)

import os
from constructs import Construct
from aws_cdk import aws_kinesis as kinesis
from aws_cdk import aws_lambda as _lambda
from aws_cdk.aws_lambda_event_sources import KinesisEventSource
import aws_cdk.aws_certificatemanager as certificate
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_iam as iam
import aws_cdk.aws_route53 as route53
import aws_cdk.aws_cognito as cognito
import aws_cdk.aws_cognito_identitypool_alpha as identity
import aws_cdk.custom_resources as custom
import aws_cdk.aws_opensearchservice as es
import aws_cdk as cdk
from config import (
      kinesisconf,
      lambdaconf,
      domain,
      cognitopool,
      REGION
    )



class CDKStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        self.userPool = cognito.UserPool(self,"CognitoUserPool", 
            user_pool_name = cognitopool["userpoolname"]
        )
        
        self.idPool = cognito.CfnIdentityPool(self, "Cognitoidentitypool",
           cognito_identity_providers = [],
           allow_unauthenticated_identities= False
         )
         
        cognito.UserPoolDomain(self,"CognitoUserPoolDomain", 
           user_pool = self.userPool,
           cognito_domain = cognito.CognitoDomainOptions(
                domain_prefix=cognitopool["domain-prefix"]
            )
        )
         
        self.esRole = iam.Role(self, "ESRole",
           role_name="aws-es-cognito-role",
           assumed_by= iam.ServicePrincipal("es.amazonaws.com"),
           managed_policies = [iam.ManagedPolicy.from_aws_managed_policy_name("AmazonESCognitoAccess")]
        )
        
        self.esAdminuserRole = iam.Role(self, "ESAdminRole",
            role_name="aws-es-admin",
            assumed_by=iam.FederatedPrincipal("cognito-identity.amazonaws.com", {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": self.idPool.ref
                },
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "authenticated"
                }
            },"sts:AssumeRoleWithWebIdentity")
        )
        
        self.esLimitedAccess = iam.Role(self, "ESLimitedRole",
            role_name="aws-es-limited",
            assumed_by=iam.FederatedPrincipal("cognito-identity.amazonaws.com", {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": self.idPool.ref
                },
                "ForAnyValue:StringLike": {
                    "cognito-identity.amazonaws.com:amr": "authenticated"
                }
            },"sts:AssumeRoleWithWebIdentity")
        )
        
        cognito.CfnUserPoolGroup(self, "CfnUserPoolGroup",
            user_pool_id=self.userPool.user_pool_id,
            group_name="Admins",
            role_arn=self.esAdminuserRole.role_arn
        )
        
        self.provider_url = f"cognito-idp.{REGION}.amazonaws.com/{self.userPool.user_pool_id}"
        
        
        self.domain_cert = certificate.Certificate.from_certificate_arn(self, "DomainCert", domain["certificate_arn"] )
    
        self.domain = es.Domain(self, "ESDomain",
            domain_name = domain["es_domain_name"],
            custom_endpoint = es.CustomEndpointOptions(
                domain_name = domain["custom_domain"],
                certificate = self.domain_cert,
                hosted_zone  = route53.HostedZone.from_hosted_zone_attributes(self, "HostedZone",
                  hosted_zone_id=domain["hostedzone_id"],zone_name=domain["hostedzone_name"])
            ),
            capacity= domain["capacity"],
            fine_grained_access_control= es.AdvancedSecurityOptions(
                master_user_arn=self.esAdminuserRole.role_arn
            ),
            enforce_https=True,
            cognito_dashboards_auth=es.CognitoOptions(
                identity_pool_id=self.idPool.ref,
                user_pool_id=self.userPool.user_pool_id,
                role=self.esRole
            ),
            logging= es.LoggingOptions(
                audit_log_enabled=True,
                slow_search_log_enabled=True,
                app_log_enabled=True,
                slow_index_log_enabled=True
            ),
            version=domain["version"],
            ebs=domain["ebs"],
            node_to_node_encryption=True,
            encryption_at_rest=es.EncryptionAtRestOptions(
                enabled=True
            ),
            access_policies = [
              iam.PolicyStatement(
                  effect=iam.Effect.ALLOW,
                  principals= [iam.AnyPrincipal()],
                  actions=["es:ESHttp*"],
                  resources=["*"]
                )
            ]
        )
        
        self.aws_custom = custom.AwsCustomResource(self, "AwsCustomResource",
            on_create=custom.AwsSdkCall(
                service="CognitoIdentityServiceProvider",
                action="listUserPoolClients",
                parameters={
                    "UserPoolId": self.userPool.user_pool_id
                },
                physical_resource_id=custom.PhysicalResourceId.of("CleintId-AwsCustomResource")
            ),
            policy=custom.AwsCustomResourcePolicy.from_sdk_calls(
                resources=[self.userPool.user_pool_arn]
            )
        )
        self.aws_custom.node.add_dependency(self.domain)
        
        userPoolclientId = self.aws_custom.get_response_field("UserPoolClients.0.ClientId")
        
        provider = f"cognito-idp.{REGION}.amazonaws.com/{self.userPool.user_pool_id}:{userPoolclientId}"
        
        cognito.CfnIdentityPoolRoleAttachment(self, "ESIdentityPoolRoleAttachment",
            identity_pool_id=self.idPool.ref,
            role_mappings={
                "UserPool": cognito.CfnIdentityPoolRoleAttachment.RoleMappingProperty(
                    type="Token",
                    ambiguous_role_resolution="Deny",
                    identity_provider=provider
                )
            },
            roles={
                'authenticated': self.esLimitedAccess.role_arn
            }
        )
        
        self.stream = kinesis.Stream(
            self, "KinesisStream",
            stream_name=kinesisconf['streamname']
        )

        # Create a Lambda Function
        self.function = _lambda.Function(
            self, "LambdaFunction",
            runtime=_lambda.Runtime.PYTHON_3_7,
            handler="main.handler",
            code=_lambda.Code.from_asset("src"),
            environment={
                "es_host": f"https://{domain['custom_domain']}"
            },
            function_name=lambdaconf['lambdaname']
        )

        # Add permissions to the Lambda function to read from the Kinesis Stream
        self.function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                "kinesis:DescribeStream",
                "kinesis:DescribeStreamSummary",
                "kinesis:GetRecords",
                "kinesis:GetShardIterator",
                "kinesis:ListShards",
                "kinesis:ListStreams",
                "kinesis:SubscribeToShard"
            ],
                resources=[self.stream.stream_arn]
            )
        )
        self.function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                "es:ESHttp*"
                ],
                resources=["*"]
            )
        )

        # Add a Kinesis trigger to the Lambda function
        self.function.add_event_source(
            KinesisEventSource(
                self.stream,
                starting_position=_lambda.StartingPosition.LATEST
            )
        )



