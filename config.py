import aws_cdk.aws_ec2 as ec2
import aws_cdk as cdk
import aws_cdk.aws_opensearchservice as es
# basic VPC configs


REGION = 'us-west-2'
ACCOUNT = '080266302756'

kinesisconf = {
    'streamname': "kinesis-stream"
}

lambdaconf  = {
    'lambdaname': "kinesis-lambda"
}


domain = {
    "capacity": es.CapacityConfig(
                data_node_instance_type = "t3.small.search",
                data_nodes=1
            ),
    "version": es.EngineVersion.ELASTICSEARCH_7_8,
    "ebs": es.EbsOptions(
                volume_size=100,
                volume_type=ec2.EbsDeviceVolumeType.GP2
            ),
    "es_domain_name": "opensearch-cognito",
    "custom_domain": "escognito.abdelalitraining.com",
    "certificate_arn": "arn:aws:acm:us-west-2:080266302756:certificate/b438ee4b-3423-4a8a-91f7-2cbf4e5c55d2",
    "hostedzone_id":"Z05045244G4M5OFGHB4C",
    "hostedzone_name":"abdelalitraining.com"
}

cognitopool = {
    "userpoolname":"aws-opensearch-pool",
    "domain-prefix":"opensearch-kinesis",
    "identityname": "aws-openserarch-identity"
}