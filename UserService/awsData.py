import boto3

ssm = boto3.client('ssm','us-east-1')

service='UserService'

# Getting shared key
response = ssm.get_parameter(Name='/Qickart/dev/auth-shared-key', WithDecryption=True)
sharedKey = response['Parameter']['Value']

# Getting encrypted database password with decryption
response = ssm.get_parameter(Name=f'/Qickart/dev/{service}/passwordDB', WithDecryption=True)
passwordDb = response['Parameter']['Value']