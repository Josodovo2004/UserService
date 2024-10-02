import boto3

ssm = boto3.client('ssm','us-east-1')

service='UserService'

# Getting shared key
response = ssm.get_parameter(Name='/Qickart/dev/auth-shared-key', WithDecryption=True)
sharedKey = response['Parameter']['Value']

# Getting database engine
response = ssm.get_parameter(Name='/Qickart/dev/postgresEngine')
dbEngine = response['Parameter']['Value']

# Getting database name
response = ssm.get_parameter(Name=f'/Qickart/dev/{service}/NameDB')
nameDb = response['Parameter']['Value']

# Getting database user
response = ssm.get_parameter(Name=f'/Qickart/dev/{service}/UserDB')
userDb = response['Parameter']['Value']

# Getting encrypted database password with decryption
response = ssm.get_parameter(Name=f'/Qickart/dev/{service}/passwordDB', WithDecryption=True)
passwordDb = response['Parameter']['Value']

# Getting database port
response = ssm.get_parameter(Name=f'/Qickart/dev/{service}/PORTDB')
portDb = response['Parameter']['Value']

# Getting database host
response = ssm.get_parameter(Name=f'/Qickart/dev/{service}/HOSTDB')
hostDb = response['Parameter']['Value']