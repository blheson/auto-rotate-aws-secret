import boto3
import logging
import json
import jwt
from datetime import datetime, timedelta, timezone
from jwt import ExpiredSignatureError, InvalidTokenError

SECRET_KEY = "a-string-secret-at-least-256-bits-long" #this should be changed and stored securely
ALGORITHM = 'HS256'
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    
    logger.info(f" event {event}")

    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']
    
    # Setup the client
    service_client = boto3.client('secretsmanager')

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    
    if not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    
    # Get versions
    versions = metadata['VersionIdsToStages']

    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
    
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
    
    
    
    if step == "createSecret":
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")
 
 
def create_secret(service_client, arn, token):

    try:
        
        # This is the version that is being worked on
        service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:

        user_data = {
            "user_id": "177f5a63-1497-4808-a315-a7d90683df14",
            "role": "developer"
        }
        
        new_token = generate_jwt_token(user_data, SECRET_KEY)
        # Put the secret
        # third_party_service_key should be replaced with the actual key name used in secrets manager
        service_client.put_secret_value(
            SecretId=arn, 
            ClientRequestToken=token, 
            SecretString=json.dumps({
                "third_party_service_key": new_token
            }),
            VersionStages=['AWSPENDING'])
        
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))

def generate_jwt_token(payload, secret_key, algorithm="HS256"):

    now = datetime.now(timezone.utc)
    expiry = now + timedelta(days=30)

    token_payload = {
        **payload,
        "iat": int(now.timestamp()),     # issued at
        "exp": int(expiry.timestamp()),  # expires at
    }

    token = jwt.encode(token_payload, secret_key, algorithm=algorithm)
    return token


def set_secret(service_client, arn, token):
    # This is where the secret should be set in the service
    pass


def test_secret(service_client, arn, token):
    # Retrieve the AWSPENDING version of the secret
    try:
        response = service_client.get_secret_value(
            SecretId=arn, 
            VersionId=token, 
            VersionStage="AWSPENDING"
        )
        parsed_result = json.loads(response['SecretString'])
        jwt_token = parsed_result['third_party_service_key']
        logger.info("testSecret: Successfully retrieved secret for ARN %s and version %s." % (arn, token))
        
        # Validate the JWT token
        validate_jwt_token(jwt_token, SECRET_KEY)
        logger.info("testSecret: Successfully validated JWT token for version %s." % token)
        
    except service_client.exceptions.ResourceNotFoundException:
        logger.error("testSecret: Secret version %s not found for ARN %s." % (token, arn))
        raise ValueError("Secret version %s not found for ARN %s." % (token, arn))
    except ValueError as e:
        logger.error("testSecret: JWT validation failed - %s" % str(e))
        raise
    
def validate_jwt_token(token, secret_key, algorithms=("HS256",)):
    try:
        options={"require": ["exp", "iat"]}
        
        logger.info(f"token:{token} secret_key:{secret_key} algorithms:{algorithms} options: {options}")
        
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=algorithms,
            options=options
        )
        logger.info(f" payload: {payload}")
        return payload

    except ExpiredSignatureError:
        raise ValueError("JWT token has expired")

    except InvalidTokenError as e:
        raise ValueError(f"Invalid JWT token: {str(e)}")

def finish_secret(service_client, arn, token):
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, 
                                               VersionStage="AWSCURRENT", 
                                               MoveToVersionId=token, 
                                               RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))
    

