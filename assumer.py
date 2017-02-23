import logging
logger = logging.getLogger(__name__)


class Assumer(object):
    """
    This class handles communication with the AWS STS service to acquire credentials to act in a given role.
    It takes an active boto3 connection, or any connection with a matching interface,
    to AWS STS as a construction parameter.
    client = boto3.client('sts', aws_access_key_id=os.environ.get('AWS_ACCESS_KEY'),
                              aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'))
    Assumer(connection=client)
    """
    def __init__(self, connection=None):
        self.connection = connection

    def get_assumed_role_creds(self, role_arn=None, role_session_name=None, serial_number=None, token_code=None,
                               assumed_account_id=None, user_account_id=None, role_name=None, user_name=None):
        """
        Gets temporary credentials from AWS STS for a user to act under the role they are assuming.
        :param role_arn: This is the ARN for the role in AWS, this can be generated from the Assumed_account_id and role_name
        :param role_session_name: This is an arbitrary name to give to the user's assumption of the role.
        :param serial_number: The serial number of your mfa device.  This can be generated for Virtual MFA devices only (Google Authenticator or any other MFA on a phone) via the user's account id and user name.
        :param token_code: This is the token from the MFA device
        :param assumed_account_id: The account under which the role allows the user to assume privledge.
        :param user_account_id: This is the account to which the user belongs, AKA the Ops account
        :param role_name: The name of the role in AWS that will be assumed.
        :param user_name: THe user name of the user that is assuming the role.
        :return: Returns a dictionary of credentials, which can be used with the #map_to_boto3_kwargs method to initiate a new boto3 session.
        """
        if role_arn is None:
            if assumed_account_id is None or role_name is None:
                raise TypeError('Either role_arn or assumed_account_id and role_name must be specified.')
            else:
                role_arn = self.role_arn_builder(assumed_account_id, role_name)
        if serial_number is None:
            if user_account_id is None or user_name is None:
                raise TypeError('Either serial_number or user_account_id and user_name must be specified.')
            else:
                serial_number = self.virtual_mfa_arn_builder(user_account_id, user_name)
        response = self.connection.assume_role(RoleArn=role_arn, RoleSessionName=role_session_name,
                                               SerialNumber=serial_number, TokenCode=token_code)
        logger.info(
            "User {} of account {} has assumed role {} on account {}".format(user_name, user_account_id, role_name,
                                                                             assumed_account_id))
        return response['Credentials']

    @staticmethod
    def map_to_boto3_kwargs(response):
        return {'aws_access_key_id': response['AccessKeyId'], 'aws_secret_access_key': response['SecretAccessKey'],
                'aws_session_token': response['SessionToken']}

    @staticmethod
    def role_arn_builder(account_id, role_name):
        return 'arn:aws:iam::' + account_id + ':role/' + role_name

    @staticmethod
    def virtual_mfa_arn_builder(account_id, user_name):
        return 'arn:aws:iam::' + account_id + ':mfa/' + user_name
