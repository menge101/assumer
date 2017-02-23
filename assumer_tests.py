from assume_role import Assumer
import boto3
from builtins import input
from moto import mock_sts
import os
import unittest


class AssumerTestCase(unittest.TestCase):
    def setUp(self):
        self.mock = mock_sts()
        self.mock.start()
        self.valid_assumer_keys = ['role_arn', 'role_session_name', 'serial_number', 'token', 'account_id',
                                   'role_name', 'username']
        client = boto3.client('sts', aws_access_key_id=os.environ.get('AWS_ACCESS_KEY'),
                              aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'))
        self.assume = Assumer(connection=client)

    def tearDown(self):
        self.mock.stop()

    def test_assume_role(self):
        ops_account_id = '494255855136'
        username = 'NathanMenge'
        assumed_account_id = '408520305116'
        role_name = 'AdminAccess'
        role_arn = Assumer.role_arn_builder(assumed_account_id, role_name)
        role_session_name = 'Testing_Role_assumption'
        serial = Assumer.virtual_mfa_arn_builder(ops_account_id, username)
        token = '097833'
        if token is None:
            token = input("Enter MFA Code")
        response = self.assume.get_assumed_role_creds(role_arn=role_arn, role_session_name=role_session_name,
                                                      serial_number=serial, token_code=token)
        self.assertIn('AccessKeyId', response)
        self.assertIn('SecretAccessKey', response)
        self.assertIn('SessionToken', response)

    def test_assume_role_easy(self):
        ops_account_id = '494255855136'
        username = 'NathanMenge'
        assumed_account_id = '408520305116'
        role_name = 'AdminAccess'
        role_session_name = 'Testing_Role_assumption'
        token = '097833'
        if token is None:
            token = input("Enter MFA Code")
        response = self.assume.get_assumed_role_creds(role_session_name=role_session_name, token_code=token,
                                                      assumed_account_id=assumed_account_id,
                                                      user_account_id=ops_account_id, role_name=role_name,
                                                      user_name=username)
        self.assertIn('AccessKeyId', response)
        self.assertIn('SecretAccessKey', response)
        self.assertIn('SessionToken', response)

    def test_proper_exception_messages(self):
        ops_account_id = '494255855136'
        username = 'NathanMenge'
        assumed_account_id = '408520305116'
        role_name = 'AdminAccess'
        role_arn = Assumer.role_arn_builder(assumed_account_id, role_name)
        role_session_name = 'Testing_Role_assumption'
        serial = Assumer.virtual_mfa_arn_builder(ops_account_id, username)
        no_role_arn_msg = 'Either role_arn or assumed_account_id and role_name must be specified.'
        no_serial_msg = 'Either serial_number or user_account_id and user_name must be specified.'
        token = '097833'
        if token is None:
            token = input("Enter MFA Code")
        try:
            self.assume.get_assumed_role_creds(
                **{'role_session_name': role_session_name, 'serial_number': serial, 'token_code': token,
                   'assumed_account_id': assumed_account_id})
        except TypeError as te:
            self.assertEqual(no_role_arn_msg, te.message)
        try:
            self.assume.get_assumed_role_creds(
                **{'role_session_name': role_session_name, 'serial_number': serial, 'token_code': token,
                   'role_name': role_name})
        except TypeError as te:
            self.assertEqual(no_role_arn_msg, te.message)
        try:
            self.assume.get_assumed_role_creds(
                **{'role_arn': role_arn, 'role_session_name': role_session_name, 'token_code': token,
                   'user_account_id': ops_account_id})
        except TypeError as te:
            self.assertEqual(no_serial_msg, te.message)
        try:
            self.assume.get_assumed_role_creds(
                **{'role_arn': role_arn, 'role_session_name': role_session_name, 'token_code': token,
                   'user_name': username})
        except TypeError as te:
            self.assertEqual(no_serial_msg, te.message)
