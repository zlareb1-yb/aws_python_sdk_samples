# -*- coding: utf-8 -*-
import boto3

# pylint: disable=C0301, W0105
class Aws(object):
    """Make a new Aws handle and return"""

    error_message_map = {
        "not authorized": "Provided settings don't have sufficient permissions for AWS EC2.",
        "validate the provided access credentials": "Provided credentials are incorrect.",
        "request has expired": "Time of the machine is incorrect",
        "certificate verify failed": "AWS don't have a valid SSL certificate",
        "failure in name resolution": "Internet/DNS is not working",
        "check your aws secret access key": "Provided AWS secret access key is incorrect"
    }

    def __init__(self, region_name, aws_access_key_id, aws_secret_access_key):
        """Get the AWS instance
         Args:
            region_name (String), aws_access_key_id(String), aws_secret_access_key(String): AWS credentials
         Returns:
         Raises:
        """
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.ec2_conn = boto3.client('ec2', region_name, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
        self.iam_conn = boto3.client('iam', region_name, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    def get_user_name(self):
        """Get the username of the user with this access_key, secretkey
         Args:
         Returns:
            Username (String)
         Raises:
        """
        key_info = self.iam_conn.get_access_key_last_used(AccessKeyId=self.aws_access_key_id)
        return key_info['UserName']

    """
    Get all the user policies attached to this user
    """
    def get_user_policies(self):
        """Get all the user policies attached to this user
         Args:
         Returns:
            policies (list)
         Raises:
            None
        """
        user_name = self.get_user_name()
        policy = self.iam_conn.list_attached_user_policies(UserName=user_name)
        """
        Boto3 returns attached policies as the first key,value pair in the dict
        """
        policy_values = policy.values()[0]
        policy_count = len(policy_values)
        policies = []
        for idx in range(policy_count):
            policy_name = policy_values[idx]['PolicyName']
            policies.append(policy_name)

        return policies

    def verify(self):
        """Verify if the user has the IAM read access and EC2 full access permissions so that he can launch a Blueprint
         Args:
         Returns:
            pass_role_check (Bool)
         Raises:
            Exception: Check your IAM permissions
        """
        user_policies = self.get_user_policies()
        user_policy_set = set(user_policies)

        iam_policies = set(['IAMReadOnlyAccess', 'IAMFullAccess'])
        ec2_policy = set(['AmazonEC2FullAccess'])
        pass_role_policy = set(['PassOnRolePolicy'])

        iam_check = False if user_policy_set.intersection(iam_policies) == set() else True
        ec2_check = False if user_policy_set.intersection(ec2_policy) == set() else True

        if not (iam_check and ec2_check):
            raise Exception("Check your IAM permissions")

        pass_role_check = False if user_policy_set.intersection(pass_role_policy) == set() else True
        return pass_role_check