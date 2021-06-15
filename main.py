#!/usr/bin/env python3

import os
from typing import Dict
import boto3
import json
import sys
import argparse

region = "eu-central-1"

def main(argv):
    account = ''
    iam = ''
    sid = ''
    role = []
    custom_role = []

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--account', help="<accountId>", required=True)
    parser.add_argument('-i', '--iam', help="<accountId>", required=True)
    parser.add_argument('-s', '--sid', help="<sid>", required=True)
    parser.add_argument('-r', '--role', nargs='+', help='<role>', required=True)
    parser.add_argument('-c', '--custom-role', nargs='+', help='<role>', required=True)
    args = parser.parse_args()._get_kwargs()

    for arg, value in args:
        if arg == 'account':
            account = value
            print("Account: ", account)
        elif arg == 'iam':
            iam = value
            print("IAM: ", iam)
        elif arg == 'sid':
            sid = value
            print("Sid: ", sid)
        elif arg == 'role':
            role = value
            print("Current role: ", role)
        elif arg == 'custom_role':
            custom_role = value
            print("Custom role/s: ", custom_role)

    # +++++++++++++++++++++++ # GET CREDENTIALS # ++++++++++++++++++++++++ #
    sts_connection = boto3.client("sts")
    role_name = "terraform_admin_role"
    credentials = sts_connection.assume_role(
        RoleArn="arn:aws:iam::{}:role/{}".format(account, role_name),
        RoleSessionName="trustPolicySession",
    )
    
    client = boto3.client(
        "iam",
        aws_access_key_id=credentials["Credentials"]["AccessKeyId"],
        aws_secret_access_key=credentials["Credentials"]["SecretAccessKey"],
        aws_session_token=credentials["Credentials"]["SessionToken"],
    )

    # +++++++++++++++++++++++ # VERIFY ACCOUNT # ++++++++++++++++++++++++ #
    org = boto3.client("organizations")
    account_name = org.describe_account(AccountId=account).get("Account")
    alias = account_name["Name"].replace(" ", "_").replace("-", "_")
    print("Account Name: {}\n".format(alias))

    # +++++++++++++++++++++++ # UPDATE ROLES # ++++++++++++++++++++++++ #

    if 'Role' in str(role):
        custom_role.append(*role)
        custom_role.append("{}{}".format(alias, str(*role)[6:]))

    full_arn = ["arn:aws:iam::{}:role/{}".format(iam,i.strip(',')) for i in custom_role] 

    iam_policy = client.get_role(RoleName=str(*role))
    policy = iam_policy['Role']['AssumeRolePolicyDocument']

    if policy['Statement'][1]['Sid'] == sid:
        policy['Statement'][1]['Principal']['AWS'] = [i for i in full_arn]
    
    policy = json.dumps(policy)

    response = client.update_assume_role_policy(
        PolicyDocument=policy,
        RoleName=str(*role),
    )

    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        print("Roles are up to date.", )
    else:
        print("Failed updating roles.", )

if __name__ == "__main__":
    main(sys.argv[1:])
