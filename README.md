AWS IAM Trust Relationship Roles update
========

This script helps you update specifically role policy on the trust relationship entities in your Amazon Web Services (AWS) environment.

# Commands
- `a`: Reference the account to be assumed.
- `i`: Reference the account inside the arn to which trust policy to correspond.


python3 main.py -a accountId -i trustRelationshipAccId -s specificSid -r roleToUpdate -c customRole1, customRole2, etc
