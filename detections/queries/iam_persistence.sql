-- New identities, credentials, and admin grants: the usual persistence moves.
SELECT eventtime, useridentity.arn AS actor, eventname,
       json_extract_scalar(requestparameters, '$.userName') AS target_user,
       json_extract_scalar(requestparameters, '$.policyArn') AS policy_arn,
       sourceipaddress, errorcode
FROM ${database}.cloudtrail
WHERE eventsource = 'iam.amazonaws.com'
  AND eventname IN ('CreateUser', 'CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile',
                    'AttachUserPolicy', 'PutUserPolicy', 'AddUserToGroup',
                    'CreateRole', 'UpdateAssumeRolePolicy', 'AttachRolePolicy')
  AND date >= date_format(current_date - interval '30' day, '%Y/%m/%d')
ORDER BY eventtime DESC;
