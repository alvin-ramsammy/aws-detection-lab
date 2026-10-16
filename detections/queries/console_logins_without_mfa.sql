-- Successful console sign-ins that did not use MFA.
SELECT eventtime, useridentity.arn AS principal, sourceipaddress, useragent,
       json_extract_scalar(additionaleventdata, '$.MFAUsed') AS mfa_used
FROM ${database}.cloudtrail
WHERE eventname = 'ConsoleLogin'
  AND json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Success'
  AND json_extract_scalar(additionaleventdata, '$.MFAUsed') <> 'Yes'
  AND date >= date_format(current_date - interval '30' day, '%Y/%m/%d')
ORDER BY eventtime DESC;
