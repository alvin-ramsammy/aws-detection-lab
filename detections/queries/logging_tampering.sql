-- Attempts (successful or not) to blind the defenders.
SELECT eventtime, useridentity.arn AS principal, eventsource, eventname, awsregion,
       sourceipaddress, errorcode, requestparameters
FROM ${database}.cloudtrail
WHERE eventname IN ('StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors',
                    'DeleteFlowLogs', 'DeleteDetector', 'UpdateDetector',
                    'DisableSecurityHub', 'DeleteLogGroup')
  AND date >= date_format(current_date - interval '30' day, '%Y/%m/%d')
ORDER BY eventtime DESC;
