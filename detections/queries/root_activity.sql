-- Any use of the root user in the last 7 days. Root should be idle.
SELECT eventtime, eventsource, eventname, awsregion, sourceipaddress, useragent, errorcode
FROM ${database}.cloudtrail
WHERE useridentity.type = 'Root'
  AND date >= date_format(current_date - interval '7' day, '%Y/%m/%d')
ORDER BY eventtime DESC
LIMIT 200;
