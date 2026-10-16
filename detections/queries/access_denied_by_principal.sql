-- Principals collecting AccessDenied errors: a common sign of enumeration
-- with stolen credentials (an attacker probing what a key can do).
SELECT useridentity.arn AS principal, sourceipaddress,
       count(*) AS denied_calls,
       count(DISTINCT eventname) AS distinct_apis,
       min(eventtime) AS first_seen, max(eventtime) AS last_seen
FROM ${database}.cloudtrail
WHERE errorcode IN ('AccessDenied', 'Client.UnauthorizedOperation', 'UnauthorizedOperation')
  AND date >= date_format(current_date - interval '1' day, '%Y/%m/%d')
GROUP BY 1, 2
HAVING count(*) >= 10
ORDER BY denied_calls DESC;
