-- Largest outbound transfers from the VPC: the place exfiltration shows up.
SELECT srcaddr, dstaddr, dstport, sum(bytes) AS total_bytes, count(*) AS flows
FROM ${database}.vpc_flow_logs
WHERE action = 'ACCEPT'
  AND srcaddr LIKE '10.20.%'
  AND NOT dstaddr LIKE '10.20.%'
  AND date >= date_format(current_date - interval '1' day, '%Y/%m/%d')
GROUP BY 1, 2, 3
ORDER BY total_bytes DESC
LIMIT 25;
