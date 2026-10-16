-- Who is knocking: rejected traffic by source and port over the last day.
SELECT srcaddr, dstport, protocol, count(*) AS flows, sum(packets) AS packets
FROM ${database}.vpc_flow_logs
WHERE action = 'REJECT'
  AND date >= date_format(current_date - interval '1' day, '%Y/%m/%d')
GROUP BY 1, 2, 3
ORDER BY flows DESC
LIMIT 50;
