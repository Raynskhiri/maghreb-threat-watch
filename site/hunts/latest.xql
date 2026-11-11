// Maghreb Threat Watch hunt | generated 2026-11-11
// 8 lookalike/phishing domains (medium and high, rolling 30 days)
// Finds endpoints that resolved or connected to any of them, subdomains included.
// Source: https://github.com/Raynskhiri/maghreb-threat-watch
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| filter dns_query_name ~= "(^|[.])(?:wifakepay[.]com|cannabissamenbank[.]ch|atbclientsupport[.]com|6x8147[.]xyz|biat-bonuss[.]sbs|81472[.]my|attijariwafabank[.]com[.]eg|biat-quiltexpo[.]com)$"
      or action_external_hostname ~= "(^|[.])(?:wifakepay[.]com|cannabissamenbank[.]ch|atbclientsupport[.]com|6x8147[.]xyz|biat-bonuss[.]sbs|81472[.]my|attijariwafabank[.]com[.]eg|biat-quiltexpo[.]com)$"
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name,
         dns_query_name, action_external_hostname, action_remote_ip
| sort desc _time
