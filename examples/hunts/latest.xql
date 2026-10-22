// Maghreb Threat Watch hunt | generated 2026-10-22
// 17 lookalike/phishing domains (medium and high, rolling 30 days)
// Finds endpoints that resolved or connected to any of them, subdomains included.
// Source: https://github.com/Raynskhiri/maghreb-threat-watch
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.NETWORK
| filter dns_query_name ~= "(^|[.])(?:stb-tn-verification[.]com|steg-facture-tn[.]com|attijarlbank-login[.]com|cnss-tn-remboursement[.]com|amenb4nk[.]net|oredoo-recharge[.]xyz|baridimob-dz[.]top|b1at-tn[.]com|djezzy-bonus[.]shop|flouci-pay[.]netlify[.]app|tunisietelecom-facture[.]online|biat-secure-login[.]xyz|espace-client-attijari[.]site|xn--bit-login-1yh[.]com|xn--redoo-gift-dvia[.]com|colis-suivi[.]xyz|verify-account[.]xyz)$"
      or action_external_hostname ~= "(^|[.])(?:stb-tn-verification[.]com|steg-facture-tn[.]com|attijarlbank-login[.]com|cnss-tn-remboursement[.]com|amenb4nk[.]net|oredoo-recharge[.]xyz|baridimob-dz[.]top|b1at-tn[.]com|djezzy-bonus[.]shop|flouci-pay[.]netlify[.]app|tunisietelecom-facture[.]online|biat-secure-login[.]xyz|espace-client-attijari[.]site|xn--bit-login-1yh[.]com|xn--redoo-gift-dvia[.]com|colis-suivi[.]xyz|verify-account[.]xyz)$"
| fields _time, agent_hostname, actor_effective_username, actor_process_image_name,
         dns_query_name, action_external_hostname, action_remote_ip
| sort desc _time
