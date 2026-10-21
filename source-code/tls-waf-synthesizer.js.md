/\*\*  
 \* TLSFingerprintForge Pro \- Multi-WAF Bot Defense Rule Synthesizer  
 \* Generates ready-to-deploy mitigation rules for Cloudflare WAF, AWS WAF v2,  
 \* Nginx, HAProxy, and ModSecurity CRS.  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.TLSWAFSynthesizer \= factory();  
  }  
})(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  const TLSWAFSynthesizer \= {  
    /\*\*  
     \* Cloudflare WAF Custom Rule expression  
     \*/  
    generateCloudflare(ja4, ja3Hash, ruleAction \= 'block') {  
      const cleanJa4 \= ja4 || 't13d080000\_...';  
      const cleanJa3 \= ja3Hash || 'cd08e31494f9531f560d64cfa37e90ad';

      return \`\# \========================================================  
\# Cloudflare WAF Custom Rule (Expression Engine)  
\# Action: \${ruleAction.toUpperCase()} (or managed\_challenge)  
\# \========================================================

Expression:  
(cf.bot\_management.ja4 \== "\${cleanJa4}" or cf.bot\_management.ja3\_hash \== "\${cleanJa3}")

\# Terraform HCL representation:  
resource "cloudflare\_filter" "bot\_tls\_filter" {  
  zone\_id     \= var.cloudflare\_zone\_id  
  description \= "Block malicious scraping tool by JA4/JA3 fingerprint"  
  expression  \= "(cf.bot\_management.ja4 \== \\\\"\${cleanJa4}\\\\" or cf.bot\_management.ja3\_hash \== \\\\"\${cleanJa3}\\\\")"  
}

resource "cloudflare\_firewall\_rule" "bot\_tls\_rule" {  
  zone\_id     \= var.cloudflare\_zone\_id  
  description \= "Enforce TLS Fingerprint Shield"  
  filter\_id   \= cloudflare\_filter.bot\_tls\_filter.id  
  action      \= "\${ruleAction}"  
}\`;  
    },

    /\*\*  
     \* AWS WAF v2 JSON Statement  
     \*/  
    generateAWSWAF(ja4, ruleAction \= 'BLOCK') {  
      const cleanJa4 \= ja4 || 't13d080000\_...';  
      const payload \= {  
        Name: "Enforce-TLS-Fingerprint-Shield",  
        Priority: 10,  
        Statement: {  
          ByteMatchStatement: {  
            SearchString: cleanJa4,  
            FieldToMatch: {  
              SingleHeader: {  
                Name: "x-ja4-fingerprint"  
              }  
            },  
            TextTransformations: \[  
              {  
                Priority: 0,  
                Type: "NONE"  
              }  
            \],  
            PositionalConstraint: "EXACTLY"  
          }  
        },  
        Action: {  
          \[ruleAction.charAt(0).toUpperCase() \+ ruleAction.slice(1).toLowerCase()\]: {}  
        },  
        VisibilityConfig: {  
          SampledRequestsEnabled: true,  
          CloudWatchMetricsEnabled: true,  
          MetricName: "TLSFingerprintBlockedRequests"  
        }  
      };

      return JSON.stringify(payload, null, 2);  
    },

    /\*\*  
     \* Nginx map & server drop directive  
     \*/  
    generateNginx(ja4, ja3Hash) {  
      const cleanJa4 \= ja4 || 't13d080000\_...';  
      const cleanJa3 \= ja3Hash || 'cd08e31494f9531f560d64cfa37e90ad';

      return \`\# \========================================================  
\# Nginx TLS Fingerprint Filter Configuration  
\# Place map inside http {} block and check inside server {}  
\# \========================================================

\# Requires lua-resty-fingerprint or custom proxy header  
map \$http\_x\_ja4\_fingerprint \$is\_bad\_tls\_fingerprint {  
    default 0;  
    "\${cleanJa4}" 1;  
}

map \$http\_x\_ja3\_fingerprint \$is\_bad\_ja3\_fingerprint {  
    default 0;  
    "\${cleanJa3}" 1;  
}

server {  
    listen 443 ssl http2;  
    server\_name example.com;

    \# Immediate drop on bot fingerprint match  
    if (\$is\_bad\_tls\_fingerprint) {  
        return 403 "Forbidden: Automated Scraper Fingerprint Detected";  
    }  
    if (\$is\_bad\_ja3\_fingerprint) {  
        return 403 "Forbidden: Automated Scraper Fingerprint Detected";  
    }  
}\`;  
    },

    /\*\*  
     \* HAProxy configuration  
     \*/  
    generateHAProxy(ja4) {  
      const cleanJa4 \= ja4 || 't13d080000\_...';  
      return \`\# \========================================================  
\# HAProxy TLS Fingerprint ACL  
\# \========================================================  
frontend https\_front  
    bind :443 ssl crt /etc/ssl/certs/site.pem

    \# Capture and check TLS Fingerprint header  
    acl is\_blocked\_ja4 req.hdr(X-JA4-Fingerprint) \-m str "\${cleanJa4}"  
      
    \# Drop with HTTP 403 Forbidden  
    http-request deny deny\_status 403 if is\_blocked\_ja4  
\`;  
    },

    /\*\*  
     \* ModSecurity CRS SecRule  
     \*/  
    generateModSecurity(ja4, ja3Hash) {  
      const cleanJa4 \= ja4 || 't13d080000\_...';  
      return \`\# \========================================================  
\# ModSecurity CRS SecRule \- TLS Bot Defense  
\# \========================================================  
SecRule REQUEST\_HEADERS:X-JA4-Fingerprint "@streq \${cleanJa4}" \\\\  
    "id:990100,\\\\  
    phase:1,\\\\  
    deny,\\\\  
    status:403,\\\\  
    log,\\\\  
    msg:'Malicious TLS Client Fingerprint Detected (JA4: \${cleanJa4})',\\\\  
    tag:'attack-reputation-bot',\\\\  
    severity:'CRITICAL'"  
\`;  
    }  
  };

  return TLSWAFSynthesizer;  
});  
