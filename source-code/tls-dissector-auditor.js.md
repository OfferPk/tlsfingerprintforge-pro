/\*\*  
 \* TLSFingerprintForge Pro \- Client Hello Dissector & 10-Point Zero-Trust Auditor  
 \* Detects User-Agent vs TLS stack incoherence and scores traffic from 0-100% (Grades A+ to F).  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory(require('./tls-fingerprint-engine.js'), require('./tls-bot-database.js'));  
  } else {  
    root.TLSDissectorAuditor \= factory(root.TLSFingerprintEngine, root.TLSBotDatabase);  
  }  
})(typeof self \!== 'undefined' ? self : this, function (Engine, Database) {  
  'use strict';

  const TLSDissectorAuditor \= {  
    /\*\*  
     \* Audits a client TLS session object:  
     \* session \= {  
     \*   userAgent: 'Mozilla/5.0 ...',  
     \*   clientHello: { ... }  
     \* }  
     \*/  
    audit(session) {  
      const ua \= session.userAgent || 'Unknown';  
      const hello \= session.clientHello || {};

      const ja4 \= Engine.calculateJA4(hello);  
      const ja3 \= Engine.calculateJA3(hello);

      // Check GREASE presence in raw arrays  
      const hasGreaseCiphers \= (hello.ciphers || \[\]).some(c \=\> Engine.isGrease(c));  
      const hasGreaseExts \= (hello.extensions || \[\]).some(e \=\> Engine.isGrease(e));  
      const hasGrease \= hasGreaseCiphers || hasGreaseExts;

      // Database signature lookup  
      const matchedSig \= Database.findMatch(ja4, ja3.hash);

      // User-Agent vs TLS Stack Mismatch Detection  
      let isUaMismatch \= false;  
      let mismatchReason \= null;

      const isClaimingChrome \= /Chrome\\//i.test(ua) && \!/HeadlessChrome/i.test(ua);  
      const isClaimingSafari \= /Safari\\//i.test(ua) && \!/Chrome/i.test(ua);  
      const isClaimingFirefox \= /Firefox\\//i.test(ua);

      if ((isClaimingChrome || isClaimingSafari) && \!hasGrease) {  
        isUaMismatch \= true;  
        mismatchReason \= 'User-Agent claims to be a modern desktop browser (Chrome/Safari), but TLS Client Hello lacks RFC 8701 GREASE values. Standard modern browsers always inject GREASE.';  
      } else if ((isClaimingChrome || isClaimingSafari || isClaimingFirefox) && \!hello.alpn) {  
        isUaMismatch \= true;  
        mismatchReason \= 'User-Agent claims to be a desktop browser, but TLS Client Hello lacks Application-Layer Protocol Negotiation (ALPN h2/http/1.1). Browsers always offer ALPN.';  
      } else if (matchedSig && matchedSig.category \=== 'SCRAPER' && (isClaimingChrome || isClaimingSafari || isClaimingFirefox)) {  
        isUaMismatch \= true;  
        mismatchReason \= 'CRITICAL SPOOFING: User-Agent claims to be a desktop browser, but the underlying TLS fingerprint matches "' \+ matchedSig.name \+ '"\!';  
      }

      const checks \= \[\];  
      let totalScore \= 0;

      // 1\. Signature Matching & Category Trust (20 pts)  
      if (matchedSig && matchedSig.category \=== 'BROWSER') {  
        checks.push({  
          id: 'sig\_match',  
          title: 'TLS Client Signature Identification',  
          points: 15,  
          maxPoints: 15,  
          passed: true,  
          level: 'PASS',  
          message: 'Fingerprint matches verified legitimate browser: ' \+ matchedSig.name \+ '.',  
          remediation: null  
        });  
        totalScore \+= 15;  
      } else if (matchedSig && matchedSig.isMalicious) {  
        checks.push({  
          id: 'sig\_match',  
          title: 'TLS Client Signature Identification',  
          points: 0,  
          maxPoints: 15,  
          passed: false,  
          level: 'CRITICAL',  
          message: 'THREAT DETECTED: Fingerprint matches malicious tool: ' \+ matchedSig.name \+ '.',  
          remediation: 'Drop connection or trigger CAPTCHA/Managed Challenge.'  
        });  
      } else if (matchedSig && matchedSig.isBot) {  
        checks.push({  
          id: 'sig\_match',  
          title: 'TLS Client Signature Identification',  
          points: 5,  
          maxPoints: 15,  
          passed: false,  
          level: 'WARN',  
          message: 'Fingerprint matches automated scraping tool: ' \+ matchedSig.name \+ '.',  
          remediation: 'Apply rate limiting or bot challenge.'  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'sig\_match',  
          title: 'TLS Client Signature Identification',  
          points: 12,  
          maxPoints: 15,  
          passed: true,  
          level: 'PASS',  
          message: 'Uncatalogued signature. Evaluating protocol heuristics.',  
          remediation: null  
        });  
        totalScore \+= 12;  
      }

      // 2\. User-Agent & TLS Stack Coherence (20 pts)  
      if (isUaMismatch) {  
        checks.push({  
          id: 'ua\_coherence',  
          title: 'User-Agent vs TLS Stack Coherence',  
          points: 0,  
          maxPoints: 20,  
          passed: false,  
          level: 'CRITICAL',  
          message: 'HIGH-CONFIDENCE MASQUERADING: ' \+ mismatchReason,  
          remediation: 'Immediately block or quarantine request; client is spoofing headers.'  
        });  
      } else if (matchedSig && matchedSig.isBot) {  
        checks.push({  
          id: 'ua\_coherence',  
          title: 'User-Agent vs TLS Stack Coherence',  
          points: 5,  
          maxPoints: 20,  
          passed: false,  
          level: 'WARN',  
          message: 'Automated client identity declared in User-Agent (' \+ matchedSig.name \+ '). Not a human browser.',  
          remediation: 'Apply scraper rate-limiting or challenge.'  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'ua\_coherence',  
          title: 'User-Agent vs TLS Stack Coherence',  
          points: 15,  
          maxPoints: 15,  
          passed: true,  
          level: 'PASS',  
          message: 'Client User-Agent aligns with underlying cryptographic TLS stack.',  
          remediation: null  
        });  
        totalScore \+= 20;  
      }

      // 3\. RFC 8701 GREASE Presence (10 pts)  
      if (hasGrease) {  
        checks.push({  
          id: 'grease\_check',  
          title: 'RFC 8701 GREASE Anti-Fingerprint Presence',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'Client Hello contains RFC 8701 GREASE values, typical of genuine browsers.',  
          remediation: null  
        });  
        totalScore \+= 10;  
      } else {  
        checks.push({  
          id: 'grease\_check',  
          title: 'RFC 8701 GREASE Anti-Fingerprint Presence',  
          points: isClaimingChrome ? 0 : 5,  
          maxPoints: 10,  
          passed: \!isClaimingChrome,  
          level: isClaimingChrome ? 'FAIL' : 'WARN',  
          message: isClaimingChrome  
            ? 'Missing GREASE values while claiming Chrome User-Agent. Definitive indicator of Python/cURL automation.'  
            : 'No GREASE values observed.',  
          remediation: 'Automated scraping frameworks (requests, Go, cURL) do not implement GREASE.'  
        });  
        if (\!isClaimingChrome) totalScore \+= 5;  
      }

      // 4\. ALPN Negotiation (10 pts)  
      if (hello.alpn \=== 'h2' || hello.alpn \=== 'h3') {  
        checks.push({  
          id: 'alpn\_check',  
          title: 'Application-Layer Protocol Negotiation (ALPN)',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'Client actively negotiates modern HTTP multiplexing (' \+ hello.alpn \+ ').',  
          remediation: null  
        });  
        totalScore \+= 10;  
      } else if (hello.alpn) {  
        checks.push({  
          id: 'alpn\_check',  
          title: 'Application-Layer Protocol Negotiation (ALPN)',  
          points: 5,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'Client negotiates legacy protocol (' \+ hello.alpn \+ ').',  
          remediation: null  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'alpn\_check',  
          title: 'Application-Layer Protocol Negotiation (ALPN)',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'WARN',  
          message: 'Client Hello completely lacks ALPN extension. Common in basic scraping scripts.',  
          remediation: 'Inspect if client is a legacy HTTP/1.0 script.'  
        });  
      }

      // 5\. TLS Version Hygiene (10 pts)  
      const isModernTls \= String(hello.tlsVersion).includes('1.3') || String(hello.tlsVersion).includes('1.2');  
      if (isModernTls) {  
        checks.push({  
          id: 'tls\_version',  
          title: 'TLS Protocol Version Hygiene',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'Client initiates session using modern TLS (' \+ hello.tlsVersion \+ ').',  
          remediation: null  
        });  
        totalScore \+= 10;  
      } else {  
        checks.push({  
          id: 'tls\_version',  
          title: 'TLS Protocol Version Hygiene',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'CRITICAL',  
          message: 'Insecure TLS version (' \+ hello.tlsVersion \+ '). SSLv3/TLS 1.0/1.1 are deprecated.',  
          remediation: 'Enforce minimum TLS 1.2 on server.'  
        });  
      }

      // 6\. Cipher Suite Richness & Diversity (10 pts)  
      const cleanCiphers \= (hello.ciphers || \[\]).filter(c \=\> \!Engine.isGrease(c));  
      if (cleanCiphers.length \>= 10\) {  
        checks.push({  
          id: 'cipher\_diversity',  
          title: 'Cipher Suite Richness & Diversity',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'Client offers ' \+ cleanCiphers.length \+ ' cipher suites, consistent with major browser engines.',  
          remediation: null  
        });  
        totalScore \+= 10;  
      } else if (cleanCiphers.length \>= 5\) {  
        checks.push({  
          id: 'cipher\_diversity',  
          title: 'Cipher Suite Richness & Diversity',  
          points: 5,  
          maxPoints: 10,  
          passed: false,  
          level: 'WARN',  
          message: 'Client offers only ' \+ cleanCiphers.length \+ ' ciphers. Typical of lightweight OpenSSL wrappers.',  
          remediation: null  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'cipher\_diversity',  
          title: 'Cipher Suite Richness & Diversity',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'CRITICAL',  
          message: 'Minimal cipher suite list (' \+ cleanCiphers.length \+ '). High probability of automated tool.',  
          remediation: null  
        });  
      }

      // 7\. Elliptic Curves & Modern Key Exchange (10 pts)  
      const curves \= hello.ellipticCurves || \[\];  
      const hasX25519 \= curves.includes(29);  
      if (hasX25519) {  
        checks.push({  
          id: 'curve\_hygiene',  
          title: 'Elliptic Curves & Key Exchange',  
          points: 10,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'Client supports Curve25519 (X25519 / group 29\) for modern forward secrecy.',  
          remediation: null  
        });  
        totalScore \+= 10;  
      } else if (curves.length \> 0\) {  
        checks.push({  
          id: 'curve\_hygiene',  
          title: 'Elliptic Curves & Key Exchange',  
          points: 5,  
          maxPoints: 10,  
          passed: true,  
          level: 'PASS',  
          message: 'Client offers NIST elliptic curves (P-256 / group 23).',  
          remediation: null  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'curve\_hygiene',  
          title: 'Elliptic Curves & Key Exchange',  
          points: 0,  
          maxPoints: 10,  
          passed: false,  
          level: 'FAIL',  
          message: 'No supported elliptic curves provided in Client Hello.',  
          remediation: null  
        });  
      }

      // 8\. SNI Domain Declaration (5 pts)  
      if (hello.hasSniDomain \!== false) {  
        checks.push({  
          id: 'sni\_declaration',  
          title: 'Server Name Indication (SNI) Domain',  
          points: 5,  
          maxPoints: 5,  
          passed: true,  
          level: 'PASS',  
          message: 'SNI extension declared with target hostname.',  
          remediation: null  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'sni\_declaration',  
          title: 'Server Name Indication (SNI) Domain',  
          points: 0,  
          maxPoints: 5,  
          passed: false,  
          level: 'WARN',  
          message: 'SNI is missing or contains direct IP literal. Characteristic of blind scanners.',  
          remediation: null  
        });  
      }

      // 9\. Extension Count & Padding Integrity (5 pts)  
      const cleanExts \= (hello.extensions || \[\]).filter(e \=\> \!Engine.isGrease(e));  
      if (cleanExts.length \>= 10\) {  
        checks.push({  
          id: 'ext\_integrity',  
          title: 'Extension Count & Padding Integrity',  
          points: 5,  
          maxPoints: 5,  
          passed: true,  
          level: 'PASS',  
          message: 'Client offers ' \+ cleanExts.length \+ ' extensions, consistent with modern browser capabilities.',  
          remediation: null  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'ext\_integrity',  
          title: 'Extension Count & Padding Integrity',  
          points: 0,  
          maxPoints: 5,  
          passed: false,  
          level: 'WARN',  
          message: 'Low extension count (' \+ cleanExts.length \+ '). Automation scripts rarely implement browser extensions.',  
          remediation: null  
        });  
      }

      // 10\. Threat Intelligence & Malicious CVE Association (5 pts)  
      const isKnownThreat \= matchedSig && (matchedSig.isMalicious || matchedSig.category \=== 'MALWARE\_C2' || matchedSig.category \=== 'SCANNER');  
      if (\!isKnownThreat) {  
        checks.push({  
          id: 'threat\_intel',  
          title: 'Threat Intelligence & C2 Signature Feeds',  
          points: 5,  
          maxPoints: 5,  
          passed: true,  
          level: 'PASS',  
          message: 'Signature has no active indicators of compromise (IoCs) or C2 beacon correlation.',  
          remediation: null  
        });  
        totalScore \+= 5;  
      } else {  
        checks.push({  
          id: 'threat\_intel',  
          title: 'Threat Intelligence & C2 Signature Feeds',  
          points: 0,  
          maxPoints: 5,  
          passed: false,  
          level: 'CRITICAL',  
          message: 'Active Threat Intelligence Match: ' \+ matchedSig.name,  
          remediation: 'Drop connection immediately.'  
        });  
      }

      // Grade assignment  
      let grade \= 'F';  
      if (totalScore \>= 95\) grade \= 'A+';  
      else if (totalScore \>= 90\) grade \= 'A';  
      else if (totalScore \>= 80\) grade \= 'B';  
      else if (totalScore \>= 70\) grade \= 'C';

      // Threat Classification  
      let threatLevel \= 'VERIFIED\_HUMAN\_BROWSER';  
      if (isKnownThreat) {  
        threatLevel \= 'CONFIRMED\_MALWARE\_OR\_EXPLOIT';  
      } else if (isUaMismatch) {  
        threatLevel \= 'MASQUERADING\_STEALTH\_BOT';  
      } else if (matchedSig && matchedSig.isBot) {  
        threatLevel \= 'KNOWN\_AUTOMATION\_SCRAPER';  
      } else if (matchedSig && matchedSig.category \=== 'BROWSER') {  
        threatLevel \= 'VERIFIED\_HUMAN\_BROWSER';  
      } else if (totalScore \< 70\) {  
        threatLevel \= 'SUSPICIOUS\_UNVERIFIED\_CLIENT';  
      }

      const isProductionReady \= (totalScore \>= 90 && \!isUaMismatch && \!isKnownThreat);

      return {  
        score: totalScore,  
        maxScore: 100,  
        grade,  
        isProductionReady,  
        threatLevel,  
        ja4,  
        ja3Hash: ja3.hash,  
        ja3Raw: ja3.raw,  
        matchedSignature: matchedSig,  
        isUaMismatch,  
        mismatchReason,  
        checks  
      };  
    }  
  };

  return TLSDissectorAuditor;  
});  
