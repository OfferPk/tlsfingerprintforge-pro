/\*\*  
 \* TLSFingerprintForge Pro \- Curated TLS Bot & Browser Fingerprint Signature Database  
 \* Indexes known JA4 and JA3 signatures across legitimate browsers, web scrapers,  
 \* headless automation tools, vulnerability scanners, and C2 malware frameworks.  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.TLSBotDatabase \= factory();  
  }  
})(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  const SIGNATURES \= \[  
    // 1\. Modern Legitimate Browsers  
    {  
      id: 'chrome\_desktop',  
      name: 'Google Chrome 120-124+ (macOS / Windows)',  
      category: 'BROWSER',  
      trustScore: 98,  
      expectedUserAgentPattern: /Chrome\\/(12\[0-9\]|13\[0-9\])/i,  
      ja4Prefix: 't13d15',  
      ja4Full: 't13d1515h2',  
      ja3Hash: 'b32309a26951912be7dba3738dfc0a70',  
      description: 'Standard modern Chrome desktop browser with GREASE, ALPN h2, and 15+ modern ciphers.',  
      isMalicious: false  
    },  
    {  
      id: 'firefox\_desktop',  
      name: 'Mozilla Firefox 120-125+ (Desktop)',  
      category: 'BROWSER',  
      trustScore: 95,  
      expectedUserAgentPattern: /Firefox\\/(12\[0-9\]|13\[0-9\])/i,  
      ja4Prefix: 't13d1413h2',  
      ja3Hash: '6f4806a64010a300ff0101b0993510e1',  
      description: 'Standard modern Firefox desktop client with ALPN h2 and strong curve preferences.',  
      isMalicious: false  
    },  
    {  
      id: 'safari\_macos',  
      name: 'Apple Safari 17+ (macOS / iOS)',  
      category: 'BROWSER',  
      trustScore: 96,  
      expectedUserAgentPattern: /Safari\\/\[0-9.\]+(?\!.\*Chrome)/i,  
      ja4Prefix: 't13d1912h2',  
      ja3Hash: '773906b0ef9db5e76e10787e9c395c47',  
      description: 'Apple Safari WebKit TLS stack with ChaCha20 priority and Apple ALPN negotiation.',  
      isMalicious: false  
    },  
    {  
      id: 'edge\_desktop',  
      name: 'Microsoft Edge 120+ (Desktop)',  
      category: 'BROWSER',  
      trustScore: 97,  
      expectedUserAgentPattern: /Edg\\/(12\[0-9\]|13\[0-9\])/i,  
      ja4Prefix: 't13d15',  
      ja4Full: 't13d1515h2',  
      ja3Hash: 'b32309a26951912be7dba3738dfc0a70',  
      description: 'Chromium-based Microsoft Edge with standard Google/MS GREASE extensions.',  
      isMalicious: false  
    },

    // 2\. Web Scrapers & Automation Libraries  
    {  
      id: 'python\_requests',  
      name: 'Python Requests 2.x / urllib3',  
      category: 'SCRAPER',  
      trustScore: 20,  
      expectedUserAgentPattern: /python-requests|urllib/i,  
      ja4Prefix: 't13d080700',  
      ja3Hash: '9a2c611c7c2c5b92c96b691a1259b878',  
      description: 'Default OpenSSL TLS stack used by Python requests. No ALPN, no GREASE, few ciphers.',  
      isMalicious: false,  
      isBot: true  
    },  
    {  
      id: 'python\_aiohttp',  
      name: 'Python aiohttp / httpx Async Client',  
      category: 'SCRAPER',  
      trustScore: 25,  
      expectedUserAgentPattern: /aiohttp|httpx/i,  
      ja4Prefix: 't13d080000',  
      ja3Hash: '1255e340cf3fb314545f1b0a8809ff45',  
      description: 'Asynchronous Python scraping client with default OpenSSL cipher order.',  
      isMalicious: false,  
      isBot: true  
    },  
    {  
      id: 'scrapy\_framework',  
      name: 'Scrapy Web Scraping Framework',  
      category: 'SCRAPER',  
      trustScore: 15,  
      expectedUserAgentPattern: /Scrapy/i,  
      ja4Prefix: 't12d080000',  
      ja3Hash: '2647c0d7681c2f37e42d65f57778b456',  
      description: 'Twisted Python TLS engine used by Scrapy spiders. Lacks HTTP/2 ALPN.',  
      isMalicious: false,  
      isBot: true  
    },  
    {  
      id: 'nodejs\_axios',  
      name: 'Node.js Axios / Got / Fetch Client',  
      category: 'SCRAPER',  
      trustScore: 30,  
      expectedUserAgentPattern: /axios|node-fetch|got/i,  
      ja4Prefix: 't13d0700h1',  
      ja3Hash: 'b25c345b10697e16faab2084c8a5a415',  
      description: 'Node.js runtime TLS engine. Negotiates http/1.1 by default with distinct cipher list.',  
      isMalicious: false,  
      isBot: true  
    },  
    {  
      id: 'golang\_net\_http',  
      name: 'Go net/http Standard Client',  
      category: 'SCRAPER',  
      trustScore: 25,  
      expectedUserAgentPattern: /Go-http-client/i,  
      ja4Prefix: 't13d0300h2',  
      ja3Hash: '853da31eeb4a5202611e3b5e4a529a6b',  
      description: 'Go language standard library client. Often used in high-volume micro-scrapers.',  
      isMalicious: false,  
      isBot: true  
    },  
    {  
      id: 'curl\_tool',  
      name: 'cURL Command Line / libcurl',  
      category: 'TOOL',  
      trustScore: 35,  
      expectedUserAgentPattern: /curl\\/\[0-9.\]+/i,  
      ja4Prefix: 't13d0700h2',  
      ja3Hash: '057864f9bf80db454f7a2fb60a373ff1',  
      description: 'Standard cURL tool linked with OpenSSL. Negotiates HTTP/2 without GREASE.',  
      isMalicious: false,  
      isBot: true  
    },

    // 3\. Headless Browsers & Stealth Automation  
    {  
      id: 'puppeteer\_default',  
      name: 'Puppeteer Headless Chrome',  
      category: 'HEADLESS\_BOT',  
      trustScore: 30,  
      expectedUserAgentPattern: /HeadlessChrome/i,  
      ja4Prefix: 't13d15',  
      ja4Full: 't13d1515h2',  
      ja3Hash: 'b32309a26951912be7dba3738dfc0a70',  
      description: 'Headless Chrome controlled via DevTools Protocol. Often stripped of GREASE.',  
      isMalicious: false,  
      isBot: true  
    },  
    {  
      id: 'playwright\_chromium',  
      name: 'Playwright Chromium Automation',  
      category: 'HEADLESS\_BOT',  
      trustScore: 35,  
      expectedUserAgentPattern: /Playwright/i,  
      ja4Prefix: 't13d15',  
      ja4Full: 't13d1515h2',  
      ja3Hash: 'b32309a26951912be7dba3738dfc0a70',  
      description: 'Playwright automated browser instance. Lacks persistent user profile context.',  
      isMalicious: false,  
      isBot: true  
    },  
    {  
      id: 'stealth\_spoofed\_scraper',  
      name: 'Masquerading Scraper (UA Spoofing)',  
      category: 'STEALTH\_BOT',  
      trustScore: 10,  
      expectedUserAgentPattern: /Mozilla\\/5\\.0.\*Chrome/i,  
      ja4Prefix: 't13d080700',  
      ja3Hash: '9a2c611c7c2c5b92c96b691a1259b878',  
      description: 'CRITICAL SPOOFING: Claims to be Chrome desktop in User-Agent, but TLS fingerprint is Python requests\!',  
      isMalicious: true,  
      isBot: true  
    },

    // 4\. Vulnerability Scanners  
    {  
      id: 'sqlmap\_scanner',  
      name: 'SQLMap Automatic SQL Injection Tool',  
      category: 'SCANNER',  
      trustScore: 5,  
      expectedUserAgentPattern: /sqlmap/i,  
      ja4Prefix: 't12i060000',  
      ja3Hash: '64d6db8754b23c21a4f00b95eb56d787',  
      description: 'Automated database exploit framework. Uses ancient Python TLS profile.',  
      isMalicious: true,  
      isBot: true  
    },  
    {  
      id: 'nuclei\_scanner',  
      name: 'Nuclei Vulnerability Scanner (ProjectDiscovery)',  
      category: 'SCANNER',  
      trustScore: 15,  
      expectedUserAgentPattern: /nuclei/i,  
      ja4Prefix: 't13d040000',  
      ja3Hash: '992a54318c47b5202611e3b5e4a529a6',  
      description: 'Fast template-based vulnerability scanner written in Go.',  
      isMalicious: false,  
      isBot: true  
    },

    // 5\. C2 Frameworks & Malicious Stealers  
    {  
      id: 'cobalt\_strike',  
      name: 'Cobalt Strike HTTPS Malleable C2',  
      category: 'MALWARE\_C2',  
      trustScore: 0,  
      expectedUserAgentPattern: /.\*/,  
      ja4Prefix: 't12d070000',  
      ja3Hash: 'a0e9f5d64349fb13191bc781f81f42e1',  
      description: 'Known default Cobalt Strike HTTPS beacon TLS profile.',  
      isMalicious: true,  
      isBot: true  
    }  
  \];

  const TLSBotDatabase \= {  
    SIGNATURES,

    /\*\*  
     \* Finds matching signature by JA4 prefix or JA3 hash.  
     \*/  
    findMatch(ja4String, ja3Hash) {  
      if (ja3Hash) {  
        const ja3Match \= SIGNATURES.find(s \=\> s.ja3Hash \=== ja3Hash);  
        if (ja3Match) return ja3Match;  
      }

      if (ja4String) {  
        const prefix \= ja4String.split('\_')\[0\];  
        const ja4Match \= SIGNATURES.find(s \=\> prefix.startsWith(s.ja4Prefix) || s.ja4Prefix \=== prefix);  
        if (ja4Match) return ja4Match;  
      }

      return null;  
    }  
  };

  return TLSBotDatabase;  
});  
