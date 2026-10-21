/\*\*  
 \* TLSFingerprintForge Pro \- Core TLS Client Fingerprint Engine  
 \* Calculates JA4 (W3C/Cloudflare standard) and JA3 (Salesforce standard)  
 \* with RFC 8701 GREASE filtering and IANA cipher translation.  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory(require('crypto'));  
  } else {  
    root.TLSFingerprintEngine \= factory(root.crypto);  
  }  
})(typeof self \!== 'undefined' ? self : this, function (nodeCrypto) {  
  'use strict';

  // RFC 8701 GREASE values (Generate Random Extensions And Sustain Extensibility)  
  // Hex values: 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,  
  // 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa  
  const GREASE\_DECIMALS \= \[  
    2570, 6666, 10762, 14858, 18954, 23050, 27146, 31242,  
    35338, 39434, 43530, 47626, 51722, 55818, 59914, 64010  
  \];

  function isGrease(num) {  
    return GREASE\_DECIMALS.includes(Number(num));  
  }

  // IANA TLS Cipher Suites Dictionary (Top Common Suites)  
  const IANA\_CIPHERS \= {  
    '0x1301': 'TLS\_AES\_128\_GCM\_SHA256',  
    '0x1302': 'TLS\_AES\_256\_GCM\_SHA384',  
    '0x1303': 'TLS\_CHACHA20\_POLY1305\_SHA256',  
    '0x1304': 'TLS\_AES\_128\_CCM\_SHA256',  
    '0x1305': 'TLS\_AES\_128\_CCM\_8\_SHA256',  
    '0xc02b': 'TLS\_ECDHE\_ECDSA\_WITH\_AES\_128\_GCM\_SHA256',  
    '0xc02f': 'TLS\_ECDHE\_RSA\_WITH\_AES\_128\_GCM\_SHA256',  
    '0xc02c': 'TLS\_ECDHE\_ECDSA\_WITH\_AES\_256\_GCM\_SHA384',  
    '0xc030': 'TLS\_ECDHE\_RSA\_WITH\_AES\_256\_GCM\_SHA384',  
    '0xcca9': 'TLS\_ECDHE\_ECDSA\_WITH\_CHACHA20\_POLY1305\_SHA256',  
    '0xcca8': 'TLS\_ECDHE\_RSA\_WITH\_CHACHA20\_POLY1305\_SHA256',  
    '0xc013': 'TLS\_ECDHE\_RSA\_WITH\_AES\_128\_CBC\_SHA',  
    '0xc014': 'TLS\_ECDHE\_RSA\_WITH\_AES\_256\_CBC\_SHA',  
    '0x009c': 'TLS\_RSA\_WITH\_AES\_128\_GCM\_SHA256',  
    '0x009d': 'TLS\_RSA\_WITH\_AES\_256\_GCM\_SHA384',  
    '0x002f': 'TLS\_RSA\_WITH\_AES\_128\_CBC\_SHA',  
    '0x0035': 'TLS\_RSA\_WITH\_AES\_256\_CBC\_SHA',  
    '0x000a': 'TLS\_RSA\_WITH\_3DES\_EDE\_CBC\_SHA'  
  };

  // Pure JavaScript MD5 & SHA-256 implementations for standalone browser usage  
  function md5(string) {  
    function rotateLeft(lValue, iShiftBits) {  
      return (lValue \<\< iShiftBits) | (lValue \>\>\> (32 \- iShiftBits));  
    }  
    function addUnsigned(lX, lY) {  
      const lX8 \= (lX & 0x80000000);  
      const lY8 \= (lY & 0x80000000);  
      const lX4 \= (lX & 0x40000000);  
      const lY4 \= (lY & 0x40000000);  
      const lResult \= (lX & 0x3FFFFFFF) \+ (lY & 0x3FFFFFFF);  
      if (lX4 & lY4) return (lResult ^ 0x80000000 ^ lX8 ^ lY8);  
      if (lX4 | lY4) {  
        if (lResult & 0x40000000) return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);  
        return (lResult ^ 0x40000000 ^ lX8 ^ lY8);  
      }  
      return (lResult ^ lX8 ^ lY8);  
    }  
    function F(x, y, z) { return (x & y) | ((\~x) & z); }  
    function G(x, y, z) { return (x & z) | (y & (\~z)); }  
    function H(x, y, z) { return (x ^ y ^ z); }  
    function I(x, y, z) { return (y ^ (x | (\~z))); }  
    function FF(a, b, c, d, x, s, ac) {  
      a \= addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));  
      return addUnsigned(rotateLeft(a, s), b);  
    }  
    function GG(a, b, c, d, x, s, ac) {  
      a \= addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));  
      return addUnsigned(rotateLeft(a, s), b);  
    }  
    function HH(a, b, c, d, x, s, ac) {  
      a \= addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));  
      return addUnsigned(rotateLeft(a, s), b);  
    }  
    function II(a, b, c, d, x, s, ac) {  
      a \= addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));  
      return addUnsigned(rotateLeft(a, s), b);  
    }  
    function convertToWordArray(string) {  
      let lWordCount;  
      const lMessageLength \= string.length;  
      const lNumberOfWords\_temp1 \= lMessageLength \+ 8;  
      const lNumberOfWords\_temp2 \= (lNumberOfWords\_temp1 \- (lNumberOfWords\_temp1 % 64)) / 64;  
      const lNumberOfWords \= (lNumberOfWords\_temp2 \+ 1\) \* 16;  
      const lWordArray \= Array(lNumberOfWords \- 1);  
      let lBytePosition \= 0;  
      let lByteCount \= 0;  
      while (lByteCount \< lMessageLength) {  
        lWordCount \= (lByteCount \- (lByteCount % 4)) / 4;  
        lBytePosition \= (lByteCount % 4\) \* 8;  
        lWordArray\[lWordCount\] \= (lWordArray\[lWordCount\] | (string.charCodeAt(lByteCount) \<\< lBytePosition));  
        lByteCount++;  
      }  
      lWordCount \= (lByteCount \- (lByteCount % 4)) / 4;  
      lBytePosition \= (lByteCount % 4\) \* 8;  
      lWordArray\[lWordCount\] \= lWordArray\[lWordCount\] | (0x80 \<\< lBytePosition);  
      lWordArray\[lNumberOfWords \- 2\] \= lMessageLength \<\< 3;  
      lWordArray\[lNumberOfWords \- 1\] \= lMessageLength \>\>\> 29;  
      return lWordArray;  
    }  
    function wordToHex(lValue) {  
      let WordToHexValue \= '', WordToHexValue\_temp \= '', lByte, lCount;  
      for (lCount \= 0; lCount \<= 3; lCount++) {  
        lByte \= (lValue \>\>\> (lCount \* 8)) & 255;  
        WordToHexValue\_temp \= '0' \+ lByte.toString(16);  
        WordToHexValue \= WordToHexValue \+ WordToHexValue\_temp.substr(WordToHexValue\_temp.length \- 2, 2);  
      }  
      return WordToHexValue;  
    }  
    const x \= convertToWordArray(string);  
    let k, AA, BB, CC, DD, a, b, c, d;  
    const S11 \= 7, S12 \= 12, S13 \= 17, S14 \= 22;  
    const S21 \= 5, S22 \= 9, S23 \= 14, S24 \= 20;  
    const S31 \= 4, S32 \= 11, S33 \= 16, S34 \= 23;  
    const S41 \= 6, S42 \= 10, S43 \= 15, S44 \= 21;  
    a \= 0x67452301; b \= 0xEFCDAB89; c \= 0x98BADCFE; d \= 0x10325476;  
    for (k \= 0; k \< x.length; k \+= 16\) {  
      AA \= a; BB \= b; CC \= c; DD \= d;  
      a \= FF(a, b, c, d, x\[k \+ 0\], S11, 0xD76AA478);  
      d \= FF(d, a, b, c, x\[k \+ 1\], S12, 0xE8C7B756);  
      c \= FF(c, d, a, b, x\[k \+ 2\], S13, 0x242070DB);  
      b \= FF(b, c, d, a, x\[k \+ 3\], S14, 0xC1BDCEEE);  
      a \= FF(a, b, c, d, x\[k \+ 4\], S11, 0xF57C0FAF);  
      d \= FF(d, a, b, c, x\[k \+ 5\], S12, 0x4787C62A);  
      c \= FF(c, d, a, b, x\[k \+ 6\], S13, 0xA8304613);  
      b \= FF(b, c, d, a, x\[k \+ 7\], S14, 0xFD469501);  
      a \= FF(a, b, c, d, x\[k \+ 8\], S11, 0x698098D8);  
      d \= FF(d, a, b, c, x\[k \+ 9\], S12, 0x8B44F7AF);  
      c \= FF(c, d, a, b, x\[k \+ 10\], S13, 0xFFFF5BB1);  
      b \= FF(b, c, d, a, x\[k \+ 11\], S14, 0x895CD7BE);  
      a \= FF(a, b, c, d, x\[k \+ 12\], S11, 0x6B901122);  
      d \= FF(d, a, b, c, x\[k \+ 13\], S12, 0xFD987193);  
      c \= FF(c, d, a, b, x\[k \+ 14\], S13, 0xA679438E);  
      b \= FF(b, c, d, a, x\[k \+ 15\], S14, 0x49B40821);  
      a \= GG(a, b, c, d, x\[k \+ 1\], S21, 0xF61E2562);  
      d \= GG(d, a, b, c, x\[k \+ 6\], S22, 0xC040B340);  
      c \= GG(c, d, a, b, x\[k \+ 11\], S23, 0x265E5A51);  
      b \= GG(b, c, d, a, x\[k \+ 0\], S24, 0xE9B6C7AA);  
      a \= GG(a, b, c, d, x\[k \+ 5\], S21, 0xD62F105D);  
      d \= GG(d, a, b, c, x\[k \+ 10\], S22, 0x2441453);  
      c \= GG(c, d, a, b, x\[k \+ 15\], S23, 0xD8A1E681);  
      b \= GG(b, c, d, a, x\[k \+ 4\], S24, 0xE7D3FBC8);  
      a \= GG(a, b, c, d, x\[k \+ 9\], S21, 0x21E1CDE6);  
      d \= GG(d, a, b, c, x\[k \+ 14\], S22, 0xC33707D6);  
      c \= GG(c, d, a, b, x\[k \+ 3\], S23, 0xF4D50D87);  
      b \= GG(b, c, d, a, x\[k \+ 8\], S24, 0x455A14ED);  
      a \= GG(a, b, c, d, x\[k \+ 13\], S21, 0xA9E3E905);  
      d \= GG(d, a, b, c, x\[k \+ 2\], S22, 0xFCEFA3F8);  
      c \= GG(c, d, a, b, x\[k \+ 7\], S23, 0x676F02D9);  
      b \= GG(b, c, d, a, x\[k \+ 12\], S24, 0x8D2A4C8A);  
      a \= HH(a, b, c, d, x\[k \+ 5\], S31, 0xFFFA3942);  
      d \= HH(d, a, b, c, x\[k \+ 8\], S32, 0x8771F681);  
      c \= HH(c, d, a, b, x\[k \+ 11\], S33, 0x6D9D6122);  
      b \= HH(b, c, d, a, x\[k \+ 14\], S34, 0xFDE5380C);  
      a \= HH(a, b, c, d, x\[k \+ 1\], S31, 0xA4BEEA44);  
      d \= HH(d, a, b, c, x\[k \+ 4\], S32, 0x4BDECFA9);  
      c \= HH(c, d, a, b, x\[k \+ 7\], S33, 0xF6BB4B60);  
      b \= HH(b, c, d, a, x\[k \+ 10\], S34, 0xBEBFBC70);  
      a \= HH(a, b, c, d, x\[k \+ 13\], S31, 0x289B7EC6);  
      d \= HH(d, a, b, c, x\[k \+ 0\], S32, 0xEAA127FA);  
      c \= HH(c, d, a, b, x\[k \+ 3\], S33, 0xD4EF3085);  
      b \= HH(b, c, d, a, x\[k \+ 6\], S34, 0x4881D05);  
      a \= HH(a, b, c, d, x\[k \+ 9\], S31, 0xD9D4D039);  
      d \= HH(d, a, b, c, x\[k \+ 12\], S32, 0xE6DB99E5);  
      c \= HH(c, d, a, b, x\[k \+ 15\], S33, 0x1FA27CF8);  
      b \= HH(b, c, d, a, x\[k \+ 2\], S34, 0xC4AC5665);  
      a \= II(a, b, c, d, x\[k \+ 0\], S41, 0xF4292244);  
      d \= II(d, a, b, c, x\[k \+ 7\], S42, 0x432AFF97);  
      c \= II(c, d, a, b, x\[k \+ 14\], S43, 0xAB9423A7);  
      b \= II(b, c, d, a, x\[k \+ 5\], S44, 0xFC93A039);  
      a \= II(a, b, c, d, x\[k \+ 12\], S41, 0x655B59C3);  
      d \= II(d, a, b, c, x\[k \+ 3\], S42, 0x8F0CCC92);  
      c \= II(c, d, a, b, x\[k \+ 10\], S43, 0xFFEFF47D);  
      b \= II(b, c, d, a, x\[k \+ 1\], S44, 0x85845DD1);  
      a \= II(a, b, c, d, x\[k \+ 8\], S41, 0x6FA87E4F);  
      d \= II(d, a, b, c, x\[k \+ 15\], S42, 0xFE2CE6E0);  
      c \= II(c, d, a, b, x\[k \+ 6\], S43, 0xA3014314);  
      b \= II(b, c, d, a, x\[k \+ 13\], S44, 0x4E0811A1);  
      a \= II(a, b, c, d, x\[k \+ 4\], S41, 0xF7537E82);  
      d \= II(d, a, b, c, x\[k \+ 11\], S42, 0xBD3AF235);  
      c \= II(c, d, a, b, x\[k \+ 2\], S43, 0x2AD7D2BB);  
      b \= II(b, c, d, a, x\[k \+ 9\], S44, 0xEB86D391);  
      a \= addUnsigned(a, AA);  
      b \= addUnsigned(b, BB);  
      c \= addUnsigned(c, CC);  
      d \= addUnsigned(d, DD);  
    }  
    return (wordToHex(a) \+ wordToHex(b) \+ wordToHex(c) \+ wordToHex(d)).toLowerCase();  
  }

  function sha256Hex(ascii) {  
    if (nodeCrypto && typeof nodeCrypto.createHash \=== 'function') {  
      return nodeCrypto.createHash('sha256').update(ascii, 'utf8').digest('hex');  
    }  
    // Pure JS fallback  
    function rightRotate(value, amount) {  
      return (value \>\>\> amount) | (value \<\< (32 \- amount));  
    }  
    const mathPow \= Math.pow;  
    const maxWord \= mathPow(2, 32);  
    let i, j;  
    const words \= \[\];  
    const asciiBitLength \= ascii.length \* 8;  
    let hash \= \[\];  
    const k \= \[\];  
    let primeCounter \= 0;  
    const isComposite \= {};  
    for (let candidate \= 2; primeCounter \< 64; candidate++) {  
      if (\!isComposite\[candidate\]) {  
        for (i \= 0; i \< 313; i \+= candidate) isComposite\[i\] \= candidate;  
        hash\[primeCounter\] \= (mathPow(candidate, 0.5) \* maxWord) | 0;  
        k\[primeCounter++\] \= (mathPow(candidate, 1 / 3\) \* maxWord) | 0;  
      }  
    }  
    hash \= hash.slice(0, 8);  
    ascii \+= '\\x80';  
    while ((ascii.length % 64\) \- 56\) ascii \+= '\\x00';  
    for (i \= 0; i \< ascii.length; i++) {  
      j \= ascii.charCodeAt(i);  
      words\[i \>\> 2\] |= j \<\< (((3 \- i) % 4\) \* 8);  
    }  
    words\[words.length\] \= (asciiBitLength / maxWord) | 0;  
    words\[words.length\] \= asciiBitLength | 0;

    for (j \= 0; j \< words.length;) {  
      const w \= words.slice(j, (j \+= 16));  
      const oldHash \= hash;  
      hash \= hash.slice(0, 8);  
      for (i \= 0; i \< 64; i++) {  
        const w15 \= w\[i \- 15\], w2 \= w\[i \- 2\];  
        const s0 \= rightRotate(w15, 7\) ^ rightRotate(w15, 18\) ^ (w15 \>\>\> 3);  
        const s1 \= rightRotate(w2, 17\) ^ rightRotate(w2, 19\) ^ (w2 \>\>\> 10);  
        const ch \= (hash\[4\] & hash\[5\]) ^ (\~hash\[4\] & hash\[6\]);  
        const maj \= (hash\[0\] & hash\[1\]) ^ (hash\[0\] & hash\[2\]) ^ (hash\[1\] & hash\[2\]);  
        const temp1 \= (hash\[7\] \+ (rightRotate(hash\[4\], 6\) ^ rightRotate(hash\[4\], 11\) ^ rightRotate(hash\[4\], 25)) \+ ch \+ k\[i\] \+ (w\[i\] \= (i \< 16\) ? w\[i\] : (w\[i \- 16\] \+ s0 \+ w\[i \- 7\] \+ s1) | 0)) | 0;  
        const temp2 \= ((rightRotate(hash\[0\], 2\) ^ rightRotate(hash\[0\], 13\) ^ rightRotate(hash\[0\], 22)) \+ maj) | 0;

        hash \= \[(temp1 \+ temp2) | 0, hash\[0\], hash\[1\], hash\[2\], (hash\[3\] \+ temp1) | 0, hash\[4\], hash\[5\], hash\[6\]\];  
      }  
      for (i \= 0; i \< 8; i++) hash\[i\] \= (hash\[i\] \+ oldHash\[i\]) | 0;  
    }  
    let hex \= '';  
    for (i \= 0; i \< 8; i++) {  
      const h \= (hash\[i\] \>\>\> 0).toString(16);  
      hex \+= ('00000000' \+ h).slice(-8);  
    }  
    return hex;  
  }

  const TLSFingerprintEngine \= {  
    IANA\_CIPHERS,  
    GREASE\_DECIMALS,  
    isGrease,

    /\*\*  
     \* Calculates the modern JA4 Fingerprint string.  
     \* Specification:  
     \* JA4\_a: Protocol(1) \+ Version(2) \+ SNI(1) \+ CiphersCount(2) \+ ExtensionsCount(2) \+ ALPN(2)  
     \* JA4\_b: SHA256 of sorted hex ciphers (truncated to 12 chars)  
     \* JA4\_c: SHA256 of sorted hex extensions \+ signature algorithms (truncated to 12 chars)  
     \*/  
    calculateJA4(params) {  
      // Protocol: TCP ('t') or QUIC ('q')  
      const proto \= params.protocol \=== 'QUIC' ? 'q' : 't';

      // TLS Version mapping: 1.3 \-\> '13', 1.2 \-\> '12', 1.1 \-\> '11', 1.0 \-\> '10'  
      let ver \= '13';  
      const rawVer \= String(params.tlsVersion || 'TLSv1.3');  
      if (rawVer.includes('1.2') || rawVer \=== '771') ver \= '12';  
      else if (rawVer.includes('1.1') || rawVer \=== '770') ver \= '11';  
      else if (rawVer.includes('1.0') || rawVer \=== '769') ver \= '10';

      // SNI: 'd' if domain present, 'i' if IP or missing  
      const sni \= params.hasSniDomain \!== false ? 'd' : 'i';

      // Filter out GREASE from ciphers and extensions  
      const rawCiphers \= Array.isArray(params.ciphers) ? params.ciphers : \[\];  
      const cleanCiphers \= rawCiphers.filter(c \=\> \!isGrease(c));

      const rawExts \= Array.isArray(params.extensions) ? params.extensions : \[\];  
      const cleanExts \= rawExts.filter(e \=\> \!isGrease(e));

      // 2-digit counts (capped at 99\)  
      const ciphersCount \= ('0' \+ Math.min(cleanCiphers.length, 99)).slice(-2);  
      const extsCount \= ('0' \+ Math.min(cleanExts.length, 99)).slice(-2);

      // ALPN: first & last character of highest priority ALPN (e.g. 'h2' \-\> 'h2', 'http/1.1' \-\> 'h1', none \-\> '00')  
      let alpnCode \= '00';  
      if (params.alpn) {  
        const alpnStr \= String(params.alpn).trim();  
        if (alpnStr \=== 'h2') alpnCode \= 'h2';  
        else if (alpnStr \=== 'h3') alpnCode \= 'h3';  
        else if (alpnStr.startsWith('http/1.1')) alpnCode \= 'h1';  
        else if (alpnStr.length \>= 2\) alpnCode \= alpnStr\[0\] \+ alpnStr\[alpnStr.length \- 1\];  
      }

      const partA \= \`\${proto}\${ver}\${sni}\${ciphersCount}\${extsCount}\${alpnCode}\`;

      // Part B: sorted hex ciphers (4-digit lowercase hex, comma-separated)  
      const hexCiphers \= cleanCiphers.map(c \=\> {  
        const n \= typeof c \=== 'number' ? c : parseInt(String(c), 16);  
        return ('0000' \+ n.toString(16)).slice(-4).toLowerCase();  
      }).sort();  
      const bPayload \= hexCiphers.join(',');  
      const partB \= bPayload ? sha256Hex(bPayload).substring(0, 12\) : '000000000000';

      // Part C: sorted hex extensions \+ sorted signature algorithms  
      const hexExts \= cleanExts.map(e \=\> {  
        const n \= typeof e \=== 'number' ? e : parseInt(String(e), 16);  
        return ('0000' \+ n.toString(16)).slice(-4).toLowerCase();  
      }).sort();

      const rawSigAlgs \= Array.isArray(params.signatureAlgorithms) ? params.signatureAlgorithms : \[\];  
      const cleanSigAlgs \= rawSigAlgs.filter(s \=\> \!isGrease(s)).map(s \=\> {  
        const n \= typeof s \=== 'number' ? s : parseInt(String(s), 16);  
        return ('0000' \+ n.toString(16)).slice(-4).toLowerCase();  
      }).sort();

      let cPayload \= hexExts.join(',');  
      if (cleanSigAlgs.length \> 0\) {  
        cPayload \+= '\_' \+ cleanSigAlgs.join(',');  
      }  
      const partC \= cPayload ? sha256Hex(cPayload).substring(0, 12\) : '000000000000';

      return \`\${partA}\_\${partB}\_\${partC}\`;  
    },

    /\*\*  
     \* Calculates legacy JA3 fingerprint string & MD5 hash.  
     \* Raw format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats  
     \*/  
    calculateJA3(params) {  
      let sslVersion \= 771; // TLS 1.2 / 1.3 default in ClientHello  
      if (params.tlsVersion \=== 'TLSv1.3' || params.tlsVersion \=== '772') sslVersion \= 771;  
      else if (params.tlsVersion \=== 'TLSv1.1' || params.tlsVersion \=== '770') sslVersion \= 770;  
      else if (params.tlsVersion \=== 'TLSv1.0' || params.tlsVersion \=== '769') sslVersion \= 769;

      const ciphers \= (params.ciphers || \[\]).filter(c \=\> \!isGrease(c)).join('-');  
      const extensions \= (params.extensions || \[\]).filter(e \=\> \!isGrease(e)).join('-');  
      const curves \= (params.ellipticCurves || \[\]).filter(c \=\> \!isGrease(c)).join('-');  
      const pointFormats \= (params.ellipticCurvePointFormats || \[\]).filter(p \=\> \!isGrease(p)).join('-');

      const rawString \= \`\${sslVersion},\${ciphers},\${extensions},\${curves},\${pointFormats}\`;  
      const hash \= md5(rawString);

      return {  
        raw: rawString,  
        hash  
      };  
    },

    /\*\*  
     \* Translates numeric / hex cipher codes into IANA standard names.  
     \*/  
    resolveCipherName(code) {  
      let hex \= '';  
      if (typeof code \=== 'number') {  
        hex \= '0x' \+ ('0000' \+ code.toString(16)).slice(-4).toLowerCase();  
      } else {  
        hex \= String(code).toLowerCase();  
        if (\!hex.startsWith('0x')) hex \= '0x' \+ hex;  
      }  
      return IANA\_CIPHERS\[hex\] || \`UNKNOWN\_CIPHER (\${hex})\`;  
    }  
  };

  return TLSFingerprintEngine;  
});  
