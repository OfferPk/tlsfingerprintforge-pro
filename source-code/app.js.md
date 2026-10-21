/\*\*  
 \* TLSFingerprintForge Pro \- Studio UI Controller  
 \*/

// Global State  
let currentSession \= {  
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10\_15\_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',  
  clientHello: {  
    protocol: 'TCP',  
    tlsVersion: 'TLSv1.3',  
    hasSniDomain: true,  
    alpn: 'h2',  
    ciphers: \[4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53, 2570\],  
    extensions: \[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21, 6666\],  
    ellipticCurves: \[29, 23, 24\],  
    ellipticCurvePointFormats: \[0\],  
    signatureAlgorithms: \[1027, 1283, 1539, 2052, 2053, 2054\]  
  }  
};

let currentConfigTab \= 'cloudflare'; // 'cloudflare', 'aws', 'nginx', 'haproxy', 'modsec'

const PRESETS \= {  
  chrome: {  
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10\_15\_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',  
    clientHello: {  
      protocol: 'TCP',  
      tlsVersion: 'TLSv1.3',  
      hasSniDomain: true,  
      alpn: 'h2',  
      ciphers: \[4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53, 2570\],  
      extensions: \[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21, 6666\],  
      ellipticCurves: \[29, 23, 24\],  
      ellipticCurvePointFormats: \[0\],  
      signatureAlgorithms: \[1027, 1283, 1539, 2052, 2053, 2054\]  
    }  
  },  
  python: {  
    userAgent: 'python-requests/2.31.0',  
    clientHello: {  
      protocol: 'TCP',  
      tlsVersion: 'TLSv1.3',  
      hasSniDomain: true,  
      alpn: '',  
      ciphers: \[49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172\],  
      extensions: \[0, 11, 10, 35, 13, 15, 65281\],  
      ellipticCurves: \[29, 23, 24\],  
      ellipticCurvePointFormats: \[0\],  
      signatureAlgorithms: \[1027, 1283, 1539, 2052, 2053, 2054\]  
    }  
  },  
  stealth: {  
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',  
    clientHello: {  
      protocol: 'TCP',  
      tlsVersion: 'TLSv1.3',  
      hasSniDomain: true,  
      alpn: 'h2',  
      ciphers: \[4865, 4866, 4867\],  
      extensions: \[0, 10, 11, 16\],  
      ellipticCurves: \[29\],  
      ellipticCurvePointFormats: \[0\],  
      signatureAlgorithms: \[1027\]  
    }  
  }  
};

document.addEventListener('DOMContentLoaded', () \=\> {  
  loadPreset('chrome');  
});

function loadPreset(key) {  
  const p \= PRESETS\[key\];  
  if (\!p) return;

  \['btnPresetChrome', 'btnPresetPython', 'btnPresetStealth'\].forEach(id \=\> {  
    document.getElementById(id)?.classList.remove('active');  
  });

  if (key \=== 'chrome') document.getElementById('btnPresetChrome')?.classList.add('active');  
  if (key \=== 'python') document.getElementById('btnPresetPython')?.classList.add('active');  
  if (key \=== 'stealth') document.getElementById('btnPresetStealth')?.classList.add('active');

  currentSession \= JSON.parse(JSON.stringify(p));

  // Populate UI inputs  
  document.getElementById('txtUserAgent').value \= currentSession.userAgent;  
  document.getElementById('selProtocol').value \= currentSession.clientHello.protocol || 'TCP';  
  document.getElementById('selTlsVersion').value \= currentSession.clientHello.tlsVersion || 'TLSv1.3';  
  document.getElementById('selAlpn').value \= currentSession.clientHello.alpn || '';  
  document.getElementById('txtCiphers').value \= (currentSession.clientHello.ciphers || \[\]).join(', ');  
  document.getElementById('txtExtensions').value \= (currentSession.clientHello.extensions || \[\]).join(', ');  
  document.getElementById('txtCurves').value \= (currentSession.clientHello.ellipticCurves || \[\]).join(', ');

  runLiveAudit();  
}

function onUserAgentChange(val) {  
  currentSession.userAgent \= val.trim();  
  runLiveAudit();  
}

function onParamChange() {  
  currentSession.clientHello.protocol \= document.getElementById('selProtocol').value;  
  currentSession.clientHello.tlsVersion \= document.getElementById('selTlsVersion').value;  
  currentSession.clientHello.alpn \= document.getElementById('selAlpn').value;

  const parseNums \= (str) \=\> {  
    return str.split(/\[,-\\s\]+/)  
      .map(s \=\> s.trim())  
      .filter(Boolean)  
      .map(s \=\> s.startsWith('0x') ? parseInt(s, 16\) : parseInt(s, 10))  
      .filter(n \=\> \!isNaN(n));  
  };

  currentSession.clientHello.ciphers \= parseNums(document.getElementById('txtCiphers').value);  
  currentSession.clientHello.extensions \= parseNums(document.getElementById('txtExtensions').value);  
  currentSession.clientHello.ellipticCurves \= parseNums(document.getElementById('txtCurves').value);

  runLiveAudit();  
}

function runLiveAudit() {  
  const auditReport \= TLSDissectorAuditor.audit(currentSession);

  // Update Metrics  
  document.getElementById('metricJa4').innerText \= auditReport.ja4;  
  document.getElementById('metricJa3').innerText \= auditReport.ja3Hash.substring(0, 10\) \+ '...';

  const hasGrease \= (currentSession.clientHello.ciphers || \[\]).some(c \=\> TLSFingerprintEngine.isGrease(c)) ||  
                    (currentSession.clientHello.extensions || \[\]).some(e \=\> TLSFingerprintEngine.isGrease(e));

  const greaseEl \= document.getElementById('metricGrease');  
  if (hasGrease) {  
    greaseEl.innerText \= 'Detected';  
    greaseEl.style.color \= 'var(--accent-green)';  
  } else {  
    greaseEl.innerText \= 'Absent';  
    greaseEl.style.color \= 'var(--text-muted)';  
  }

  // Threat Badge  
  const threatBadge \= document.getElementById('threatBadge');  
  threatBadge.innerText \= auditReport.threatLevel.replace(/\_/g, ' ');  
  if (auditReport.threatLevel \=== 'VERIFIED\_HUMAN\_BROWSER') {  
    threatBadge.className \= 'badge badge-green';  
  } else if (auditReport.threatLevel \=== 'MASQUERADING\_STEALTH\_BOT' || auditReport.threatLevel \=== 'CONFIRMED\_MALWARE\_OR\_EXPLOIT') {  
    threatBadge.className \= 'badge badge-red';  
  } else {  
    threatBadge.className \= 'badge badge-amber';  
  }

  // Mismatch Alert Banner  
  const banner \= document.getElementById('mismatchBanner');  
  if (auditReport.isUaMismatch) {  
    banner.style.display \= 'flex';  
    document.getElementById('mismatchReasonText').innerText \= auditReport.mismatchReason;  
  } else {  
    banner.style.display \= 'none';  
  }

  // Signature Matching Card  
  const sig \= auditReport.matchedSignature;  
  if (sig) {  
    document.getElementById('sigMatchName').innerText \= sig.name;  
    document.getElementById('sigCategoryBadge').innerText \= sig.category;  
    document.getElementById('sigCategoryBadge').className \= \`badge \${sig.isBot ? 'badge-red' : 'badge-green'}\`;  
    document.getElementById('sigMatchDesc').innerText \= sig.description;  
    document.getElementById('sigFingerprintRef').innerText \= \`Matched via JA4 prefix: \${sig.ja4Prefix || 'N/A'} | JA3: \${sig.ja3Hash || 'N/A'}\`;  
  } else {  
    document.getElementById('sigMatchName').innerText \= 'Uncatalogued TLS Client Signature';  
    document.getElementById('sigCategoryBadge').innerText \= 'UNKNOWN';  
    document.getElementById('sigCategoryBadge').className \= 'badge badge-amber';  
    document.getElementById('sigMatchDesc').innerText \= 'This TLS handshake does not match known browser or public scraper signatures.';  
    document.getElementById('sigFingerprintRef').innerText \= \`JA4: \${auditReport.ja4}\`;  
  }

  // Scorecard Header  
  const gradeBadge \= document.getElementById('gradeBadge');  
  gradeBadge.innerText \= auditReport.grade;  
  gradeBadge.className \= 'score-badge-huge grade-' \+ auditReport.grade.toLowerCase().replace('+', 'plus');

  document.getElementById('scoreSummary').innerText \= \`Score: \${auditReport.score} / 100\`;  
  document.getElementById('gradeSubtitle').innerText \= auditReport.isProductionReady  
    ? 'Legitimate Human Browser Fingerprint'  
    : 'Automated Bot, Scraping Tool, or Header Mismatch Detected';

  const prodBadge \= document.getElementById('prodReadyBadge');  
  if (auditReport.isProductionReady) {  
    prodBadge.innerText \= 'VERIFIED HUMAN';  
    prodBadge.className \= 'badge badge-green';  
  } else {  
    prodBadge.innerText \= 'BOT / THREAT DETECTED';  
    prodBadge.className \= 'badge badge-red';  
  }

  // Render Checks  
  const checksList \= document.getElementById('checksList');  
  checksList.innerHTML \= '';  
  auditReport.checks.forEach(chk \=\> {  
    const item \= document.createElement('div');  
    item.className \= 'check-item';

    const header \= document.createElement('div');  
    header.className \= 'check-header';

    const title \= document.createElement('div');  
    title.className \= 'check-title';  
    title.innerHTML \= \`\<span\>\${chk.passed ? '✅' : (chk.level \=== 'CRITICAL' ? '🛑' : '⚠️')}\</span\> \<span\>\${chk.title}\</span\>\`;

    const badge \= document.createElement('span');  
    badge.className \= \`badge \${chk.passed ? 'badge-green' : (chk.level \=== 'CRITICAL' ? 'badge-red' : 'badge-amber')}\`;  
    badge.innerText \= \`\${chk.points}/\${chk.maxPoints} pts\`;

    header.appendChild(title);  
    header.appendChild(badge);

    const msg \= document.createElement('div');  
    msg.className \= 'check-msg';  
    msg.innerText \= chk.message;

    item.appendChild(header);  
    item.appendChild(msg);

    if (\!chk.passed && chk.remediation) {  
      const rem \= document.createElement('div');  
      rem.className \= 'check-remediation';  
      rem.innerText \= '🔧 Mitigation: ' \+ chk.remediation;  
      item.appendChild(rem);  
    }

    checksList.appendChild(item);  
  });

  renderWafSynthesizer(auditReport.ja4, auditReport.ja3Hash);  
}

function switchConfigTab(tab) {  
  currentConfigTab \= tab;  
  \['tabCloudflare', 'tabAws', 'tabNginx', 'tabHaproxy', 'tabModsec'\].forEach(id \=\> {  
    document.getElementById(id)?.classList.remove('active');  
  });

  if (tab \=== 'cloudflare') document.getElementById('tabCloudflare')?.classList.add('active');  
  if (tab \=== 'aws') document.getElementById('tabAws')?.classList.add('active');  
  if (tab \=== 'nginx') document.getElementById('tabNginx')?.classList.add('active');  
  if (tab \=== 'haproxy') document.getElementById('tabHaproxy')?.classList.add('active');  
  if (tab \=== 'modsec') document.getElementById('tabModsec')?.classList.add('active');

  const ja4 \= document.getElementById('metricJa4').innerText;  
  const ja3 \= currentSession ? TLSFingerprintEngine.calculateJA3(currentSession.clientHello).hash : '';  
  renderWafSynthesizer(ja4, ja3);  
}

function renderWafSynthesizer(ja4, ja3Hash) {  
  const codeEl \= document.getElementById('configOutput');  
  let code \= '';

  if (currentConfigTab \=== 'cloudflare') {  
    code \= TLSWAFSynthesizer.generateCloudflare(ja4, ja3Hash, 'block');  
  } else if (currentConfigTab \=== 'aws') {  
    code \= TLSWAFSynthesizer.generateAWSWAF(ja4, 'BLOCK');  
  } else if (currentConfigTab \=== 'nginx') {  
    code \= TLSWAFSynthesizer.generateNginx(ja4, ja3Hash);  
  } else if (currentConfigTab \=== 'haproxy') {  
    code \= TLSWAFSynthesizer.generateHAProxy(ja4);  
  } else if (currentConfigTab \=== 'modsec') {  
    code \= TLSWAFSynthesizer.generateModSecurity(ja4, ja3Hash);  
  }  
  codeEl.innerText \= code;  
}

function copyToClipboard(elementId, alertId) {  
  const el \= document.getElementById(elementId);  
  if (\!el) return;  
  navigator.clipboard.writeText(el.value).then(() \=\> {  
    showAlert(alertId);  
  }).catch(() \=\> {  
    el.select();  
    document.execCommand('copy');  
    showAlert(alertId);  
  });  
}

function copyTextFromElement(elementId, alertId) {  
  const el \= document.getElementById(elementId);  
  if (\!el) return;  
  navigator.clipboard.writeText(el.innerText).then(() \=\> {  
    showAlert(alertId);  
  });  
}

function showAlert(alertId) {  
  const alertEl \= document.getElementById(alertId);  
  if (alertEl) {  
    alertEl.style.display \= 'inline';  
    setTimeout(() \=\> {  
      alertEl.style.display \= 'none';  
    }, 2000);  
  }  
}  
