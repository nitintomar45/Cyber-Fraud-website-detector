// Cyber Fraud Detection System - Main Application Logic

// ============================================================================
// DATA STRUCTURES
// ============================================================================

const detectionRules = [
  {
    name: "Known Phishing Domain",
    category: "Phishing Patterns",
    severity: "Dangerous",
    points: 50,
    description: "URL matches a known phishing domain in our database"
  },
  {
    name: "Suspicious TLD",
    category: "Domain Reputation",
    severity: "Warning",
    points: 25,
    description: "Domain uses a suspicious or free top-level domain"
  },
  {
    name: "Domain Age Less Than 30 Days",
    category: "Domain Reputation",
    severity: "Warning",
    points: 25,
    description: "Domain appears to be newly registered (simulation)"
  },
  {
    name: "URL Length Anomaly",
    category: "URL Structure Anomalies",
    severity: "Info",
    points: 10,
    description: "URL is unusually long, often used to hide malicious content"
  },
  {
    name: "IP Address Instead of Domain",
    category: "URL Structure Anomalies",
    severity: "Warning",
    points: 25,
    description: "URL uses an IP address instead of a domain name"
  },
  {
    name: "Excessive Subdomains",
    category: "URL Structure Anomalies",
    severity: "Info",
    points: 10,
    description: "URL contains an excessive number of subdomains"
  },
  {
    name: "Missing HTTPS",
    category: "SSL/Certificate Issues",
    severity: "Info",
    points: 10,
    description: "URL does not use secure HTTPS protocol"
  },
  {
    name: "Known Malware Distribution URL",
    category: "Malware Indicators",
    severity: "Dangerous",
    points: 50,
    description: "URL matches a known malware distribution domain"
  },
  {
    name: "Homograph Attack Pattern",
    category: "Homograph Attacks",
    severity: "Warning",
    points: 25,
    description: "URL contains look-alike characters or punycode"
  },
  {
    name: "Banking Fraud Indicator",
    category: "Banking Fraud Indicators",
    severity: "Dangerous",
    points: 50,
    description: "URL contains keywords commonly used in banking fraud"
  },
  {
    name: "Character Confusion",
    category: "Homograph Attacks",
    severity: "Warning",
    points: 25,
    description: "URL uses confusing characters (0/O, 1/l, etc.)"
  },
  {
    name: "Credential Harvesting Pattern",
    category: "Credential Harvesting Indicators",
    severity: "Dangerous",
    points: 50,
    description: "URL structure suggests credential theft attempt"
  },
  {
    name: "Parameter Injection",
    category: "URL Structure Anomalies",
    severity: "Warning",
    points: 25,
    description: "URL contains suspicious parameter patterns"
  },
  {
    name: "Misspelled Popular Domain",
    category: "Phishing Patterns",
    severity: "Dangerous",
    points: 50,
    description: "Domain appears to be a misspelling of a popular site"
  }
];

const phishingDomains = [
  "hdfc-login.tk",
  "icici-bank.ml",
  "axis-verify.ga",
  "sbi-update.cf",
  "paytm-confirm.tk",
  "googlepay-verify.ml",
  "upi-authenticate.tk",
  "airtel-pay.ga",
  "phonepe-security.ml",
  "amazon-verify.tk",
  "flipkart-login.ga",
  "whatsapp-verify.cf",
  "facebook-confirm.tk",
  "gmail-recovery.ml",
  "bank-account-verify.ga",
  "netbanking-secure.tk",
  "payment-gateway.ml",
  "card-verification.ga",
  "otp-validate.cf",
  "secure-login.tk",
  "account-security.ml",
  "verify-identity.ga",
  "update-details.cf",
  "confirm-transaction.tk",
  "banking-portal.ml",
  "mobile-banking.ga",
  "wallet-verify.cf",
  "payment-secure.tk",
  "transaction-confirm.ml",
  "kyc-update.ga",
  "aadhar-verify.cf",
  "pan-update.tk",
  "mandate-approve.ml",
  "esign-document.ga",
  "digital-signature.cf",
  "authorize-payment.tk",
  "approve-transaction.ml",
  "validate-account.ga",
  "secure-access.cf",
  "login-verify.tk",
  "password-reset.ml",
  "account-recovery.ga",
  "unlock-account.cf",
  "reactivate-card.tk",
  "limit-increase.ml",
  "reward-points.ga",
  "cashback-claim.cf",
  "offer-activate.tk",
  "promocode-redeem.ml",
  "refund-process.ga"
];

const suspiciousTlds = [
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".gq",
  ".xyz",
  ".download",
  ".accountant",
  ".webcam",
  ".stream"
];

const malwareDomains = [
  "malicious-exec.net",
  "trojan-delivery.com",
  "ransomware-host.org",
  "exploit-kit.biz",
  "malware-payload.ru",
  "virus-download.info",
  "backdoor-install.net",
  "keylogger-setup.com",
  "spyware-bundle.org",
  "rootkit-installer.biz"
];

const bankingFraudKeywords = [
  "verify",
  "confirm",
  "update",
  "secure",
  "authenticate",
  "account-locked",
  "urgent-action",
  "suspicious-activity",
  "click-here",
  "validate-account",
  "re-enter",
  "credentials-expired",
  "kyc",
  "aadhar",
  "pan",
  "otp",
  "cvv",
  "pin",
  "password-reset",
  "unlock",
  "reactivate",
  "mandate"
];

const popularDomains = [
  "google",
  "amazon",
  "facebook",
  "microsoft",
  "apple",
  "netflix",
  "paypal",
  "instagram",
  "twitter",
  "linkedin",
  "hdfc",
  "icici",
  "sbi",
  "axis",
  "paytm",
  "phonepe",
  "googlepay",
  "whatsapp",
  "flipkart"
];

// Session storage for scan history and analytics
let scanHistory = [];
let analytics = {
  totalScans: 0,
  safeUrls: 0,
  warningUrls: 0,
  dangerousUrls: 0,
  threatCounts: {}
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function parseURL(urlString) {
  try {
    // Add protocol if missing
    if (!urlString.match(/^https?:\/\//i)) {
      urlString = 'http://' + urlString;
    }
    
    const url = new URL(urlString);
    return {
      original: urlString,
      protocol: url.protocol,
      hostname: url.hostname,
      pathname: url.pathname,
      search: url.search,
      hash: url.hash,
      valid: true
    };
  } catch (e) {
    return { valid: false, original: urlString };
  }
}

function extractDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length >= 2) {
    return parts.slice(-2).join('.');
  }
  return hostname;
}

function getTLD(hostname) {
  const parts = hostname.split('.');
  return parts.length > 1 ? '.' + parts[parts.length - 1] : '';
}

function formatDate(date) {
  return new Intl.DateTimeFormat('en-IN', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }).format(date);
}

// ============================================================================
// DETECTION ENGINE
// ============================================================================

function analyzeURL(urlString) {
  const result = {
    url: urlString,
    timestamp: new Date(),
    threats: [],
    riskScore: 0,
    riskLevel: 'Safe'
  };

  const parsed = parseURL(urlString);
  
  if (!parsed.valid) {
    result.threats.push({
      rule: { name: "Invalid URL", category: "URL Structure Anomalies", severity: "Warning", points: 25 },
      description: "The provided URL is malformed or invalid"
    });
    result.riskScore = 25;
    result.riskLevel = 'Warning';
    return result;
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = parsed.original.toLowerCase();
  const domain = extractDomain(hostname);
  const tld = getTLD(hostname);

  // Check 1: Known Phishing Domain
  if (phishingDomains.includes(domain) || phishingDomains.includes(hostname)) {
    const rule = detectionRules.find(r => r.name === "Known Phishing Domain");
    result.threats.push({ rule, description: rule.description });
  }

  // Check 2: Suspicious TLD
  if (suspiciousTlds.includes(tld)) {
    const rule = detectionRules.find(r => r.name === "Suspicious TLD");
    result.threats.push({ rule, description: `Domain uses suspicious TLD: ${tld}` });
  }

  // Check 3: Known Malware Domain
  if (malwareDomains.includes(domain) || malwareDomains.includes(hostname)) {
    const rule = detectionRules.find(r => r.name === "Known Malware Distribution URL");
    result.threats.push({ rule, description: rule.description });
  }

  // Check 4: Banking Fraud Keywords
  const foundKeywords = bankingFraudKeywords.filter(keyword => fullUrl.includes(keyword));
  if (foundKeywords.length > 0) {
    const rule = detectionRules.find(r => r.name === "Banking Fraud Indicator");
    result.threats.push({ 
      rule, 
      description: `Contains banking fraud keywords: ${foundKeywords.slice(0, 3).join(', ')}` 
    });
  }

  // Check 5: Missing HTTPS
  if (parsed.protocol !== 'https:') {
    const rule = detectionRules.find(r => r.name === "Missing HTTPS");
    result.threats.push({ rule, description: rule.description });
  }

  // Check 6: IP Address Instead of Domain
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipPattern.test(hostname)) {
    const rule = detectionRules.find(r => r.name === "IP Address Instead of Domain");
    result.threats.push({ rule, description: rule.description });
  }

  // Check 7: URL Length Anomaly
  if (fullUrl.length > 100) {
    const rule = detectionRules.find(r => r.name === "URL Length Anomaly");
    result.threats.push({ 
      rule, 
      description: `URL is unusually long (${fullUrl.length} characters)` 
    });
  }

  // Check 8: Excessive Subdomains
  const subdomainCount = hostname.split('.').length - 2;
  if (subdomainCount > 2) {
    const rule = detectionRules.find(r => r.name === "Excessive Subdomains");
    result.threats.push({ 
      rule, 
      description: `URL contains ${subdomainCount} subdomains` 
    });
  }

  // Check 9: Character Confusion
  const confusingChars = /[0oО0O1lІ|]/i;
  if (confusingChars.test(hostname)) {
    const rule = detectionRules.find(r => r.name === "Character Confusion");
    result.threats.push({ rule, description: rule.description });
  }

  // Check 10: Punycode/Homograph Attack
  if (hostname.includes('xn--')) {
    const rule = detectionRules.find(r => r.name === "Homograph Attack Pattern");
    result.threats.push({ rule, description: "URL uses punycode encoding" });
  }

  // Check 11: Misspelled Popular Domain
  for (const popular of popularDomains) {
    if (hostname.includes(popular) && !hostname.endsWith(popular + '.com') && 
        !hostname.endsWith(popular + '.in') && hostname !== popular) {
      // Check for common misspellings
      const variations = [
        popular.replace('o', '0'),
        popular.replace('a', '4'),
        popular.replace('e', '3'),
        popular + 'official',
        popular + 'secure',
        'secure' + popular,
        popular.replace('l', '1')
      ];
      
      if (variations.some(v => hostname.includes(v))) {
        const rule = detectionRules.find(r => r.name === "Misspelled Popular Domain");
        result.threats.push({ 
          rule, 
          description: `Domain appears to mimic ${popular}` 
        });
        break;
      }
    }
  }

  // Check 12: Parameter Injection
  if (parsed.search && (parsed.search.includes('javascript:') || 
      parsed.search.includes('<script') || parsed.search.includes('onerror='))) {
    const rule = detectionRules.find(r => r.name === "Parameter Injection");
    result.threats.push({ rule, description: rule.description });
  }

  // Check 13: Credential Harvesting Pattern
  const credentialPatterns = ['login', 'signin', 'password', 'credential', 'auth'];
  const hasCredentialPattern = credentialPatterns.some(p => fullUrl.includes(p));
  if (hasCredentialPattern && (suspiciousTlds.includes(tld) || fullUrl.length > 80)) {
    const rule = detectionRules.find(r => r.name === "Credential Harvesting Pattern");
    result.threats.push({ rule, description: rule.description });
  }

  // Calculate risk score
  result.riskScore = result.threats.reduce((sum, threat) => sum + threat.rule.points, 0);
  result.riskScore = Math.min(result.riskScore, 100); // Cap at 100

  // Determine risk level
  if (result.riskScore <= 30) {
    result.riskLevel = 'Safe';
  } else if (result.riskScore <= 70) {
    result.riskLevel = 'Warning';
  } else {
    result.riskLevel = 'Dangerous';
  }

  return result;
}

function generateRecommendations(result) {
  const recommendations = [];

  if (result.riskLevel === 'Safe') {
    recommendations.push("This URL appears to be safe based on our analysis");
    recommendations.push("Always verify the domain matches the expected website");
    recommendations.push("Look for HTTPS and a valid SSL certificate");
  } else if (result.riskLevel === 'Warning') {
    recommendations.push("Exercise caution when accessing this URL");
    recommendations.push("Verify the legitimacy of this website before entering any information");
    recommendations.push("Check for spelling mistakes in the domain name");
    recommendations.push("Do not enter sensitive information unless you trust the source");
  } else {
    recommendations.push("⚠️ DO NOT ACCESS THIS URL - High risk detected");
    recommendations.push("This URL shows multiple indicators of malicious intent");
    recommendations.push("Do not click on links from unknown sources");
    recommendations.push("Report this URL if received via email or SMS");
    recommendations.push("Never enter banking credentials on suspicious websites");
  }

  return recommendations;
}

// ============================================================================
// UI FUNCTIONS
// ============================================================================

function displayScanResults(result) {
  const resultsDiv = document.getElementById('scanResults');
  const riskClass = result.riskLevel.toLowerCase();
  
  const recommendations = generateRecommendations(result);

  let html = `
    <div class="result-header ${riskClass}">
      <div class="result-status">
        <div class="status-icon ${riskClass}">
          ${getRiskIcon(result.riskLevel)}
        </div>
        <div class="status-text">
          <h3>${result.riskLevel.toUpperCase()}</h3>
          <p>${getRiskMessage(result.riskLevel)}</p>
        </div>
      </div>
      <div class="risk-score">
        <span class="score-value">${result.riskScore}</span>
        <span class="score-label">Risk Score</span>
      </div>
    </div>

    <div class="result-url">
      <strong>Scanned URL:</strong><br>
      ${escapeHtml(result.url)}
    </div>
  `;

  if (result.threats.length > 0) {
    html += `
      <div class="threats-detected">
        <h4>Threats Detected (${result.threats.length})</h4>
        <div class="threat-list">
    `;

    result.threats.forEach(threat => {
      const severityClass = threat.rule.severity.toLowerCase();
      html += `
        <div class="threat-item">
          <svg class="threat-icon ${severityClass}" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            ${getThreatIcon(threat.rule.severity)}
          </svg>
          <div class="threat-details">
            <div class="threat-name">${threat.rule.name}</div>
            <div class="threat-category">${threat.rule.category} • ${threat.description}</div>
          </div>
          <div class="threat-points">+${threat.rule.points}</div>
        </div>
      `;
    });

    html += `
        </div>
      </div>
    `;
  }

  html += `
    <div class="recommendations">
      <h4>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="16" x2="12" y2="12"/>
          <line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>
        Recommendations
      </h4>
      <ul>
        ${recommendations.map(rec => `<li>${rec}</li>`).join('')}
      </ul>
    </div>

    <div class="scan-timestamp">
      Scan completed at ${formatDate(result.timestamp)}
    </div>
  `;

  resultsDiv.innerHTML = html;
  resultsDiv.style.display = 'block';
}

function getRiskIcon(riskLevel) {
  if (riskLevel === 'Safe') {
    return '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>';
  } else if (riskLevel === 'Warning') {
    return '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>';
  } else {
    return '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>';
  }
}

function getThreatIcon(severity) {
  if (severity === 'Dangerous') {
    return '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>';
  } else if (severity === 'Warning') {
    return '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>';
  } else {
    return '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>';
  }
}

function getRiskMessage(riskLevel) {
  if (riskLevel === 'Safe') {
    return 'No significant threats detected';
  } else if (riskLevel === 'Warning') {
    return 'Suspicious patterns detected - Exercise caution';
  } else {
    return 'Critical threats detected - Do not access';
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function updateHeaderStats() {
  document.getElementById('totalScans').textContent = analytics.totalScans;
  document.getElementById('threatsBlocked').textContent = analytics.dangerousUrls;
}

function updateHistoryTable() {
  const tbody = document.getElementById('historyTableBody');
  
  if (scanHistory.length === 0) {
    tbody.innerHTML = '<tr class="empty-state"><td colspan="6">No scans yet. Start by scanning a URL in the Scanner tab.</td></tr>';
    return;
  }

  let html = '';
  scanHistory.slice().reverse().forEach((scan, index) => {
    const riskClass = scan.riskLevel.toLowerCase();
    html += `
      <tr>
        <td>${formatDate(scan.timestamp)}</td>
        <td class="url-cell" title="${escapeHtml(scan.url)}">${escapeHtml(scan.url)}</td>
        <td><span class="badge ${riskClass}">${scan.riskLevel}</span></td>
        <td><strong>${scan.riskScore}</strong>/100</td>
        <td>${scan.threats.length}</td>
        <td>
          <button class="btn btn--sm btn--outline" onclick="viewScanDetails(${scanHistory.length - 1 - index})">
            View Details
          </button>
        </td>
      </tr>
    `;
  });

  tbody.innerHTML = html;
}

function viewScanDetails(index) {
  const scan = scanHistory[index];
  // Switch to scanner tab and display the results
  switchTab('scanner');
  displayScanResults(scan);
  // Scroll to results
  document.getElementById('scanResults').scrollIntoView({ behavior: 'smooth' });
}

function updateRulesDisplay() {
  document.getElementById('totalRules').textContent = detectionRules.length;
  
  const dangerousCount = detectionRules.filter(r => r.severity === 'Dangerous').length;
  const warningCount = detectionRules.filter(r => r.severity === 'Warning').length;
  const infoCount = detectionRules.filter(r => r.severity === 'Info').length;
  
  document.getElementById('dangerousRules').textContent = dangerousCount;
  document.getElementById('warningRules').textContent = warningCount;
  document.getElementById('infoRules').textContent = infoCount;

  const rulesList = document.getElementById('rulesList');
  let html = '';

  detectionRules.forEach(rule => {
    html += `
      <div class="rule-card">
        <div class="rule-info">
          <h4>${rule.name}</h4>
          <div class="rule-meta">
            <span>${rule.category}</span>
            <span>•</span>
            <span class="badge ${rule.severity.toLowerCase()}">${rule.severity}</span>
          </div>
        </div>
        <div class="rule-points">+${rule.points} points</div>
      </div>
    `;
  });

  rulesList.innerHTML = html;
  document.getElementById('rulesLastUpdated').textContent = formatDate(new Date());
}

function updateBlacklistDisplay() {
  document.getElementById('phishingCount').textContent = phishingDomains.length;
  document.getElementById('tldCount').textContent = suspiciousTlds.length;
  document.getElementById('malwareCount').textContent = malwareDomains.length;
  document.getElementById('keywordCount').textContent = bankingFraudKeywords.length;

  // Display domain lists
  const phishingDiv = document.getElementById('phishingDomains');
  phishingDiv.innerHTML = phishingDomains.slice(0, 15).map(domain => 
    `<span class="domain-tag">${domain}</span>`
  ).join('') + '<span class="domain-tag">... and more</span>';

  const tldDiv = document.getElementById('suspiciousTlds');
  tldDiv.innerHTML = suspiciousTlds.map(tld => 
    `<span class="domain-tag">${tld}</span>`
  ).join('');

  const malwareDiv = document.getElementById('malwareDomains');
  malwareDiv.innerHTML = malwareDomains.map(domain => 
    `<span class="domain-tag">${domain}</span>`
  ).join('');

  const keywordDiv = document.getElementById('fraudKeywords');
  keywordDiv.innerHTML = bankingFraudKeywords.slice(0, 15).map(keyword => 
    `<span class="domain-tag">${keyword}</span>`
  ).join('') + '<span class="domain-tag">... and more</span>';
}

function updateAnalyticsDisplay() {
  document.getElementById('analyticsTotal').textContent = analytics.totalScans;
  document.getElementById('analyticsSafe').textContent = analytics.safeUrls;
  document.getElementById('analyticsWarning').textContent = analytics.warningUrls;
  document.getElementById('analyticsDangerous').textContent = analytics.dangerousUrls;

  // Update threat distribution chart
  updateThreatChart();
  updateRiskChart();
  updateCommonThreats();
}

let threatChart = null;
let riskChart = null;

function updateThreatChart() {
  const ctx = document.getElementById('threatChart');
  if (!ctx) return;

  const data = {
    labels: ['Safe', 'Warning', 'Dangerous'],
    datasets: [{
      data: [analytics.safeUrls, analytics.warningUrls, analytics.dangerousUrls],
      backgroundColor: [
        'rgba(33, 128, 141, 0.8)',
        'rgba(230, 129, 97, 0.8)',
        'rgba(255, 84, 89, 0.8)'
      ],
      borderColor: [
        'rgba(33, 128, 141, 1)',
        'rgba(230, 129, 97, 1)',
        'rgba(255, 84, 89, 1)'
      ],
      borderWidth: 2
    }]
  };

  if (threatChart) {
    threatChart.data = data;
    threatChart.update();
  } else {
    threatChart = new Chart(ctx, {
      type: 'doughnut',
      data: data,
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: getComputedStyle(document.documentElement).getPropertyValue('--color-text'),
              font: { size: 12 }
            }
          }
        }
      }
    });
  }
}

function updateRiskChart() {
  const ctx = document.getElementById('riskChart');
  if (!ctx) return;

  const riskRanges = { '0-30': 0, '31-70': 0, '71-100': 0 };
  scanHistory.forEach(scan => {
    if (scan.riskScore <= 30) riskRanges['0-30']++;
    else if (scan.riskScore <= 70) riskRanges['31-70']++;
    else riskRanges['71-100']++;
  });

  const data = {
    labels: ['Safe (0-30)', 'Warning (31-70)', 'Dangerous (71-100)'],
    datasets: [{
      label: 'URLs by Risk Score',
      data: [riskRanges['0-30'], riskRanges['31-70'], riskRanges['71-100']],
      backgroundColor: [
        'rgba(33, 128, 141, 0.6)',
        'rgba(230, 129, 97, 0.6)',
        'rgba(255, 84, 89, 0.6)'
      ],
      borderColor: [
        'rgba(33, 128, 141, 1)',
        'rgba(230, 129, 97, 1)',
        'rgba(255, 84, 89, 1)'
      ],
      borderWidth: 2
    }]
  };

  if (riskChart) {
    riskChart.data = data;
    riskChart.update();
  } else {
    riskChart = new Chart(ctx, {
      type: 'bar',
      data: data,
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { display: false }
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              color: getComputedStyle(document.documentElement).getPropertyValue('--color-text-secondary'),
              stepSize: 1
            },
            grid: {
              color: getComputedStyle(document.documentElement).getPropertyValue('--color-card-border')
            }
          },
          x: {
            ticks: {
              color: getComputedStyle(document.documentElement).getPropertyValue('--color-text-secondary')
            },
            grid: {
              display: false
            }
          }
        }
      }
    });
  }
}

function updateCommonThreats() {
  const threatsDiv = document.getElementById('commonThreats');
  
  if (Object.keys(analytics.threatCounts).length === 0) {
    threatsDiv.innerHTML = '<div class="empty-state-small">No threats detected yet</div>';
    return;
  }

  const sortedThreats = Object.entries(analytics.threatCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  let html = '';
  sortedThreats.forEach(([threat, count]) => {
    html += `
      <div class="threat-list-item">
        <span>${threat}</span>
        <strong>${count}</strong>
      </div>
    `;
  });

  threatsDiv.innerHTML = html;
}

function exportHistoryCSV() {
  if (scanHistory.length === 0) {
    alert('No scan history to export');
    return;
  }

  let csv = 'Timestamp,URL,Risk Level,Risk Score,Threats Detected\n';
  
  scanHistory.forEach(scan => {
    const timestamp = formatDate(scan.timestamp).replace(/,/g, '');
    const url = scan.url.replace(/,/g, ';');
    const threats = scan.threats.map(t => t.rule.name).join('; ');
    csv += `"${timestamp}","${url}",${scan.riskLevel},${scan.riskScore},"${threats}"\n`;
  });

  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `scan-history-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ============================================================================
// EVENT HANDLERS
// ============================================================================

function performScan() {
  const urlInput = document.getElementById('urlInput');
  const urlString = urlInput.value.trim();

  if (!urlString) {
    alert('Please enter a URL to scan');
    return;
  }

  // Show loading state
  document.getElementById('loadingState').style.display = 'block';
  document.getElementById('scanResults').style.display = 'none';

  // Simulate processing time for better UX
  setTimeout(() => {
    const result = analyzeURL(urlString);
    
    // Update analytics
    analytics.totalScans++;
    if (result.riskLevel === 'Safe') analytics.safeUrls++;
    else if (result.riskLevel === 'Warning') analytics.warningUrls++;
    else analytics.dangerousUrls++;

    result.threats.forEach(threat => {
      const name = threat.rule.name;
      analytics.threatCounts[name] = (analytics.threatCounts[name] || 0) + 1;
    });

    // Add to history
    scanHistory.push(result);

    // Update UI
    updateHeaderStats();
    displayScanResults(result);
    document.getElementById('loadingState').style.display = 'none';

    // Clear input
    urlInput.value = '';
  }, 1500);
}

function switchTab(tabName) {
  // Update nav buttons
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.classList.remove('active');
    if (btn.getAttribute('data-tab') === tabName) {
      btn.classList.add('active');
    }
  });

  // Update tab content
  document.querySelectorAll('.tab-content').forEach(tab => {
    tab.classList.remove('active');
  });
  document.getElementById(tabName + '-tab').classList.add('active');

  // Update content for specific tabs
  if (tabName === 'history') {
    updateHistoryTable();
  } else if (tabName === 'analytics') {
    updateAnalyticsDisplay();
  }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

function initializeApp() {
  // Navigation
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.getAttribute('data-tab');
      switchTab(tab);
    });
  });

  // Scan button
  document.getElementById('scanBtn').addEventListener('click', performScan);

  // Enter key in URL input
  document.getElementById('urlInput').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      performScan();
    }
  });

  // Export history
  document.getElementById('exportHistoryBtn').addEventListener('click', exportHistoryCSV);

  // Clear history
  document.getElementById('clearHistoryBtn').addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all scan history?')) {
      scanHistory = [];
      analytics = {
        totalScans: 0,
        safeUrls: 0,
        warningUrls: 0,
        dangerousUrls: 0,
        threatCounts: {}
      };
      updateHeaderStats();
      updateHistoryTable();
      updateAnalyticsDisplay();
    }
  });

  // Refresh rules
  document.getElementById('refreshRulesBtn').addEventListener('click', () => {
    updateRulesDisplay();
    alert('Detection rules refreshed successfully!');
  });

  // False positive report
  document.getElementById('reportFalsePositive').addEventListener('click', () => {
    alert('False positive report feature would send feedback to improve detection accuracy. This is a demonstration version.');
  });

  // Initialize displays
  updateRulesDisplay();
  updateBlacklistDisplay();
  updateHeaderStats();

  console.log('Cyber Fraud Detection System initialized');
  console.log('Detection Rules:', detectionRules.length);
  console.log('Phishing Domains:', phishingDomains.length);
  console.log('Malware Domains:', malwareDomains.length);
}

// Start the app when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeApp);
} else {
  initializeApp();
}