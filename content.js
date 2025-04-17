(() => {
  // Debug helper function
  function debugLog(message) {
    console.log("[IOCScout] " + message);
  }

  // --- Constants (Domains, Brands, Kits) ---
  const legitimateDomains = [
    // Microsoft domains
    'microsoft.com',
    'office.com',
    'office365.com',
    'live.com',
    'outlook.com',
    'sharepoint.com',
    'onedrive.com',
    'msn.com',
    'msedge.net',
    'microsoftonline.com',
    'azure.com',
    'windows.com',
    'visualstudio.com',
    'aka.ms', 
    'office-sway.com',
    'microsoft365.com',
    
    // CDN & Service Domains
    'cloudflare.com',
    'googleapis.com',
    'gstatic.com',
    'jquery.com',
    'fontawesome.com',
    'cloudfront.net',
    'akamaihd.net'
  ];
  const knownBrands = {
  'microsoft': ['microsoft', 'office', 'outlook', 'onedrive', 'sharepoint', 'teams', 
    'sign in to your account', 'signin', 'microsoft account', 'msauth', 'login', 
    'login.microsoftonline', 'office365', 'ms-login', 'hotmail', 'live.com'],
  'google': ['google', 'gmail', 'drive'],
  'dropbox': ['dropbox', 'file sharing'],
  'docusign': ['docusign', 'docu sign', 'esign', 'document signing'],
  'adobe': ['adobe', 'pdf', 'acrobat'],
  'paypal': ['paypal', 'payment'],
  'apple': ['apple', 'icloud'],
  'amazon': ['amazon', 'aws', 'prime', 'a to z', 'amazon.com', 'amazon prime', 'deliver to'],
  'facebook': ['facebook', 'instagram', 'fb login', 'facebook login'],
  'meta': ['meta', 'facebook business', 'meta for business', 'page appeal', 'meta appeal', 'meta platform'],
  'linkedin': ['linkedin'],
  'twitter': ['twitter', 'x.com'],
  'bank': ['bank', 'banking', 'chase', 'wells fargo', 'citibank'],
  'guild': ['guild', 'mortgage', 'loan'],
  'virtru': ['virtru', 'secure reader', 'secure email'],
  'moonpay': ['moonpay', 'moon pay', 'moon-pay'],
  'coinbase': ['coinbase', 'coin base'],
  'metamask': ['metamask', 'meta mask'],
  'binance': ['binance', 'bnb'],
  'crypto_general': ['crypto', 'bitcoin', 'ethereum', 'wallet', 'blockchain', 'web3'],
  'ledger': ['ledger', 'ledger live', 'ledger wallet', 'ledger nano', 'hardware wallet'],
  'att': ['att', 'at&t', 'currently.com', 'att mail', 'att.net', 'att.com', 'att login'],
  'steam': ['steam', 'valve', 'steamcommunity', 'steamgift', 'steam gift', 'steam wallet', 'steam activation'],
  'gaming_general': ['epic games', 'origin', 'uplay', 'battlenet', 'xbox', 'playstation', 'nintendo'],
  'roundcube': ['roundcube', 'roundcubemail', 'rcube'],
  'webmail_generic': ['webmail', 'mail login', 'email login', 'mail server', 'email server'],
  'hover': ['hover', 'hover.com', 'mail.hover.com', 'hover webmail']
};
  const phishingKitIndicators = {
    'axure': [
      '<!-- 11.0.0.4122 -->',
      'axplayer.js',
      'axutils.js'
    ],
    'adobe_kit': [
      'adobe-dc-view-sdk',
      'pdf.worker.js'
    ],
    'office_kit': [
      'office.login',
      'ms-login.js'
    ]
  };

  // --- Helper Functions (isLegitimateDomain, addUniqueTactic, etc.) ---

  // Function to check if a domain is legitimate
  function isLegitimateDomain(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname;
      
      // Check exact domain match
      if (legitimateDomains.includes(hostname)) {
        return true;
      }
      
      // Check subdomain of legitimate domain
      for (const domain of legitimateDomains) {
        if (hostname.endsWith('.' + domain)) {
          return true;
        }
      }
      
      return false;
    } catch (e) {
      // If URL parsing fails, return false
      return false;
    }
  }

  // Helper functions - add these if they don't exist

  function addUniqueTactic(mainObject, tactic) {
    if (!mainObject.tactics.includes(tactic)) {
      mainObject.tactics.push(tactic);
    }
  }

  function addIOC(mainObject, type, value, description, severity) {
    // Check if this exact IOC already exists
    const exists = mainObject.iocs.some(ioc => 
      ioc.type === type && ioc.value === value
    );
    
    if (!exists) {
      mainObject.iocs.push({
        type: type,
        value: value,
        description: description,
        severity: severity
      });
    }
  }

  function addClassificationNote(mainObject, note) {
    if (!mainObject.classification.notes.includes(note)) {
      mainObject.classification.notes.push(note);
    }
  }

  // --- Detection Functions (detectBrands, detectPhishingKit, etc.) ---
  // These functions remain largely the same but will be called with the main 'iocsObject'

  function detectBrands(doc, mainObject) {
    const title = doc.title ? doc.title.toLowerCase() : "";
    const text = doc.body ? doc.body.innerText.toLowerCase() : "";
    
    // Iterate through knownBrands
    for (const [brand, keywords] of Object.entries(knownBrands)) {
      let matchCount = 0;
      let matchDetails = [];
      
      for (const keyword of keywords) {
        // Check title (weighted higher)
        if (title.includes(keyword)) {
          matchCount += 2;
          matchDetails.push(`title: "${keyword}"`);
        }
        
        // Check visible text
        if (text.includes(keyword)) {
          matchCount += 1;
          matchDetails.push(`text: "${keyword}"`);
        }
      }
      
      // If sufficient matches found, add to detected brands
      if (matchCount >= 2) {
        if (!mainObject.detected_brands.includes(brand)) {
          mainObject.detected_brands.push(brand);
          
          addIOC(
            mainObject,
            "brand_reference",
            brand,
            `Brand reference: ${brand} (${matchDetails.join(", ")})`,
            "medium"
          );
          
          addClassificationNote(mainObject, `References to ${brand} brand detected`);
          
          // If more than 2 distinct references, likely a brand impersonation
          if (matchCount >= 4) {
            addUniqueTactic(mainObject, "brand_impersonation");
          }
        }
      }
    }
  }

  function detectSuspiciousIframes(doc, mainObject) {
    const iframes = Array.from(doc.querySelectorAll('iframe'));
    
    for (const iframe of iframes) {
      const src = iframe.getAttribute('src');
      const style = iframe.getAttribute('style') || '';
      
      // Check for blank/suspicious iframes
      if (!src || src === 'about:blank' || src === '#') {
        addIOC(
          mainObject,
          "suspicious_iframe",
          src || "blank",
          "Iframe with blank or suspicious source",
          "high"
        );
        
        addUniqueTactic(mainObject, "iframe_manipulation");
        mainObject.classification.confidence_score += 0.1;
      }
      
      // Check for hidden iframes
      if (style.includes('display:none') || 
          style.includes('display: none') || 
          style.includes('visibility:hidden') || 
          style.includes('visibility: hidden') || 
          style.includes('opacity:0') || 
          style.includes('opacity: 0')) {
        
        addIOC(
          mainObject,
          "hidden_iframe",
          src || "blank",
          "Hidden iframe detected",
          "high"
        );
        
        addUniqueTactic(mainObject, "iframe_manipulation");
        mainObject.classification.confidence_score += 0.1;
      }
    }
  }

  function detectFullScreenTechniques(doc, mainObject) {
    // Check for iframe attributes indicating fullscreen
    const iframes = Array.from(doc.querySelectorAll('iframe'));
    
    for (const iframe of iframes) {
      // Check for fullscreen attributes
      if ((iframe.style && 
          (iframe.style.width === '100%' || iframe.style.width === '100vw' || 
           iframe.style.height === '100%' || iframe.style.height === '100vh' ||
           iframe.style.position === 'absolute' || iframe.style.position === 'fixed')) ||
          (iframe.getAttribute('style') && 
          (iframe.getAttribute('style').includes('100vw') || 
           iframe.getAttribute('style').includes('100vh') ||
           iframe.getAttribute('style').includes('position: absolute') || 
           iframe.getAttribute('style').includes('position:absolute')))) {
        
        addIOC(
          mainObject,
          "fullscreen_technique",
          "fullscreen_iframe",
          "Iframe with fullscreen attributes detected (common in phishing pages that overlay legitimate sites)",
          "high"
        );
        
        addUniqueTactic(mainObject, "fullscreen_takeover");
        addClassificationNote(mainObject, "Full-screen iframe detected (may be attempting to overlay a legitimate site)");
        
        mainObject.classification.confidence_score += 0.1;
      }
    }
    
    // Check for CSS indicating fullscreen behavior
    const styles = Array.from(doc.querySelectorAll('style'));
    let fullscreenCSS = false;
    
    for (const style of styles) {
      const cssText = style.textContent.toLowerCase();
      if ((cssText.includes('100vh') || cssText.includes('100vw') || cssText.includes('width: 100%') || 
           cssText.includes('height: 100%')) && 
          (cssText.includes('position: absolute') || cssText.includes('position:absolute') || 
           cssText.includes('position: fixed') || cssText.includes('position:fixed'))) {
        
        fullscreenCSS = true;
      }
    }
    
    if (fullscreenCSS) {
      addIOC(
        mainObject,
        "fullscreen_technique",
        "fullscreen_css",
        "CSS for full-screen elements detected (common in phishing pages)",
        "high"
      );
      
      addUniqueTactic(mainObject, "fullscreen_takeover");
      addClassificationNote(mainObject, "Full-screen CSS detected");
      
      mainObject.classification.confidence_score += 0.1;
    }
    
    // Check for overflow:hidden (prevents scrolling - common in phishing)
    if (doc.documentElement.innerHTML.toLowerCase().includes('overflow: hidden') || 
        doc.documentElement.innerHTML.toLowerCase().includes('overflow:hidden')) {
      
      addIOC(
        mainObject,
        "anti_escape",
        "overflow_hidden",
        "Page prevents scrolling with overflow:hidden (common in phishing)",
        "medium"
      );
    }
  }

  function detectCredentialForms(doc, mainObject) {
    const forms = Array.from(doc.querySelectorAll('form'));
    const passwordFields = Array.from(doc.querySelectorAll('input[type="password"]'));
    
    if (passwordFields.length > 0) {
      addUniqueTactic(mainObject, "credential_form_detected");
      
      addIOC(
        mainObject,
        "credential_form",
        `password_fields_count: ${passwordFields.length}`,
        `Credential form with ${passwordFields.length} password field(s)`,
        "high"
      );
      
      mainObject.classification.confidence_score += 0.2;
    }
    
    // Check form submission methods
    for (const form of forms) {
      const action = form.getAttribute('action');
      if (action && (action.includes('login') || action.includes('signin') || action.includes('auth'))) {
        addIOC(
          mainObject,
          "credential_form",
          `form_action: ${action}`,
          "Form submission to authentication endpoint",
          "high"
        );
      }
    }
  }

  function detectBase64Obfuscation(doc, mainObject) {
    const scripts = Array.from(doc.querySelectorAll('script'));
    const scriptTexts = scripts.map(script => script.innerHTML).join('\n');
    
    // Look for base64 decode operations
    const base64Patterns = [
      /atob\s*\(/i,
      /base64_decode/i,
      /btoa\s*\(/i,
      /base64_encode/i,
      /[A-Za-z0-9+/]{40,}={0,2}/  // Long base64 string pattern
    ];
    
    for (const pattern of base64Patterns) {
      if (pattern.test(scriptTexts)) {
        addUniqueTactic(mainObject, "obfuscation");
        
        addIOC(
          mainObject,
          "base64_obfuscation",
          "Base64 encoding/decoding detected",
          "Code uses base64 encoding/decoding, common in obfuscated phishing",
          "high"
        );
        
        mainObject.classification.confidence_score += 0.1;
        break;
      }
    }
  }

  function detectAntiAnalysis(doc, mainObject) {
    const html = doc.documentElement.innerHTML.toLowerCase();
    const script = Array.from(doc.querySelectorAll('script'))
      .map(s => s.innerHTML)
      .join('\n')
      .toLowerCase();

    const antiAnalysisPatterns = [
      { pattern: /oncontextmenu\s*=\s*['"]return false['"]|event\.button\s*==\s*2|contextmenu/i, 
        description: "Disables right-click" },
        
      { pattern: /addEventListener\(\s*['"]contextmenu['"]|\.contextmenu/i, 
        description: "Blocks context menu/right-click" },
        
      { pattern: /ctrlKey|metaKey|preventDefault\(\)/i, 
        description: "Intercepts keyboard shortcuts" },
        
      { pattern: /document\.designMode\s*=\s*['"]off['"]/i, 
        description: "Disables edit mode" },
        
      { pattern: /copy|cut|paste|select|selectstart/i, 
        description: "Blocks copy/paste operations" },
        
      { pattern: /keyCode\s*(===|==)\s*(85|83|73|123|118)/i, 
        description: "Blocks inspection shortcuts" },
        
      { pattern: /debugger|console\.(clear|disable)/i, 
        description: "Anti-debugging techniques" },
        
      { pattern: /user-select\s*:\s*none/i, 
        description: "Prevents text selection" },
        
      { pattern: /document\.onkeydown/i, 
        description: "Keyboard event interception" },
        
      { pattern: /document\.on(copy|cut|paste)/i, 
        description: "Clipboard operation blocking" }
    ];

    for (const pattern of antiAnalysisPatterns) {
      if (pattern.pattern.test(html) || pattern.pattern.test(script)) {
        addIOC(
          mainObject,
          "anti_analysis",
          pattern.description,
          `Anti-analysis technique: ${pattern.description}`,
          "medium"
        );
        
        addUniqueTactic(mainObject, "anti_analysis");
        
        // Small increase in confidence - these are common on phishing pages
        mainObject.classification.confidence_score += 0.05;
      }
    }
    
    // Check for heavily obfuscated code
    const obfuscationPatterns = [
      /eval\(function\(p,a,c,k,e,/i,  // Common packer pattern
      /String\.fromCharCode\((?:\d+,){10,}/i, // Character code obfuscation
      /\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i, // Hex encoding
      /\['\\x|\\x'\]/i, // Hex array notation
      /atob\s*\(/i  // Base64 decoding
    ];
    
    for (const pattern of obfuscationPatterns) {
      if (pattern.test(script)) {
        addIOC(
          mainObject,
          "code_obfuscation",
          "obfuscated_javascript",
          "Heavily obfuscated JavaScript detected",
          "high"
        );
        
        addUniqueTactic(mainObject, "code_obfuscation");
        mainObject.classification.confidence_score += 0.1;
        break;
      }
    }

    // Check for anti-bot/crawler measures
    if (script.includes('navigator.userAgent') || 
        script.includes('navigator.webdriver') || 
        script.includes('document.referrer')) {
      
      addIOC(
        mainObject,
        "anti_analysis",
        "anti_crawler_check",
        "Anti-crawler/bot detection techniques",
        "medium"
      );
    }
    
    // Create metadata entry for anti-analysis techniques
    if (mainObject.tactics.includes('anti_analysis')) {
      const techniques = mainObject.iocs
        .filter(ioc => ioc.type === 'anti_analysis')
        .map(ioc => ioc.value);
        
      if (!mainObject.metadata.anti_analysis_techniques) {
        mainObject.metadata.anti_analysis_techniques = techniques;
      }
    }
  }

  function detectSuspiciousDomains(doc, mainObject) {
    // Get the current domain
    const currentDomain = mainObject.domain ? mainObject.domain.toLowerCase() : "";
    if (!currentDomain) return;
    
    // Skip if not a valid domain
    if (!currentDomain.includes('.')) return;
    
    // Check for common suspicious patterns
    const suspiciousPatterns = [
      { pattern: /login|signin|account|secure|verify|security|auth/, confidence: 0.3, 
        description: "Contains authentication-related terms" },
        
      { pattern: /-(?:secure|login|signin|update|verify|confirm)/, confidence: 0.4, 
        description: "Uses authentication terms with hyphens" },
        
      { pattern: /\d{5,}/, confidence: 0.3, 
        description: "Contains long numeric sequence" },
        
      { pattern: /[a-zA-Z0-9]{20,}/, confidence: 0.4, 
        description: "Excessively long subdomain" },
        
      { pattern: /-+[a-zA-Z0-9]{1,4}-+/, confidence: 0.3, 
        description: "Contains short hyphenated sections" },
        
      { pattern: /(?:online|web|net|cloud|my|e)-/, confidence: 0.2, 
        description: "Common prefix pattern in phishing" },
        
      { pattern: /secure[0-9]*|security[0-9]*|login[0-9]*/, confidence: 0.4, 
        description: "Security term with numeric suffix" }
    ];
    
    // Domain parts
    const parts = currentDomain.split('.');
    const subdomain = parts.length > 2 ? parts.slice(0, -2).join('.') : "";
    const domain = parts.length > 1 ? parts[parts.length - 2] : "";
    const tld = parts.length > 1 ? parts[parts.length - 1] : "";
    
    // Check uncommon TLDs (often used in phishing)
    const commonTLDs = ['com', 'org', 'net', 'edu', 'gov', 'co.uk', 'ca', 'de', 'jp', 'fr', 'au', 'us', 'ru', 'ch', 'it', 'nl', 'se', 'no', 'es', 'mil'];
    if (!commonTLDs.includes(tld)) {
      addIOC(
        mainObject,
        "suspicious_domain",
        `uncommon_tld: ${tld}`,
        `Domain uses uncommon TLD: .${tld}`,
        "medium"
      );
      mainObject.classification.confidence_score += 0.05;
    }
    
    // Check for suspicious patterns in the domain or subdomain
    let matchingPatterns = [];
    for (const { pattern, confidence, description } of suspiciousPatterns) {
      if (pattern.test(subdomain) || pattern.test(domain)) {
        matchingPatterns.push(description);
        mainObject.classification.confidence_score += confidence;
      }
    }
    
    // If any patterns matched, add as IOC
    if (matchingPatterns.length > 0) {
      addUniqueTactic(mainObject, "suspicious_domain");
      
      addIOC(
        mainObject,
        "suspicious_domain",
        currentDomain,
        `Domain matches suspicious patterns: ${matchingPatterns.join(", ")}`,
        "medium"
      );
      
      addClassificationNote(mainObject, `Suspicious domain patterns detected: ${matchingPatterns.join(", ")}`);
    }
  }

  function detectDomainTyposquatting(doc, mainObject) {
    // Common target domains that are frequently typosquatted
    const targetDomains = [
      { name: 'google', domain: 'google.com' },
      { name: 'facebook', domain: 'facebook.com' },
      { name: 'microsoft', domain: 'microsoft.com' },
      { name: 'apple', domain: 'apple.com' },
      { name: 'amazon', domain: 'amazon.com' },
      { name: 'paypal', domain: 'paypal.com' },
      { name: 'netflix', domain: 'netflix.com' },
      { name: 'steam', domain: 'steamcommunity.com' },
      { name: 'steam', domain: 'steampowered.com' },
      { name: 'origin', domain: 'origin.com' },
      { name: 'epic', domain: 'epicgames.com' }
    ];
    
    const currentDomain = mainObject.domain ? mainObject.domain.toLowerCase() : "";
    
    // Skip if domain is empty
    if (!currentDomain) return;
    
    // Check for typosquatting using Levenshtein distance
    for (const target of targetDomains) {
      // Skip exact matches
      if (currentDomain === target.domain) {
        continue;
      }
      
      // Check if domain contains the target name
      if (currentDomain.includes(target.name)) {
        // Calculate Levenshtein distance
        const distance = levenshteinDistance(currentDomain, target.domain);
        const similarity = 1 - (distance / Math.max(currentDomain.length, target.domain.length));
        
        // If domains are similar but not identical
        if (similarity > 0.7 && similarity < 1) {
          addUniqueTactic(mainObject, "typosquatting");
          
          addIOC(
            mainObject,
            "typosquatted_domain",
            `${currentDomain} (typosquatting ${target.domain})`,
            `Domain typosquatting detected: ${currentDomain} similar to ${target.domain} (${(similarity * 100).toFixed(1)}% similar)`,
            "high"
          );
          
          addClassificationNote(mainObject, `Typosquatted domain targeting ${target.name}`);
          
          // Increase severity - typosquatting is a strong phishing indicator
          mainObject.classification.confidence_score += 0.15;
          break;
        }
      }
    }
    
    // Helper function to calculate Levenshtein distance
    function levenshteinDistance(a, b) {
      if (a.length === 0) return b.length;
      if (b.length === 0) return a.length;
      
      const matrix = Array(a.length + 1).fill().map(() => Array(b.length + 1).fill(0));
      
      for (let i = 0; i <= a.length; i++) {
        matrix[i][0] = i;
      }
      
      for (let j = 0; j <= b.length; j++) {
        matrix[0][j] = j;
      }
      
      for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
          const cost = a[i - 1] === b[j - 1] ? 0 : 1;
          matrix[i][j] = Math.min(
            matrix[i - 1][j] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j - 1] + cost
          );
        }
      }
      
      return matrix[a.length][b.length];
    }
  }

  function analyzeResourceDomains(doc, mainObject) {
    // Skip if no resource domains
    if (!mainObject.metadata.resource_domains || 
        !Array.isArray(mainObject.metadata.resource_domains) || 
        mainObject.metadata.resource_domains.length === 0) {
      return;
    }
    
    // Get top brands from the domain names
    const domainBrandMap = {
      'googleapis.com': 'google', 
      'gstatic.com': 'google',
      'googleusercontent.com': 'google',
      'google.com': 'google',
      'microsoft.com': 'microsoft',
      'microsoftonline.com': 'microsoft',
      'office.com': 'microsoft',
      'office365.com': 'microsoft',
      'live.com': 'microsoft',
      'windows.net': 'microsoft',
      'facebook.com': 'facebook',
      'fbcdn.net': 'facebook',
      'instagram.com': 'facebook',
      'apple.com': 'apple',
      'icloud.com': 'apple',
      'amazon.com': 'amazon',
      'amazonaws.com': 'amazon',
      'paypal.com': 'paypal',
      'dropbox.com': 'dropbox',
      'adobe.com': 'adobe',
      'adobelogin.com': 'adobe',
      'steamcommunity.com': 'steam',
      'steampowered.com': 'steam',
      'cloudflare.steamstatic.com': 'steam',
      'epicgames.com': 'epic games',
      'att.com': 'att',
      'hover.com': 'hover'
    };
    
    const detectedResourceBrands = new Set();
    
    // Check each resource domain for brand indicators
    for (const resource of mainObject.metadata.resource_domains) {
      const domain = resource.domain;
      
      // Check for direct brand matches
      for (const [brandDomain, brandName] of Object.entries(domainBrandMap)) {
        if (domain.endsWith(brandDomain)) {
          detectedResourceBrands.add(brandName);
        }
      }
    }
    
    // Add detected brands to IOCs
    detectedResourceBrands.forEach(brand => {
      addIOC(
        mainObject,
        "resource_brand",
        brand,
        `Resources from ${brand} detected`,
        "medium"
      );
      
      // Only add to classification notes if not already detected
      if (!mainObject.detected_brands.includes(brand)) {
        addClassificationNote(mainObject, `Resources reference ${brand}`);
      }
    });
  }

  function detectAPIExfiltration(doc, mainObject) {
    const html = doc.documentElement.innerHTML.toLowerCase();
    const script = Array.from(doc.querySelectorAll('script'))
      .map(s => s.innerHTML)
      .join('\n');
    
    // Extract Telegram bot tokens
    const telegramTokenPattern = /bot([0-9]{8,10}:[A-Za-z0-9_-]{35})/g;
    const telegramTokens = new Set();
    let match;
    
    while ((match = telegramTokenPattern.exec(script)) !== null) {
      telegramTokens.add(match[1]);
    }
    
    // Also look for explicitly defined tokens
    const tokenPattern = /token\d*\s*=\s*['"]([0-9]{8,10}:[A-Za-z0-9_-]{35})['"]/g;
    while ((match = tokenPattern.exec(script)) !== null) {
      telegramTokens.add(match[1]);
    }
    
    // Add extracted tokens as IOCs
    telegramTokens.forEach(token => {
      addIOC(
        mainObject,
        "api_token",
        token,
        "Telegram bot token for exfiltration",
        "high"
      );
      
      // Add to exfil endpoints
      mainObject.network_behavior.exfil_endpoints.push({
        url: `https://api.telegram.org/bot${token}/`,
        method: "POST",
        type: "telegram_bot"
      });
    });
    
    // Add this section to extract Telegram chat IDs
    const chatIdPatterns = [
      /chat_id\s*=\s*['"](-?\d{7,15})['"]/g,  // chat_id="123456789"
      /chat_id\s*[:=]\s*(-?\d{7,15})[,}]/g,    // chat_id:123456789, or chat_id=123456789}
      /chat_id=(-?\d{7,15})/g,                 // URL parameter: chat_id=123456789
      /chatId\s*[:=]\s*['"]?(-?\d{7,15})['"]?/g,  // chatId:"123456789" or chatId=123456789
      /(?:chat_id|chat-id)\d*\s*=\s*['"]?(-?\d{7,15})['"]?/g  // NEW: Handles variable declarations
    ];
    
    const chatIds = new Set();
    
    // Check each pattern
    for (const pattern of chatIdPatterns) {
      let chatMatch;
      while ((chatMatch = pattern.exec(script)) !== null) {
        chatIds.add(chatMatch[1]);
      }
      
      // Also check HTML content (for URL parameters in links/forms)
      while ((chatMatch = pattern.exec(html)) !== null) {
        chatIds.add(chatMatch[1]);
      }
    }
    
    // Add extracted chat IDs as IOCs
    chatIds.forEach(chatId => {
      addIOC(
        mainObject,
        "telegram_chat_id",
        chatId,
        "Telegram chat ID for exfiltration",
        "high"
      );
      
      // Add to metadata
      if (!mainObject.metadata.telegram_exfil) {
        mainObject.metadata.telegram_exfil = {
          chat_ids: [],
          bot_tokens: Array.from(telegramTokens)
        };
      }
      mainObject.metadata.telegram_exfil.chat_ids.push(chatId);
      
      // Add classification note
      addClassificationNote(mainObject, `Telegram exfiltration to chat ID: ${chatId}`);
    });
    
    // If Telegram exfiltration is detected via any method, increase severity
    if (telegramTokens.size > 0 || chatIds.size > 0) {
      addUniqueTactic(mainObject, "telegram_exfiltration");
      mainObject.classification.confidence_score += 0.1;
    }
  }

  function detectURLShorteners(doc, mainObject) {
    const links = Array.from(doc.querySelectorAll('a[href]'));
    
    const shortenerDomains = [
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'buff.ly',
      'rebrand.ly', 'ow.ly', 'tiny.cc', 'bl.ink', 'cutt.ly', 'shorturl.at',
      'rb.gy', 's2r.co'
    ];
    
    for (const link of links) {
      const href = link.getAttribute('href');
      if (!href) continue;
      
      try {
        const url = new URL(href, document.baseURI);
        const domain = url.hostname.toLowerCase();
        
        // Check if it's a known URL shortener
        for (const shortener of shortenerDomains) {
          if (domain === shortener || domain.endsWith('.' + shortener)) {
            addUniqueTactic(mainObject, "url_obfuscation");
            
            addIOC(
              mainObject,
              "url_shortener",
              domain,
              `URL shortener detected: ${domain}`,
              "medium"
            );
            
            addClassificationNote(mainObject, `Uses URL shortener: ${domain}`);
            mainObject.classification.confidence_score += 0.05;
            break;
          }
        }
        
        // Check for suspicious short URLs
        if (url.pathname.length <= 8 && url.pathname.length > 1 && 
            !url.pathname.includes('.') && !url.pathname.includes('/')) {
          
          // Check if the URL path consists only of letters and numbers
          const alphanumericPath = /^\/[a-zA-Z0-9]+$/.test(url.pathname);
          
          if (alphanumericPath) {
            addIOC(
              mainObject,
              "potentially_shortened_url",
              href,
              "URL with short alphanumeric path may be a shortened URL",
              "low"
            );
          }
        }
      } catch (e) {
        // Invalid URL, skip
      }
    }
  }

  function detect2FAPhishing(doc, mainObject) {
    const html = doc.documentElement.innerHTML.toLowerCase();
    const text = doc.body ? doc.body.innerText.toLowerCase() : "";
    
    // 2FA related keywords
    const twoFactorTerms = [
      'two-factor', 'two factor', '2fa', 'second factor', 'verification code',
      'security code', 'one-time', 'one time', 'otp', '2-step', 'two-step',
      'authenticator', 'sms code', 'email code'
    ];
    
    // Patterns for verification code inputs
    const codePatterns = [
      /input[^>]*placeholder=['"][^'"]*\d[^'"]*['"][^>]*input/i, // Input with placeholder showing digits
      /input[^>]*maxlength=['"]?\d{1,2}['"]?/i, // Input with maxlength for codes
      /\b\d{4,8}\b/g, // 4-8 digit codes in text
      /\b\d{3}[- ]?\d{3}\b/g // 3-3 digit codes with optional separator
    ];
    
    let twoFactorEvidence = false;
    let matchedTerms = new Set();
    
    // Check for 2FA terminology
    for (const term of twoFactorTerms) {
      if (html.includes(term) || text.includes(term)) {
        twoFactorEvidence = true;
        matchedTerms.add(term);
      }
    }
    
    // Check for verification code patterns
    for (const pattern of codePatterns) {
      if (pattern.test(html)) {
        twoFactorEvidence = true;
        matchedTerms.add("verification code pattern");
      }
    }
    
    if (twoFactorEvidence) {
      addUniqueTactic(mainObject, "2fa_phishing");
      
      addIOC(
        mainObject,
        "2fa_phishing",
        Array.from(matchedTerms).join(", "),
        "Two-factor authentication phishing indicators detected",
        "high"
      );
      
      addClassificationNote(mainObject, "Two-factor authentication phishing attempt detected");
      mainObject.classification.confidence_score += 0.2;
    }
  }

  function detectDecentralizedHosting(doc, mainObject) {
    const url = document.location.href.toLowerCase();
    const html = doc.documentElement.innerHTML.toLowerCase();
    
    // Patterns for decentralized hosting platforms
    const ipfsPatterns = [
      { pattern: /ipfs\.io\/ipfs/i, platform: "IPFS" },
      { pattern: /ipfs\.fleek\.co/i, platform: "IPFS (Fleek)" },
      { pattern: /gateway\.pinata\.cloud/i, platform: "IPFS (Pinata)" },
      { pattern: /cloudflare-ipfs\.com/i, platform: "IPFS (Cloudflare)" },
      { pattern: /ipfs\.dweb\.link/i, platform: "IPFS (dweb.link)" },
      { pattern: /\w3s\.link/i, platform: "Web3.Storage" },
      { pattern: /bafy[a-zA-Z0-9]{44}/i, platform: "IPFS CID" },
      { pattern: /bafybei[a-zA-Z0-9]{52}/i, platform: "IPFS CIDv1" }
    ];
    
    // Check URL and content for IPFS indicators
    for (const pattern of ipfsPatterns) {
      if (pattern.pattern.test(url) || pattern.pattern.test(html)) {
        addIOC(
          mainObject,
          "decentralized_hosting",
          pattern.platform,
          `Decentralized hosting platform: ${pattern.platform}`,
          "high"
        );
        
        addUniqueTactic(mainObject, "decentralized_hosting");
        addClassificationNote(mainObject, `Using ${pattern.platform} decentralized hosting (resistant to takedowns)`);
        mainObject.classification.confidence_score += 0.1;
        
        // Log to both IOCs and metadata
        if (!mainObject.metadata.hosting) {
          mainObject.metadata.hosting = {
            type: "decentralized",
            platform: pattern.platform
          };
        }
        
        break;
      }
    }
  }

  function detectGamingPhishing(doc, mainObject) {
    const html = doc.documentElement.innerHTML.toLowerCase();
    const text = doc.body ? doc.body.innerText.toLowerCase() : "";
    const title = doc.title ? doc.title.toLowerCase() : "";
    const metaDesc = doc.querySelector('meta[name="description"]')?.content?.toLowerCase() || 
                    doc.querySelector('meta[property="og:description"]')?.content?.toLowerCase() || '';
    
    // Gaming-related keywords
    const gamingTerms = [
      'gift card', 'wallet code', 'redeem', 'inventory',
      'steam', 'epic games', 'fortnite', 'vbucks', 'robux', 'roblox',
      'minecraft', 'riot', 'league of legends', 'valorant',
      'activation', 'keys', 'dlc', 'drops', 'rare item'
    ];
    
    // Terms that can have multiple contexts (e.g., skins in CSS vs gaming)
    const ambiguousTerms = [
      { term: 'skin', cssPattern: /\.skin|skin\.|skin\{|#skin|skin\.css|skin:/i },
      { term: 'skins', cssPattern: /\.skins|skins\.|skins\{|#skins|skins\.css|skins:/i },
      { term: 'item', cssPattern: /\.item|item\.|item\{|#item|menu-item|list-item/i }
    ];
    
    // Check for ambiguous terms in a non-CSS context
    const nonCssAmbiguousTerms = [];
    for (const { term, cssPattern } of ambiguousTerms) {
      // Get all occurrences of the term
      let index = html.indexOf(term);
      let foundNonCssContext = false;
      
      while (index !== -1) {
        // Get context (20 chars before and after)
        const start = Math.max(0, index - 20);
        const end = Math.min(html.length, index + term.length + 20);
        const context = html.substring(start, end);
        
        // If the term appears in a non-CSS context, add to detected terms
        if (!cssPattern.test(context)) {
          foundNonCssContext = true;
          break;
        }
        
        index = html.indexOf(term, index + 1);
      }
      
      if (foundNonCssContext) {
        nonCssAmbiguousTerms.push(term);
      }
    }
    
    // Check for gaming terms in title and meta first (strong evidence)
    let strongEvidence = gamingTerms.some(term => title.includes(term)) || 
                        gamingTerms.some(term => metaDesc.includes(term));
    
    // Count definitive detected terms
    const detectedTerms = gamingTerms.filter(term => 
      html.includes(term) || text.includes(term)
    );
    
    // Add any ambiguous terms found in non-CSS contexts
    const allDetectedTerms = [...detectedTerms, ...nonCssAmbiguousTerms];
    
    if (strongEvidence || allDetectedTerms.length >= 2) {
      addUniqueTactic(mainObject, "gaming_phishing");
      
      addIOC(
        mainObject,
        "gaming_phishing",
        allDetectedTerms.join(", "),
        `Gaming-related phishing targeting: ${allDetectedTerms.join(", ")}`,
        "high"
      );
      
      addClassificationNote(mainObject, `Gaming phishing detected with ${allDetectedTerms.length} indicators`);
      
      // Increase severity - gaming phishing is often high value
      mainObject.classification.confidence_score += 0.15;
      
      // Check for Steam specifically
      if (title.includes('steam') || metaDesc.includes('steam') || 
          html.includes('steamcommunity') || html.includes('steampowered')) {
        addClassificationNote(mainObject, "Steam-specific phishing campaign detected");
      }
    }
  }

  function detectPlatformAbuse(doc, mainObject) {
    const currentURL = document.location.href.toLowerCase();
    
    const abuseablePlatforms = [
      { domain: 'webflow.io', name: 'Webflow' },
      { domain: 'glitch.me', name: 'Glitch' },
      { domain: 'netlify.app', name: 'Netlify' },
      { domain: 'herokuapp.com', name: 'Heroku' },
      { domain: 'github.io', name: 'GitHub Pages' },
      { domain: 'vercel.app', name: 'Vercel' },
      { domain: 'pages.dev', name: 'Cloudflare Pages' },
      { domain: 'repl.co', name: 'Replit' },
      { domain: 'firebaseapp.com', name: 'Firebase' },
      { domain: 'wix.com', name: 'Wix' },
      { domain: 'squarespace.com', name: 'Squarespace' },
      { domain: 'weebly.com', name: 'Weebly' },
      { domain: 'blogspot.com', name: 'Blogger' }
    ];
    
    for (const platform of abuseablePlatforms) {
      if (currentURL.includes(platform.domain)) {
        addUniqueTactic(mainObject, "platform_abuse");
        
        addIOC(
          mainObject,
          "platform_abuse",
          platform.name,
          `Abuse of ${platform.name} platform for phishing`,
          "medium"
        );
        
        addClassificationNote(mainObject, `Hosted on ${platform.name} platform`);
        break;
      }
    }
  }

  function detectCryptoContent(doc, mainObject) {
    const html = doc.documentElement.innerHTML.toLowerCase();
    const text = doc.body ? doc.body.innerText.toLowerCase() : "";
    
    const cryptoTerms = [
      'bitcoin', 'ethereum', 'btc', 'eth', 'wallet', 'blockchain', 
      'cryptocurrency', 'crypto', 'token', 'metamask', 'ledger', 'trezor',
      'binance', 'coinbase', 'web3', 'pancakeswap', 'uniswap'
    ];
    
    let matchCount = 0;
    let matchedTerms = new Set();
    
    for (const term of cryptoTerms) {
      if (html.includes(term) || text.includes(term)) {
        matchCount++;
        matchedTerms.add(term);
      }
    }
    
    if (matchCount >= 2) {
      addUniqueTactic(mainObject, "crypto_phishing");
      
      addIOC(
        mainObject,
        "crypto_content",
        Array.from(matchedTerms).join(", "),
        "Cryptocurrency-related content detected",
        "high"
      );
      
      addClassificationNote(mainObject, "Cryptocurrency-related phishing detected");
      mainObject.classification.confidence_score += 0.15;
    }
  }

  function detectEcommerceSite(doc, mainObject) {
    const html = doc.documentElement.innerHTML.toLowerCase();
    const text = doc.body ? doc.body.innerText.toLowerCase() : "";
    
    // Only proceed if we don't already have stronger phishing indicators
    // or if it's already identified as a known non-ecommerce brand
    const nonEcommerceSpecificBrands = ['microsoft', 'google', 'facebook', 'meta', 'dropbox', 'docusign', 'virtru', 'att'];
    if (mainObject.detected_brands.some(brand => nonEcommerceSpecificBrands.includes(brand)) &&
        mainObject.tactics.includes('credential_form_detected')) {
      // Skip ecommerce detection for already identified brands that aren't typically ecommerce
      return;
    }
    
    const ecommerceTerms = [
      'cart', 'checkout', 'add to cart', 'shopping cart', 'shipping', 
      'payment', 'order', 'product', 'item', 'shop now', 'buy now',
      'price', 'discount', 'sale', 'promotion'
    ];
    
    let matchCount = 0;
    let matchedTerms = new Set();
    
    for (const term of ecommerceTerms) {
      if (html.includes(term) || text.includes(term)) {
        matchCount++;
        matchedTerms.add(term);
      }
    }
    
    if (matchCount >= 3) {
      addUniqueTactic(mainObject, "ecommerce_phishing");
      
      addIOC(
        mainObject,
        "ecommerce_content",
        Array.from(matchedTerms).join(", "),
        "E-commerce related content detected",
        "medium"
      );
      
      addClassificationNote(mainObject, "E-commerce phishing detected");
      mainObject.classification.confidence_score += 0.1;
    }
  }

  function detectSuspiciousLinks(doc, mainObject) {
    const links = Array.from(doc.querySelectorAll('a[href]'));
    
    for (const link of links) {
      const href = link.getAttribute('href');
      
      // Skip empty or anchor links
      if (!href || href.startsWith('#')) continue;
      
      // Check for suspicious link text vs URL
      const linkText = link.textContent.trim().toLowerCase();
      try {
        const url = new URL(href, document.baseURI);
        
        // Check for links that say they go to one place but actually go elsewhere
        if (linkText.includes('facebook') && !url.hostname.includes('facebook')) {
          addIOC(
            mainObject,
            "deceptive_link",
            `text: ${linkText}, url: ${url.hostname}`,
            "Link text mentions Facebook but points elsewhere",
            "high"
          );
          
          addUniqueTactic(mainObject, "deceptive_links");
          mainObject.classification.confidence_score += 0.1;
        }
        
        // Same for other major brands
        const brandMismatches = [
          { brand: 'google', domain: 'google.com' },
          { brand: 'microsoft', domain: 'microsoft.com' },
          { brand: 'apple', domain: 'apple.com' },
          { brand: 'amazon', domain: 'amazon.com' },
          { brand: 'paypal', domain: 'paypal.com' }
        ];
        
        for (const { brand, domain } of brandMismatches) {
          if (linkText.includes(brand) && !url.hostname.includes(domain)) {
            addIOC(
              mainObject,
              "deceptive_link",
              `text: ${linkText}, url: ${url.hostname}`,
              `Link text mentions ${brand} but points elsewhere`,
              "high"
            );
            
            addUniqueTactic(mainObject, "deceptive_links");
            mainObject.classification.confidence_score += 0.1;
            break;
          }
        }
      } catch (e) {
        // Invalid URL
      }
    }
  }

  function detectTechSupportScam(doc, mainObject) {
    const html = doc.documentElement.innerHTML.toLowerCase();
    const text = doc.body ? doc.body.innerText.toLowerCase() : "";
    
    // Phone number patterns (without using lookbehinds)
    const phonePatterns = [
      /\b(?:\+\d{1,3}[-\s]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b/g, // US/Canada: (123) 456-7890
      /\b(?:\+\d{1,3}[-\s]?)?\d{4}[-\s]?\d{3}[-\s]?\d{3}\b/g,        // Some European: 1234 567 890
      /\b(?:\+\d{1,3}[-\s]?)?\d{2}[-\s]?\d{4}[-\s]?\d{4}\b/g,        // Some Asian: 12 3456 7890
      /\b\d{5}[-\s]?\d{6}\b/g                                       // Other formats: 12345 123456
    ];
    
    // Support-related phrases
    const supportPhrases = [
      'call', 'support', 'contact', 'technician', 'toll free', 'helpline',
      'help desk', 'customer service', 'technical support', 'toll-free',
      'windows support', 'microsoft support', 'apple support', 'google support',
      'call now', 'call immediately', 'gebührenfrei', 'anrufen', 'support anrufen'
    ];
    
    // Security alert phrases
    const alertPhrases = [
      'security alert', 'warning', 'infected', 'virus', 'malware', 'trojan',
      'spyware', 'threat', 'detected', 'compromised', 'at risk', 'blocked',
      'suspended', 'error code', 'critical error', 'windows defender',
      'firewall', 'security center', 'sicherheitswarnung', 'fehler', 'bedrohung' 
    ];
    
    // Function to validate potential phone numbers and filter out false positives
    function isLikelyPhoneNumber(match, context) {
      // Check if it appears in a URL parameter context first
      if (/[?&=][0-9]+/.test(context)) return false;
      
      // Clean up the number for analysis
      const cleaned = match.replace(/\D/g, '');
      
      // Reject if too long or too short
      if (cleaned.length < 7 || cleaned.length > 15) return false;
      
      // Check if it's likely a timestamp or version number
      if (/^\d{10,}$/.test(cleaned)) return false;
      
      // Check for support context (strong indicator for tech support scam)
      for (const phrase of supportPhrases) {
        if (context.includes(phrase) && context.includes(match)) {
          return true;
        }
      }
      
      return true;
    }
    
    // Detect phone numbers - use match() rather than exec() for better browser compatibility
    let foundPhoneNumbers = new Set();
    const contextSize = 50; // Characters before/after for context checking
    
    for (const pattern of phonePatterns) {
      const matches = html.match(pattern);
      if (!matches) continue;
      
      for (const match of matches) {
        const index = html.indexOf(match);
        if (index === -1) continue;
        
        // Get context around the match
        const start = Math.max(0, index - contextSize);
        const end = Math.min(html.length, index + match.length + contextSize);
        const context = html.substring(start, end);
        
        // Validate it's likely a real phone number
        if (isLikelyPhoneNumber(match, context)) {
          foundPhoneNumbers.add(match);
        }
      }
    }
    
    const hasAudioElement = doc.querySelectorAll('audio[autoplay], audio[src*="alert"], audio[src*="warn"], audio[src*="error"]').length > 0;
    const cursorManipulation = html.includes('cursor:none') || html.includes('cursor: none');
    const fullscreenAPI = html.includes('requestfullscreen') || 
                         html.includes('webkitrequestfullscreen') ||
                         html.includes('mozrequestfullscreen');
    const personalDataCollection = html.includes('ipwho.is') || 
                                 html.includes('ip-api.com') ||
                                 html.includes('geolocation');
    
    // Count support phrases
    const supportPhraseCount = supportPhrases.filter(phrase => html.includes(phrase)).length;
    
    // Count alert phrases  
    const alertPhraseCount = alertPhrases.filter(phrase => html.includes(phrase)).length;
    
    // Determine if this is likely a tech support scam
    const isTechSupportScam = (
      foundPhoneNumbers.size > 0 && 
      (supportPhraseCount >= 2 || alertPhraseCount >= 3 || hasAudioElement)
    );
    
    if (isTechSupportScam) {
      addUniqueTactic(mainObject, "tech_support_scam");
      
      // Add classification note
      addClassificationNote(mainObject, `Technical support scam detected with ${foundPhoneNumbers.size} phone numbers`);
      
      // Increase severity - tech support scams are high risk
      mainObject.classification.confidence_score = Math.max(mainObject.classification.confidence_score, 0.8);
      
      // Add phone numbers as IOCs
      foundPhoneNumbers.forEach(phone => {
        addIOC(
          mainObject,
          "scam_phone_number",
          phone,
          `Technical support scam phone number`,
          "high"
        );
      });
      
      // Add other indicators
      if (hasAudioElement) {
        addIOC(
          mainObject,
          "tech_support_scam",
          "audio_alert",
          "Audio alert used to create urgency (common in tech support scams)",
          "high"
        );
      }
      
      if (cursorManipulation) {
        addIOC(
          mainObject, 
          "tech_support_scam",
          "cursor_manipulation",
          "Cursor manipulation detected (hiding cursor to prevent escape)",
          "high"
        );
      }
      
      if (fullscreenAPI) {
        addIOC(
          mainObject,
          "tech_support_scam",
          "forced_fullscreen",
          "Forced fullscreen mode to prevent escape",
          "high"
        );
      }
      
      if (personalDataCollection) {
        addIOC(
          mainObject,
          "tech_support_scam",
          "personal_data_collection",
          "Collection of IP address or geolocation data",
          "high"
        );
      }
      
      // Create metadata for the scam
      mainObject.metadata.tech_support_scam = {
        phone_numbers: Array.from(foundPhoneNumbers),
        alert_phrases_found: alertPhraseCount,
        support_phrases_found: supportPhraseCount,
        has_audio_alert: hasAudioElement,
        cursor_manipulation: cursorManipulation,
        forced_fullscreen: fullscreenAPI,
        personal_data_collection: personalDataCollection
      };
    }
  }

  function collectExternalResources(doc, mainObject) {
    const resources = [];
    
    try {
      // Scripts
      Array.from(doc.querySelectorAll('script[src]')).forEach(script => {
        try {
          const url = new URL(script.src, document.baseURI).href;
          resources.push({ type: 'script', url: url });
        } catch (e) {
          // Invalid URL
        }
      });
      
      // Stylesheets
      Array.from(doc.querySelectorAll('link[rel="stylesheet"]')).forEach(link => {
        try {
          const url = new URL(link.href, document.baseURI).href;
          resources.push({ type: 'stylesheet', url: url });
        } catch (e) {
          // Invalid URL
        }
      });
      
      // Images
      Array.from(doc.querySelectorAll('img[src]')).forEach(img => {
        try {
          const url = new URL(img.src, document.baseURI).href;
          resources.push({ type: 'image', url: url });
        } catch (e) {
          // Invalid URL
        }
      });
      
      // Favicon
      const favicon = doc.querySelector('link[rel="icon"], link[rel="shortcut icon"]');
      if (favicon) {
        try {
          const url = new URL(favicon.href, document.baseURI).href;
          resources.push({ type: 'favicon', url: url });
        } catch (e) {
          // Invalid URL
        }
      }
      
      // Whitelist of common CDNs and trusted domains
      const cdnWhitelist = [
        'googleapis.com',
        'gstatic.com',
        'jquery.com',
        'jsdelivr.net',
        'cloudflare.com',
        'bootstrapcdn.com',
        'fontawesome.com',
        'cdn2.editmysite.com'
      ];
      
      // Add each resource to the report
      const pageDomain = document.location.hostname;
      
      resources.forEach((resource) => {
        mainObject.external_resources.push(resource);
        
        try {
          // Extract and track domains
          const resourceUrl = new URL(resource.url);
          const domain = resourceUrl.hostname;
          
          // Check if the domain is external AND not in the whitelist
          const isExternal = domain !== pageDomain;
          const isWhitelisted = cdnWhitelist.some(wlDomain => domain.endsWith(wlDomain));
          
          if (isExternal && !isWhitelisted) {
            addIOC(
              mainObject,
              "suspicious_url",
              resource.url,
              "External resource loaded from non-whitelisted source",
              "medium"
            );
          }
        } catch (e) {
          // Invalid URL
        }
      });
      
      // Track unique domains for reporting
      const domains = {};
      for (const resource of resources) {
        try {
          const url = new URL(resource.url);
          const domain = url.hostname;
          
          if (!domains[domain]) {
            domains[domain] = 0;
          }
          domains[domain]++;
        } catch (e) {
          // Invalid URL
        }
      }
      
      // Add domain statistics to metadata
      mainObject.metadata.resource_domains = Object.entries(domains)
        .map(([domain, count]) => ({ domain, count }))
        .sort((a, b) => b.count - a.count);
        
    } catch (error) {
      console.error("Error in collectExternalResources:", error);
      debugLog("Error collecting external resources: " + error.message);
    }
  }

  // Add this detection function before collectIOCs()

  // Analyzes external scripts for potential exfiltration mechanisms
  function analyzeExternalScripts(document, iocsObject) {
    // Get all external scripts
    const scripts = Array.from(document.querySelectorAll('script[src]'));
    const suspiciousTerms = ["validator", "validate", "form", "login", "submit", "process", "auth"];
    
    // Track suspicious scripts
    let foundSuspiciousScripts = false;
    
    scripts.forEach(script => {
      const src = script.getAttribute('src') || "";
      const fullUrl = new URL(src, document.location).href;
      let isSuspicious = false;
      let reason = [];
      
      // Check if script name contains suspicious terms
      suspiciousTerms.forEach(term => {
        if (src.toLowerCase().includes(term.toLowerCase())) {
          isSuspicious = true;
          reason.push(`contains '${term}'`);
        }
      });
      
      // Check if script is from a different domain
      if (src.startsWith('http') && !(fullUrl.includes(document.location.hostname))) {
        const scriptDomain = new URL(fullUrl).hostname;
        
        // Add to external resources regardless
        iocsObject.external_resources.push({
          type: "script",
          url: fullUrl,
          domain: scriptDomain
        });
        
        // If script looks suspicious, flag it specifically
        if (isSuspicious) {
          foundSuspiciousScripts = true;
          iocsObject.iocs.push({
            type: "suspicious_script",
            value: fullUrl,
            description: `External script likely handling form data (${reason.join(', ')})`,
            severity: "high"
          });
        }
      } else if (isSuspicious) {
        // Local but suspicious script
        foundSuspiciousScripts = true;
        iocsObject.iocs.push({
          type: "suspicious_script", 
          value: src,
          description: `Script likely handling form data (${reason.join(', ')})`,
          severity: "medium"
        });
      }
    });
    
    // Add validator.js specifically as a high-risk indicator if found
    const validatorScripts = scripts.filter(script => {
      const src = script.getAttribute('src') || "";
      return src.includes("validator.js");
    });
    
    if (validatorScripts.length > 0) {
      foundSuspiciousScripts = true;
      const src = validatorScripts[0].getAttribute('src') || "";
      const fullUrl = new URL(src, document.location).href;
      
      iocsObject.iocs.push({
        type: "exfil_script",
        value: fullUrl,
        description: "validator.js script detected - commonly used in phishing kits for credential exfiltration",
        severity: "critical" 
      });
      
      if (!iocsObject.tactics.includes("credential_exfiltration")) {
        iocsObject.tactics.push("credential_exfiltration");
      }
    }
    
    // Add to tactics if suspicious scripts found
    if (foundSuspiciousScripts && !iocsObject.tactics.includes("external_resources")) {
      iocsObject.tactics.push("external_resources");
    }
  }

  function calculateThreatScore(mainObject) {
    let score = mainObject.classification.confidence_score; // Start with base confidence
    let severity = "low";
    
    // Increase score based on tactics
    const tacticWeights = {
      "credential_form_detected": 0.2,
      "brand_impersonation": 0.15,
      "typosquatting": 0.15,
      "telegram_exfiltration": 0.15,
      "2fa_phishing": 0.2,
      "tech_support_scam": 0.3,
      "crypto_phishing": 0.15,
      "gaming_phishing": 0.15,
      "anti_analysis": 0.05,
      "code_obfuscation": 0.1,
      "decentralized_hosting": 0.1,
      "platform_abuse": 0.05,
      "fullscreen_takeover": 0.1,
      "iframe_manipulation": 0.1,
      "suspicious_domain": 0.05,
      "deceptive_links": 0.1,
      "spear_phishing": 0.3,
      "advanced_evasion": 0.2
    };
    
    mainObject.tactics.forEach(tactic => {
      score += tacticWeights[tactic] || 0;
    });
    
    // Increase score based on high severity IOCs
    const highSeverityIOCs = mainObject.iocs.filter(ioc => ioc.severity === 'high').length;
    score += highSeverityIOCs * 0.05;
    
    // Cap score at 1.0
    score = Math.min(score, 1.0);
    
    // Determine severity based on score
    if (score >= 0.8) {
      severity = "critical";
    } else if (score >= 0.6) {
      severity = "high";
    } else if (score >= 0.3) {
      severity = "medium";
    } else {
      severity = "low";
    }
    
    // Update the main object
    mainObject.classification.confidence_score = parseFloat(score.toFixed(2));
    mainObject.classification.severity = severity;
    
    // Add final classification note
    addClassificationNote(mainObject, `Final classification: ${severity} (Score: ${score.toFixed(2)})`);
  }

  // Detects pre-filled credentials indicating spear phishing
  function detectPrefilledCredentials(document, iocsObject) {
    const emailInputs = Array.from(document.querySelectorAll('input[type="email"], input[type="text"]'));
    
    for (const input of emailInputs) {
      const value = input.getAttribute('value');
      if (value && value.includes('@') && value.includes('.')) {
        iocsObject.iocs.push({
          type: "spear_phishing",
          value: `prefilled_email: ${value.replace(/@.*$/, '@[redacted]')}`, // partially redact email
          description: "Pre-filled email detected, indicating targeted spear phishing",
          severity: "critical"
        });
        
        if (!iocsObject.tactics.includes("spear_phishing")) {
          iocsObject.tactics.push("spear_phishing");
        }
        
        iocsObject.classification.notes.push("Spear phishing attack detected with pre-filled credentials");
        break;
      }
    }
  }

  // Detects campaign tracking identifiers and functions
  function detectCampaignTrackers(document, iocsObject) {
    const scripts = Array.from(document.scripts);
    
    for (const script of scripts) {
      const content = script.textContent || "";
      if (content.includes("getcrrid") || content.match(/return\s+['"][a-f0-9]{32}['"]/) || 
          content.includes("campaign") || content.includes("cid=")) {
        
        iocsObject.iocs.push({
          type: "campaign_tracker",
          value: "Campaign ID function detected",
          description: "Page contains unique campaign/tracking identifier function",
          severity: "medium"
        });
        break;
      }
    }
  }

  // Detects techniques used to bypass automated scanning
  function detectAntiScanningTechniques(document, iocsObject) {
    // Check the entire HTML content for Cloudflare challenge indicators
    const html = document.documentElement.outerHTML;
    
    if (html.includes("challenge-platform") || 
        html.includes("__CF$cv$params") || 
        html.includes("cdn-cgi")) {
      
      iocsObject.iocs.push({
        type: "anti_scanning",
        value: "cloudflare_challenge",
        description: "Page uses Cloudflare challenge platform to evade automated scanning",
        severity: "high"
      });
      
      if (!iocsObject.tactics.includes("advanced_evasion")) {
        iocsObject.tactics.push("advanced_evasion");
      }
    }
    
    // Check for script src attributes that might load Cloudflare challenge
    const allScripts = document.querySelectorAll('script[src]');
    for (const script of allScripts) {
      const src = script.getAttribute('src');
      if (src && (src.includes("challenge-platform") || src.includes("cdn-cgi"))) {
        iocsObject.iocs.push({
          type: "anti_scanning",
          value: "external_cloudflare_challenge",
          description: "Page loads external Cloudflare challenge script",
          severity: "high"
        });
        
        if (!iocsObject.tactics.includes("advanced_evasion")) {
          iocsObject.tactics.push("advanced_evasion");
        }
        break;
      }
    }
    
    // Also check for hidden iframes (common anti-scanning technique)
    const hiddenIframes = Array.from(document.querySelectorAll('iframe')).filter(iframe => {
      // Check for various ways iframes can be hidden or minimized
      return iframe.height === "1" || 
             iframe.width === "1" || 
             iframe.style.visibility === "hidden" ||
             iframe.style.display === "none" ||
             iframe.getAttribute("height") === "1" ||
             iframe.getAttribute("width") === "1";
    });
    
    if (hiddenIframes.length > 0) {
      iocsObject.iocs.push({
        type: "anti_scanning",
        value: "hidden_iframe",
        description: "Page uses hidden iframe, commonly used for anti-scanning techniques",
        severity: "medium"
      });
      
      if (!iocsObject.tactics.includes("advanced_evasion")) {
        iocsObject.tactics.push("advanced_evasion");
      }
    }
  }

  // --- Main Collection Function ---
  function collectIOCs() {
    debugLog("Starting IOC collection...");

    // Initialize result object (keep your existing initialization)
    const iocsObject = {
      domain: document.location.hostname,
      url: document.location.href,
      title: document.title,
      timestamp: new Date().toISOString(),
      classification: {
        severity: "",
        confidence_score: 0,
        notes: []
      },
      tactics: [],
      detected_brands: [],
      iocs: [],
      external_resources: [],
      network_behavior: {
        redirects: [],
        exfil_endpoints: []
      },
      metadata: {
        errors: [] // Track any errors that occur
      }
    };

    // Run all detection functions directly with try/catch
    try { detectBrands(document, iocsObject); } catch(e) {
      console.error("Error in detectBrands:", e);
      iocsObject.metadata.errors.push({ function: "detectBrands", error: e.message });
    }

    try { detectSuspiciousIframes(document, iocsObject); } catch(e) {
      console.error("Error in detectSuspiciousIframes:", e);
      iocsObject.metadata.errors.push({ function: "detectSuspiciousIframes", error: e.message });
    }

    try { detectFullScreenTechniques(document, iocsObject); } catch(e) {
      console.error("Error in detectFullScreenTechniques:", e);
      iocsObject.metadata.errors.push({ function: "detectFullScreenTechniques", error: e.message });
    }

    try { detectCredentialForms(document, iocsObject); } catch(e) {
      console.error("Error in detectCredentialForms:", e);
      iocsObject.metadata.errors.push({ function: "detectCredentialForms", error: e.message });
    }

    try { detectBase64Obfuscation(document, iocsObject); } catch(e) {
      console.error("Error in detectBase64Obfuscation:", e);
      iocsObject.metadata.errors.push({ function: "detectBase64Obfuscation", error: e.message });
    }

    try { detectAntiAnalysis(document, iocsObject); } catch(e) {
      console.error("Error in detectAntiAnalysis:", e);
      iocsObject.metadata.errors.push({ function: "detectAntiAnalysis", error: e.message });
    }

    try { detectSuspiciousDomains(document, iocsObject); } catch(e) {
      console.error("Error in detectSuspiciousDomains:", e);
      iocsObject.metadata.errors.push({ function: "detectSuspiciousDomains", error: e.message });
    }

    try { detectDomainTyposquatting(document, iocsObject); } catch(e) {
      console.error("Error in detectDomainTyposquatting:", e);
      iocsObject.metadata.errors.push({ function: "detectDomainTyposquatting", error: e.message });
    }

    // Collect resources before analyzing them
    try { collectExternalResources(document, iocsObject); } catch(e) {
      console.error("Error in collectExternalResources:", e);
      iocsObject.metadata.errors.push({ function: "collectExternalResources", error: e.message });
    }

    // Now analyze resource domains
    try { analyzeResourceDomains(document, iocsObject); } catch(e) {
      console.error("Error in analyzeResourceDomains:", e);
      iocsObject.metadata.errors.push({ function: "analyzeResourceDomains", error: e.message });
    }

    try { detectPlatformAbuse(document, iocsObject); } catch(e) {
      console.error("Error in detectPlatformAbuse:", e);
      iocsObject.metadata.errors.push({ function: "detectPlatformAbuse", error: e.message });
    }

    try { detectCryptoContent(document, iocsObject); } catch(e) {
      console.error("Error in detectCryptoContent:", e);
      iocsObject.metadata.errors.push({ function: "detectCryptoContent", error: e.message });
    }

    try { detectEcommerceSite(document, iocsObject); } catch(e) {
      console.error("Error in detectEcommerceSite:", e);
      iocsObject.metadata.errors.push({ function: "detectEcommerceSite", error: e.message });
    }

    try { detectGamingPhishing(document, iocsObject); } catch(e) {
      console.error("Error in detectGamingPhishing:", e);
      iocsObject.metadata.errors.push({ function: "detectGamingPhishing", error: e.message });
    }

    try { detectSuspiciousLinks(document, iocsObject); } catch(e) {
      console.error("Error in detectSuspiciousLinks:", e);
      iocsObject.metadata.errors.push({ function: "detectSuspiciousLinks", error: e.message });
    }

    try { detectAPIExfiltration(document, iocsObject); } catch(e) {
      console.error("Error in detectAPIExfiltration:", e);
      iocsObject.metadata.errors.push({ function: "detectAPIExfiltration", error: e.message });
    }

    try { detect2FAPhishing(document, iocsObject); } catch(e) {
      console.error("Error in detect2FAPhishing:", e);
      iocsObject.metadata.errors.push({ function: "detect2FAPhishing", error: e.message });
    }

    try { detectURLShorteners(document, iocsObject); } catch(e) {
      console.error("Error in detectURLShorteners:", e);
      iocsObject.metadata.errors.push({ function: "detectURLShorteners", error: e.message });
    }

    try { detectTechSupportScam(document, iocsObject); } catch(e) {
      console.error("Error in detectTechSupportScam:", e);
      iocsObject.metadata.errors.push({ function: "detectTechSupportScam", error: e.message });
    }

    try { detectDecentralizedHosting(document, iocsObject); } catch(e) {
      console.error("Error in detectDecentralizedHosting:", e);
      iocsObject.metadata.errors.push({ function: "detectDecentralizedHosting", error: e.message });
    }

    try { detectPrefilledCredentials(document, iocsObject); } catch(e) {
      console.error("Error in detectPrefilledCredentials:", e);
      iocsObject.metadata.errors.push({ function: "detectPrefilledCredentials", error: e.message });
    }

    try { detectCampaignTrackers(document, iocsObject); } catch(e) {
      console.error("Error in detectCampaignTrackers:", e);
      iocsObject.metadata.errors.push({ function: "detectCampaignTrackers", error: e.message });
    }

    try { detectAntiScanningTechniques(document, iocsObject); } catch(e) {
      console.error("Error in detectAntiScanningTechniques:", e);
      iocsObject.metadata.errors.push({ function: "detectAntiScanningTechniques", error: e.message });
    }

    try { analyzeExternalScripts(document, iocsObject); } catch(e) {
      console.error("Error in analyzeExternalScripts:", e);
      iocsObject.metadata.errors.push({ function: "analyzeExternalScripts", error: e.message });
    }

    // Calculate threat score
    try {
      calculateThreatScore(iocsObject);
    } catch (error) {
      console.error("Error calculating threat score:", error);
      iocsObject.metadata.errors.push({
        function: "calculateThreatScore",
        error: error.message || String(error)
      });
    }

    debugLog("IOC collection complete. Sending results...");
    console.log("Final IOCs Object:", iocsObject); // Log the final object for debugging

    // Send results via chrome.runtime.sendMessage (like in your backup)
    chrome.runtime.sendMessage({ type: "save_iocs", data: iocsObject });

    return iocsObject; // Still return in case it's needed elsewhere
  }

  // --- Event Listener ---
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg === "collect_iocs") {
      // Just call collectIOCs() without sending response
      // The function will send results directly
      collectIOCs();
      debugLog("IOCs collected");
    } else if (msg === "blur_and_capture") {
      document.querySelectorAll('input').forEach(el => el.style.filter = 'blur(8px)');
      setTimeout(() => {
        sendResponse({ status: "blurred" });
        debugLog("Inputs blurred for screenshot.");
      }, 500);
      return true;
    }
  });

  // Log that content script has loaded
  console.log("IOCScout content script loaded");

  // Let the extension know the content script is loaded
  chrome.runtime.sendMessage({ type: "content_script_ready" });

  debugLog("Content script initialized and ready.");
})();
