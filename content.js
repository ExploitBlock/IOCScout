(() => {
  // Debug helper function
  function debugLog(message) {
    console.log("[IOCScout] " + message);
  }

  // Debug helper function that won't affect normal operation
  function setupDebugHelpers() {
    // Only in development mode or when debug flag is set
    const isDebug = new URLSearchParams(window.location.search).has('iocscout_debug');
    
    if (isDebug) {
      window.extractValidatorContent = function() {
        fetch("https://lp.cybeready.net/Forms/MS-online/validator.js")
          .then(response => response.text())
          .then(content => {
            console.log("VALIDATOR.JS FULL CONTENT:");
            console.log(content);
          })
          .catch(err => console.error("Error fetching validator:", err));
      };
      
      console.log("[IOCScout] Debug helpers initialized. Try window.extractValidatorContent()");
    }
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

  // --- DEFINE BRANDS ARRAY HERE ---
  const brands = [
      { 
        name: "meta", 
        patterns: [/meta for business/i, /meta © \d{4}/i, /meta platforms/i, /facebook/i, /fbcdn/i, /meta-facebook/i], // Combined Meta/Facebook
        svgLabels: [/логотип meta/i], 
        severity: "high" 
      },
      { name: "instagram", patterns: [/instagram/i], severity: "high" }, // Keep separate if needed, or merge with Meta
      { name: "microsoft", patterns: [/microsoft/i, /windows live/i, /office 365/i, /outlook\.com/i, /microsoftonline\.com/i], severity: "critical" },
      { name: "google", patterns: [/google/i, /gmail/i, /accounts\.google\.com/i, /docs\.google\.com/i], severity: "critical" },
      { name: "amazon", patterns: [/amazon/i, /awsapps\.com/i, /amazon\.com/i], severity: "critical" },
      { name: "linkedin", patterns: [/linkedin/i], severity: "high" },
      { name: "apple", patterns: [/apple\.com/i, /icloud\.com/i, /iforgot\.apple\.com/i], severity: "critical" },
      { name: "paypal", patterns: [/paypal\.com/i, /paypalobjects\.com/i], severity: "critical" },
      { name: "netflix", patterns: [/netflix\.com/i, /nflxext\.com/i], severity: "high" },
      { name: "dropbox", patterns: [/dropbox\.com/i], severity: "high" },
      { name: "adobe", patterns: [/adobe\.com/i, /adobelogin\.com/i], severity: "high" },
      { name: "docusign", patterns: [/docusign\.com/i, /docusign\.net/i], severity: "high" },
      { 
        name: "fedex", 
        patterns: [/fedex/i], 
        color: "#4D148C", 
        imagePatterns: [/fedex-truck/i, /fedex_logo/i], 
        severity: "high" 
      }
      // Add other brands as needed
  ];
  // --- END BRAND DEFINITION ---

  // --- Helper function for whitelisting (used by multiple detectors) ---
  function isWhitelisted(domain) {
      const domainWhitelist = [
          'googleapis.com', 'google.com', 'gstatic.com', 
          'cloudflare.com', 'cdnjs.cloudflare.com', 
          'jsdelivr.net', 'unpkg.com', 
          'jquery.com', 
          'bootstrapcdn.com', 
          'fontawesome.com', 
          'assets.squarespace.com', 'static1.squarespace.com', // Example: Whitelist Squarespace
          'use.typekit.net', // Example: Whitelist Typekit
          // Add other known safe domains if needed
          document.location.hostname 
      ];
      // Ensure domain is valid before checking endsWith
      if (typeof domain !== 'string' || domain.length === 0) {
          return false;
      }
      return domainWhitelist.some(d => domain.endsWith(d));
  }
  // --- END HELPER ---

  // Modify the detectBrands function
  function detectBrands(document, iocsObject) {
    debugLog("Checking for brand impersonation...");
    const bodyText = document.body.innerText.toLowerCase();
    const titleText = document.title.toLowerCase();
    const imageSources = Array.from(document.querySelectorAll('img')).map(img => (img.src || "").toLowerCase());
    // --- ADD SVG CHECK ---
    const svgLabels = Array.from(document.querySelectorAll('svg[aria-label]')).map(svg => (svg.getAttribute('aria-label') || "").toLowerCase());
    // --- END ADD ---
    const stylesheets = Array.from(document.styleSheets);
    let detectedBrandNames = [];

    brands.forEach(brand => {
      let found = false;
      // Check text patterns (including title)
      if (brand.patterns.some(pattern => pattern.test(bodyText) || pattern.test(titleText) || pattern.test(document.location.href))) {
        found = true;
      }
      // Check image patterns
      if (!found && brand.imagePatterns && imageSources.some(src => brand.imagePatterns.some(pattern => pattern.test(src)))) {
         found = true;
      }
      // --- ADD SVG LABEL CHECK ---
      if (!found && brand.svgLabels && svgLabels.some(label => brand.svgLabels.some(pattern => pattern.test(label)))) {
         found = true;
      }
      // --- END ADD ---
      // Check color patterns
      if (!found && brand.color) {
         // ... (existing color check logic) ...
         const prominentElements = document.querySelectorAll('nav, header, body, .navbar, .header, .bg-primary'); 
         for (let elem of prominentElements) {
            const style = window.getComputedStyle(elem);
            const bgColor = style.backgroundColor;
            if (bgColor) {
                if (bgColor.toUpperCase() === brand.color.toUpperCase()) { 
                    found = true;
                    break;
                }
                if (bgColor === 'rgb(77, 20, 140)') { // Example for FedEx purple
                    found = true;
                    break; 
                }
            }
         }
      }


      if (found) {
        if (!detectedBrandNames.includes(brand.name)) {
           detectedBrandNames.push(brand.name);
           iocsObject.iocs.push({
             type: "brand_impersonation",
             value: brand.name,
             description: `Page impersonates ${brand.name}`,
             severity: brand.severity
           });
           if (!iocsObject.tactics.includes("brand_impersonation")) {
             iocsObject.tactics.push("brand_impersonation");
           }
           debugLog(`Detected brand: ${brand.name}`);
        }
      }
    });
    
    // Update main classification object
    iocsObject.detected_brands = detectedBrandNames;
    if (detectedBrandNames.length > 0) {
        iocsObject.classification.notes.push(`Impersonates: ${detectedBrandNames.join(', ')}`);
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
  }

  // Helper function to calculate Levenshtein distance (Corrected)
  function levenshteinDistance(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    
    const matrix = Array(a.length + 1).fill(null).map(() => Array(b.length + 1).fill(0));
    
    // Initialize first column
    for (let i = 0; i <= a.length; i++) {
      matrix[i][0] = i;
    }
    
    // Initialize first row
    for (let j = 0; j <= b.length; j++) {
      matrix[0][j] = j;
    }
    
    // --- CORRECTED NESTED LOOPS ---
    // Outer loop for 'i' (iterating through string 'a')
    for (let i = 1; i <= a.length; i++) {
      // Inner loop for 'j' (iterating through string 'b')
      for (let j = 1; j <= b.length; j++) { // Line 645 is now the start of the inner loop
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,      // Deletion
          matrix[i][j - 1] + 1,      // Insertion
          matrix[i - 1][j - 1] + cost // Substitution
        );
      } // End inner loop (j)
    } // End outer loop (i)
    // --- END CORRECTION ---
    
    return matrix[a.length][b.length];
  } // End levenshteinDistance function

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

  // Modify the detect2FAPhishing function for better accuracy
  function detect2FAPhishing(document, iocsObject) {
    debugLog("Checking for 2FA phishing indicators...");
    
    let found2FA = false;
    const keywords = [
      "verification code", "security code", "one-time password", "authenticator app", 
      "mfa code", "2fa code", "enter code", "authentication code"
    ];
    // Stricter input field name/id patterns
    const inputPatterns = [
      /otp/i, /code/i, /mfa/i, /verification[_ ]?code/i, /auth[_ ]?code/i, 
      /security[_ ]?code/i, /token/i, /pin/i // Added PIN as it's sometimes used
    ];
    
    // Check input fields for specific names/ids/placeholders
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
      // Use return inside forEach doesn't exit the outer function, so remove 'return' and just set flag
      if (found2FA) return; // Skip further checks if already found

      const name = input.name || "";
      const id = input.id || "";
      const placeholder = input.placeholder || "";
      const type = input.type || ""; // Check type=tel or type=number often used for codes

      // Check if name, id, or placeholder matches specific 2FA patterns
      if (inputPatterns.some(pattern => pattern.test(name) || pattern.test(id) || pattern.test(placeholder))) {
         // Additional check: ensure it's not a common non-2FA field like 'zipcode', 'country_code'
         if (!/zip|country|area|postal|promo|discount|gift|captcha|search/i.test(name + id + placeholder)) {
            found2FA = true;
            debugLog(`Found potential 2FA input: name='${name}', id='${id}', placeholder='${placeholder}'`);
         }
      }
      // Check if type is tel or number and context suggests code
      if (!found2FA && (type === 'tel' || type === 'number') && /code|token|pin|otp|verification/i.test(name + id + placeholder)) {
          found2FA = true;
          debugLog(`Found potential 2FA input (type ${type}): name='${name}', id='${id}', placeholder='${placeholder}'`);
      }
    });

    // If not found via specific inputs, check body text for keywords IN CONTEXT
    // This is less reliable and more prone to false positives, use cautiously
    if (!found2FA) {
        const bodyText = document.body.innerText.toLowerCase();
        // Look for keywords ONLY IF there's also a password field present on the page
        // This reduces false positives on pages that just mention 2FA generally
        const passwordFieldPresent = document.querySelector('input[type="password"]');
        if (passwordFieldPresent && keywords.some(keyword => bodyText.includes(keyword))) {
            // Check if keywords appear near an input field (simple proximity check)
            // Check within the whole body as forms might not be standard <form> elements
            if (keywords.some(keyword => bodyText.includes(keyword))) { // Simplified check: keyword exists + password field exists
                found2FA = true;
                debugLog("Found 2FA keywords in body text, and a password field exists.");
             }
        }
    }

    // Add IOC only if evidence found
    if (found2FA) {
      iocsObject.iocs.push({
        type: "2fa_phishing",
        value: "2FA indicators detected", // Keep value generic
        description: "Two-factor authentication phishing indicators detected (check inputs/context)",
        severity: "high" // Keep high severity as actual 2FA theft is critical
      });
      if (!iocsObject.tactics.includes("2fa_phishing")) {
        iocsObject.tactics.push("2fa_phishing");
      }
      // Add note to classification
       iocsObject.classification.notes.push("Two-factor authentication phishing attempt detected");
    } else {
       debugLog("No specific 2FA phishing indicators found.");
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

  function detectExternalResources(document, iocsObject) {
    debugLog("Checking for external resources...");
    const resources = [];
    const domains = {};
    const suspiciousUrls = [];
    const resourceBrands = []; // Track brands found in resources

    // Whitelist common CDN/API domains (adjust as needed)
    const domainWhitelist = [
      'googleapis.com', 'google.com', 'gstatic.com', // Google
      'cloudflare.com', 'cdnjs.cloudflare.com', // Cloudflare
      'jsdelivr.net', 'unpkg.com', // General CDNs
      'jquery.com', // jQuery CDN
      'bootstrapcdn.com', // Bootstrap CDN
      'fontawesome.com', // FontAwesome
      // Add specific domains if they are consistently safe for your use case
      // 'assets.squarespace.com', 'static1.squarespace.com', // Example: Whitelist Squarespace if needed
      // 'use.typekit.net', // Example: Whitelist Typekit if needed
      document.location.hostname // Always whitelist the current domain
    ];

    // --- REMOVE Microsoft from brand check list ---
    const brandDomainPatterns = {
      // google: [/google/i, /gstatic/i], // Example
      // facebook: [/facebook/i, /fbcdn/i], // Example
      // REMOVE: microsoft: [/microsoft/i, /windows/i, /office/i, /live\.com/i, /microsoftonline/i], 
    };
    // --- END REMOVAL ---


    // Function to check domain against whitelist
    const isWhitelisted = (domain) => domainWhitelist.some(d => domain.endsWith(d));

    // Function to check domain against brand patterns
    const checkBrandDomain = (domain) => {
      for (const brand in brandDomainPatterns) {
        if (brandDomainPatterns[brand].some(pattern => pattern.test(domain))) {
          if (!resourceBrands.includes(brand)) {
            resourceBrands.push(brand);
            iocsObject.iocs.push({
              type: "resource_brand",
              value: brand,
              description: `Resources from ${brand} detected`,
              severity: "medium" // Or adjust severity
            });
          }
          return true; // Found a brand match
        }
      }
      return false; // No brand match
    };


    // Collect scripts, stylesheets, images, iframes, favicons
    const selectors = 'script[src], link[rel="stylesheet"][href], img[src], iframe[src], link[rel*="icon"][href]';
    document.querySelectorAll(selectors).forEach(el => {
      let url;
      let type;
      let domain;

      try {
        if (el.tagName === 'SCRIPT') { type = 'script'; url = el.src; }
        else if (el.tagName === 'LINK' && el.rel.includes('stylesheet')) { type = 'stylesheet'; url = el.href; }
        else if (el.tagName === 'IMG') { type = 'image'; url = el.src; }
        else if (el.tagName === 'IFRAME') { type = 'iframe'; url = el.src; }
        else if (el.tagName === 'LINK' && el.rel.includes('icon')) { type = 'favicon'; url = el.href; }
        else { return; } // Skip if type is unknown

        // Resolve relative URLs and handle protocol-relative URLs
        if (url.startsWith('//')) {
           url = `${window.location.protocol}${url}`;
        }
        const absoluteUrl = new URL(url, document.baseURI).href;
        
        // Skip data URIs for domain analysis but maybe list them?
        if (absoluteUrl.startsWith('data:')) {
            resources.push({ type: type, url: 'data:... (truncated)' });
            return;
        }

        domain = new URL(absoluteUrl).hostname;

        resources.push({ type: type, url: absoluteUrl });

        // Count domains
        domains[domain] = (domains[domain] || 0) + 1;

        // Check if domain is whitelisted or matches a known brand
        if (!isWhitelisted(domain) && !checkBrandDomain(domain)) {
          suspiciousUrls.push(absoluteUrl);
          iocsObject.iocs.push({
            type: "suspicious_url",
            value: absoluteUrl,
            description: "External resource loaded from non-whitelisted source",
            severity: "medium" // Or adjust based on domain reputation later
          });
        }
      } catch (e) {
        console.warn(`[IOCScout] Error processing resource URL: ${url}`, e);
        // Optionally add to metadata errors
        // iocsObject.metadata.errors.push({ function: "detectExternalResources", error: `Invalid resource URL: ${url}` });
      }
    });

    iocsObject.external_resources = resources;
    iocsObject.metadata.resource_domains = Object.entries(domains)
                                              .map(([domain, count]) => ({ domain, count }))
                                              .sort((a, b) => b.count - a.count); // Sort by count

    if (suspiciousUrls.length > 0 && !iocsObject.tactics.includes("external_resources")) {
      iocsObject.tactics.push("external_resources");
    }
  }

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

  // Detects anchor tags used as submit buttons pointing to suspicious URLs
  function detectSuspiciousSubmitLinks(document, iocsObject) {
    // Select potential submit links (adjust selectors as needed)
    const submitLinks = Array.from(document.querySelectorAll('a[id*="submit"], a[class*="submit"], a[id*="signin"], a[class*="signin"], a[onclick*="validate"], a[data-bind*="submit"]'));
    
    submitLinks.forEach(link => {
      const href = link.getAttribute('href');
      if (!href || href === '#' || href.startsWith('javascript:')) {
        return; // Skip irrelevant hrefs
      }
      
      try {
        const linkUrl = new URL(href, document.location.href);
        const linkDomain = linkUrl.hostname;
        const currentDomain = document.location.hostname;
        
        // Define known legitimate domains (add more as needed)
        const legitimateDomains = ['microsoft.com', 'live.com', 'google.com', 'apple.com', currentDomain]; 
        const isLegitimate = legitimateDomains.some(d => linkDomain.endsWith(d));
        
        if (!isLegitimate) {
          iocsObject.iocs.push({
            type: "exfiltration_redirect_url",
            value: linkUrl.href,
            description: `Submit link/button points to suspicious domain: ${linkDomain}`,
            severity: "critical"
          });
          
          // Add exfil endpoint
          iocsObject.network_behavior.exfil_endpoints.push({
            url: linkUrl.href,
            description: `Detected via submit link href pointing to ${linkDomain}`,
            type: "html_link"
          });

          // Add tactic if not present
          if (!iocsObject.tactics.includes("credential_exfiltration")) {
            iocsObject.tactics.push("credential_exfiltration");
          }
           if (!iocsObject.tactics.includes("suspicious_redirection")) {
            iocsObject.tactics.push("suspicious_redirection");
          }
        }
      } catch (e) {
        console.error(`[IOCScout] Error processing submit link href ${href}:`, e);
        iocsObject.metadata.errors.push({ function: "detectSuspiciousSubmitLinks", error: `Invalid link href: ${href}` });
      }
    });
  }

  // Modify the detectThirdPartyApiExfil function
  function detectThirdPartyApiExfil(document, iocsObject) {
    debugLog("Checking for third-party API exfiltration...");
    
    // Get all inline and external scripts
    const scripts = Array.from(document.querySelectorAll('script'));
    const scriptContents = [];
    
    // Get content from inline scripts
    scripts.filter(s => !s.src).forEach(script => {
      scriptContents.push(script.textContent);
    });
    
    // Define patterns for third-party API exfiltration
    const exfilPatterns = [
      // EmailJS patterns
      {
        name: "EmailJS",
        patterns: [
          /emailjs\.send\s*\(/i,
          /api\.emailjs\.com\/api\/v[0-9.]+\/email\/send/i,
          /service_[a-zA-Z0-9]+/i,
          /template_[a-zA-Z0-9]+/i,
          /emailjs\.init\s*\(/i
        ],
        endpoint: "https://api.emailjs.com/api/v1.0/email/send",
        severity: "critical"
      },
      // Formspree patterns
      {
        name: "Formspree",
        patterns: [
          /formspree\.io/i
        ],
        endpoint: "https://formspree.io",
        severity: "critical"
      },
      // Web3Forms patterns
      {
        name: "Web3Forms",
        patterns: [
          /web3forms\.com\/api/i,
          /forms\.web3forms\.com/i
        ],
        endpoint: "https://api.web3forms.com/submit",
        severity: "critical"
      },
      // FormSubmit patterns
      {
        name: "FormSubmit",
        patterns: [
          /formsubmit\.co/i
        ],
        endpoint: "https://formsubmit.co",
        severity: "critical"
      },
      // Zapier Webhook patterns
      {
        name: "Zapier Webhooks",
        patterns: [
          /hooks\.zapier\.com/i
        ],
        endpoint: "https://hooks.zapier.com",
        severity: "critical"
      }
    ];
    
    // --- ADD IP Lookup Patterns ---
    const ipLookupPatterns = [
        /api\.db-ip\.com/i,
        /ipinfo\.io/i,
        /ip-api\.com/i,
        /ipapi\.co/i,
        /ipgeolocation\.io/i
    ];
    let ipLookupDetected = false;
    // --- END ADD ---

    // Check each script content against each exfil pattern
    scriptContents.forEach(content => {
      exfilPatterns.forEach(exfilType => {
        const matches = exfilType.patterns.some(pattern => pattern.test(content));
        if (matches) {
          // Add to IOCs
          iocsObject.iocs.push({
            type: "third_party_api_exfiltration",
            value: exfilType.name,
            description: `${exfilType.name} API detected - commonly abused for credential exfiltration`,
            severity: exfilType.severity
          });
          
          // Add to exfil endpoints
          iocsObject.network_behavior.exfil_endpoints.push({
            url: exfilType.endpoint,
            description: `${exfilType.name} API endpoint detected in page scripts`,
            type: "third_party_api"
          });

          // Add to tactics
          if (!iocsObject.tactics.includes("credential_exfiltration")) {
            iocsObject.tactics.push("credential_exfiltration");
          }
          
          // Extract API keys if possible (especially for EmailJS)
          if (exfilType.name === "EmailJS") {
            // Extract service IDs (no change needed)
            const serviceIdMatch = /service_[a-zA-Z0-9]+/i.exec(content);
            if (serviceIdMatch) {
              iocsObject.iocs.push({
                type: "api_key",
                value: serviceIdMatch[0],
                description: `EmailJS service ID found in page scripts`,
                severity: "medium"
              });
            }
            
            // --- MODIFIED User ID Regex ---
            // Look for assignment or a likely key pattern within quotes, avoiding common JS words
            const userIdMatch = /userId\s*=\s*["']([a-zA-Z0-9_-]{15,30})["']/i.exec(content) || 
                                /(?<![a-zA-Z])["']([a-zA-Z0-9_-]{20,30})["'](?!=[a-zA-Z])/i.exec(content); // More specific pattern in quotes
            // --- END MODIFICATION ---
            
            if (userIdMatch && userIdMatch[1] && !/function|document|window|return|const|var|let|this/i.test(userIdMatch[1])) { // Add keyword check
              iocsObject.iocs.push({
                type: "api_key",
                value: userIdMatch[1], // Use captured group 1
                description: `EmailJS user ID/API key found in page scripts`,
                severity: "medium"
              });
            }
            
            // Extract template IDs (no change needed)
            const templateIdMatch = /template_[a-zA-Z0-9]+/i.exec(content);
            if (templateIdMatch) {
              iocsObject.iocs.push({
                type: "api_key",
                value: templateIdMatch[0],
                description: `EmailJS template ID found in page scripts`,
                severity: "medium"
              });
            }
          }
        }
      });

      // --- ADD IP Lookup Check ---
      ipLookupPatterns.forEach(pattern => {
          if (pattern.test(content)) {
              ipLookupDetected = true;
              const domainMatch = pattern.exec(content);
              iocsObject.iocs.push({
                  type: "info_gathering",
                  value: domainMatch ? domainMatch[0] : "IP Lookup Service",
                  description: "Script attempts to fetch user IP/geolocation.",
                  severity: "medium"
              });
              // Add tactic if not present
              if (!iocsObject.tactics.includes("information_gathering")) {
                  iocsObject.tactics.push("information_gathering");
              }
          }
      });
      // --- END ADD ---
    });
    
    // Additionally look for these patterns in external script URLs
    scripts.filter(s => s.src).forEach(script => {
      const src = script.src.toLowerCase();
      
      // Fixed ternary operator with proper default value
      const serviceName = 
        src.includes('emailjs') ? 'EmailJS' :
        src.includes('formspree') ? 'Formspree' :
        src.includes('web3forms') ? 'Web3Forms' : null;
      
      // Fixed conditional block structure
      if (serviceName) {
        console.log(`Service detected: ${serviceName}`);
        
        iocsObject.iocs.push({
          type: "suspicious_script_source",
          value: script.src,
          description: `Script loaded from ${serviceName} - commonly used for credential exfiltration`,
          severity: "high"
        });
        
        if (!iocsObject.tactics.includes("credential_exfiltration")) {
          iocsObject.tactics.push("credential_exfiltration");
        }
      }
    });
  }

  // Add this new function definition before collectIOCs()
  function detectSocialEngineeringLinks(document, iocsObject) {
    debugLog("Checking for social engineering links (WhatsApp, Telegram)...");
    let foundLink = false;

    const links = document.querySelectorAll('a[href]');

    links.forEach(link => {
      const href = link.href || "";

      // Check for WhatsApp links (wa.me)
      if (href.startsWith("https://wa.me/")) {
        foundLink = true;
        const phoneNumber = href.split('/')[3]?.split('?')[0] || "unknown";
        iocsObject.iocs.push({
          type: "social_engineering_link",
          value: `WhatsApp: ${phoneNumber}`,
          description: "Link directs users to WhatsApp, potentially for scams or phishing.",
          severity: "high"
        });
        debugLog(`Found WhatsApp link: ${href}`);
      }
      
      // Check for Telegram links (t.me)
      else if (href.startsWith("https://t.me/")) {
         foundLink = true;
         const usernameOrGroup = href.split('/')[3]?.split('?')[0] || "unknown";
         iocsObject.iocs.push({
           type: "social_engineering_link",
           value: `Telegram: ${usernameOrGroup}`,
           description: "Link directs users to Telegram, potentially for scams or phishing.",
           severity: "high"
         });
         debugLog(`Found Telegram link: ${href}`);
      }
      
      // Add checks for other platforms if needed (e.g., Discord invite links)
      // else if (href.includes("discord.gg/") || href.includes("discord.com/invite/")) { ... }

    });

    if (foundLink) {
      if (!iocsObject.tactics.includes("social_engineering")) {
        iocsObject.tactics.push("social_engineering");
      }
      iocsObject.classification.notes.push("Contains direct social engineering contact links (e.g., WhatsApp, Telegram).");
    }
  }

  // --- Modify detectSuspiciousKeywords ---
  function detectSuspiciousKeywords(document, iocsObject) {
    debugLog("Checking for suspicious keywords...");
    const keywordsConfig = [
      // Keep login/credential keywords
      { type: "credential_form_keywords", keywords: ["login", "signin", "password", "username", "userid", "credential", "account", "authenticate"], severity: "medium", tactic: "credential_access" },
      // Keep financial keywords
      { type: "financial_keywords", keywords: ["bank", "credit card", "payment", "invoice", "billing", "wire transfer", "account number"], severity: "high", tactic: "financial_theft" },
      // Keep urgency keywords
      { type: "urgency_keywords", keywords: ["urgent", "important", "action required", "verify", "confirm", "suspended", "locked", "unusual activity"], severity: "medium", tactic: "social_engineering" },
      
      // --- REMOVE E-COMMERCE KEYWORDS ---
      // { type: "ecommerce_content", keywords: ["cart", "checkout", "shipping", "payment", "order", "product", "item", "price", "discount", "sale", "promotion"], severity: "medium", tactic: "ecommerce_phishing" },
      
      // Keep gaming keywords (but maybe review later if they cause issues)
      { type: "gaming_phishing", keywords: ["game key", "skin drop", "item trade", "account recovery", "free credits", "virtual currency"], severity: "medium", tactic: "gaming_phishing" },
      // Keep support scam keywords
      { type: "support_scam", keywords: ["support", "helpdesk", "technician", "virus", "malware", "error code", "call now"], severity: "high", tactic: "support_scam" }
    ];

    const bodyText = document.body.innerText.toLowerCase();
    let foundKeywords = {}; // Track found types to avoid duplicates

    keywordsConfig.forEach(config => {
      config.keywords.forEach(keyword => {
        if (bodyText.includes(keyword) && !foundKeywords[config.type]) {
          iocsObject.iocs.push({
            type: config.type,
            value: keyword, // Report the specific keyword found
            description: `Suspicious keyword related to ${config.type.replace(/_/g, ' ')} detected: "${keyword}"`,
            severity: config.severity
          });
          if (config.tactic && !iocsObject.tactics.includes(config.tactic)) {
            iocsObject.tactics.push(config.tactic);
          }
          // Add note to classification
          iocsObject.classification.notes.push(`Contains keywords related to ${config.type.replace(/_/g, ' ')}.`);
          foundKeywords[config.type] = true; // Mark type as found
          debugLog(`Found suspicious keyword type: ${config.type}, keyword: ${keyword}`);
        }
      });
    });
  }

  // --- Modify detectDeceptiveLinks ---
  function detectDeceptiveLinks(document, iocsObject) {
    debugLog("Checking for deceptive links...");
    const links = document.querySelectorAll('a[href]');
    const currentDomain = document.location.hostname;
    let foundDeceptive = false;

    // Keywords/classes often used for primary action buttons
    const actionKeywords = ['login', 'signin', 'daftar', 'register', 'submit', 'continue', 'next', 'download', 'claim', 'verify', 'confirm', 'alternatif link'];
    const actionClasses = ['button', 'btn', 'action', 'submit', 'primary', 'animated-button1']; // Add classes common in phishing kits

    links.forEach(link => {
      const href = link.href;
      const text = link.innerText.toLowerCase();
      let linkDomain = null;
      try {
          // Ensure href is valid before creating URL object
          if (href && (href.startsWith('http') || href.startsWith('//'))) {
             linkDomain = new URL(href, document.baseURI).hostname;
          } else if (href && !href.startsWith('javascript:') && !href.startsWith('mailto:') && !href.startsWith('#')) {
             // Handle relative paths if needed, assume same domain if relative
             linkDomain = currentDomain; 
          }
      } catch (e) {
          console.warn(`[IOCScout] Could not parse link domain for href: ${href}`, e);
      }


      // 1. Link text mismatch (uses global 'brands')
      brands.forEach(brand => {
        // Ensure linkDomain is valid before proceeding
        if (linkDomain && brand.patterns.some(pattern => pattern.test(text)) && !brand.patterns.some(pattern => pattern.test(linkDomain)) && linkDomain !== currentDomain) {
          iocsObject.iocs.push({
            type: "deceptive_link_text",
            value: href,
            description: `Link text "${link.innerText}" suggests ${brand.name}, but points to ${linkDomain}`,
            severity: "high"
          });
          foundDeceptive = true;
        }
      });

      // 2. Generic text links pointing to different domains
      if (!foundDeceptive && /click here|continue|next|download|verify|confirm/i.test(text) && linkDomain && linkDomain !== currentDomain) {
         iocsObject.iocs.push({
            type: "deceptive_link_generic",
            value: href,
            description: `Generic action link "${link.innerText}" points to external domain: ${linkDomain}`,
            severity: "medium"
         });
         foundDeceptive = true;
      }

      // 3. Check for primary action buttons pointing to suspicious external domains
      const isActionButton = actionKeywords.some(kw => text.includes(kw)) || 
                             actionClasses.some(cls => link.classList.contains(cls));
      // Ensure linkDomain is valid before checking whitelist
      const isSuspiciousExternal = linkDomain && linkDomain !== currentDomain && 
                                   !isWhitelisted(linkDomain); 

      if (isActionButton && isSuspiciousExternal) {
          iocsObject.iocs.push({
            type: "suspicious_action_link",
            value: href,
            description: `Primary action button/link "${link.innerText}" points to suspicious external domain: ${linkDomain}`,
            severity: "high" 
          });
          // Also add to exfil endpoints as a potential redirect/exfil stage
          if (!iocsObject.network_behavior.exfil_endpoints.some(ep => ep.url === href)) {
              iocsObject.network_behavior.exfil_endpoints.push({
                  url: href,
                  description: `Suspicious redirect link found in primary action button`,
                  type: "redirect_link"
              });
          }
          foundDeceptive = true; 
          debugLog(`Found suspicious action link: ${href}`);
      }

    });

    if (foundDeceptive && !iocsObject.tactics.includes("deception")) {
      iocsObject.tactics.push("deception");
    }
  }

  // --- ADD calculateThreatScore FUNCTION DEFINITION ---
  function calculateThreatScore(iocsObject) {
    debugLog("Calculating threat score...");
    let score = 0;
    const severityWeights = {
      critical: 5,
      high: 3,
      medium: 2,
      low: 1,
      info: 0 // Or adjust as needed
    };

    // Simple scoring based on IOC severity
    iocsObject.iocs.forEach(ioc => {
      score += severityWeights[ioc.severity] || 0; // Add score based on severity, default to 0 if severity unknown
    });

    // You could add more complex logic here:
    // - Boost score for specific combinations of tactics (e.g., credential_form + exfiltration)
    // - Boost score for critical brands (e.g., banking, government)
    // - Adjust score based on domain reputation (if available)

    // Assign the calculated score
    iocsObject.threat_score = score;

    // Determine a qualitative rating based on score thresholds (adjust thresholds as needed)
    let rating = "Informational";
    if (score >= 15) {
      rating = "Critical";
    } else if (score >= 10) {
      rating = "High";
    } else if (score >= 5) {
      rating = "Medium";
    } else if (score > 0) {
      rating = "Low";
    }
    iocsObject.threat_rating = rating;

    debugLog(`Calculated Threat Score: ${score}, Rating: ${rating}`);
  }
  // --- END FUNCTION DEFINITION ---

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
      },
      threat_score: 0, // Initialize score
      threat_rating: "Informational" // Initialize rating
    };

    // Keep window.iocsObject reference for async access from script analysis
    window.iocsObject = iocsObject;

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
    try { detectExternalResources(document, iocsObject); } catch(e) {
      console.error("Error in detectExternalResources:", e);
      iocsObject.metadata.errors.push({ function: "detectExternalResources", error: e.message });
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
    try { detectSuspiciousSubmitLinks(document, iocsObject); } catch(e) {
      console.error("Error in detectSuspiciousSubmitLinks:", e);
      iocsObject.metadata.errors.push({ function: "detectSuspiciousSubmitLinks", error: e.message });
    }
    try { detectThirdPartyApiExfil(document, iocsObject); } catch(e) {
      console.error("Error in detectThirdPartyApiExfil:", e);
      iocsObject.metadata.errors.push({ function: "detectThirdPartyApiExfil", error: e.message });
    }
    // --- ADD CALL TO NEW DETECTOR ---
    try { detectSocialEngineeringLinks(document, iocsObject); } catch(e) { 
      console.error("Error in detectSocialEngineeringLinks:", e);
      iocsObject.metadata.errors.push({ function: "detectSocialEngineeringLinks", error: e.message });
    }
    // --- END ADD ---
    try { detectSuspiciousKeywords(document, iocsObject); } catch(e) { 
      console.error("Error in detectSuspiciousKeywords:", e);
      iocsObject.metadata.errors.push({ function: "detectSuspiciousKeywords", error: e.message });
    }
    try { detectDeceptiveLinks(document, iocsObject); } catch(e) { 
      console.error("Error in detectDeceptiveLinks:", e);
      iocsObject.metadata.errors.push({ function: "detectDeceptiveLinks", error: e.message });
    }

    // --- REMOVE E-COMMERCE TACTIC IF PRESENT (Optional Cleanup) ---
    // This ensures the tactic isn't added by mistake elsewhere if the IOC is removed
    // const ecommerceIndex = iocsObject.tactics.indexOf("ecommerce_phishing");
    // if (ecommerceIndex > -1 && !iocsObject.iocs.some(ioc => ioc.type === 'ecommerce_content')) {
    //    iocsObject.tactics.splice(ecommerceIndex, 1);
    // }
    
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

    debugLog("IOC collection complete (sync part). Sending results...");
    console.log("IOCs Object (may not include full async script analysis):", iocsObject);

    // Send results via chrome.runtime.sendMessage (like in your backup)
    // This message goes to background.js to be saved
    chrome.runtime.sendMessage({ type: "save_iocs", data: iocsObject });

    // Clean up global reference immediately after sending message
    window.iocsObject = null;

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

  // Call this at the end of your IIFE
  setupDebugHelpers();
})();
