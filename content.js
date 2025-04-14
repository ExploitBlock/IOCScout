(() => {
  // Debug helper function
  function debugLog(message) {
    console.log("[IOCScout Debug] " + message);
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
    'microsoft': ['microsoft', 'office', 'outlook', 'onedrive', 'sharepoint', 'teams'],
    'google': ['google', 'gmail', 'drive'],
    'dropbox': ['dropbox', 'file sharing'],
    'docusign': ['docusign', 'docu sign', 'esign', 'document signing'],
    'adobe': ['adobe', 'pdf', 'acrobat'],
    'paypal': ['paypal', 'payment'],
    'apple': ['apple', 'icloud'],
    'amazon': ['amazon', 'aws'],
    'facebook': ['facebook', 'instagram'],
    'linkedin': ['linkedin'],
    'twitter': ['twitter', 'x.com'],
    'bank': ['bank', 'banking', 'chase', 'wells fargo', 'citibank'],
    'guild': ['guild', 'mortgage', 'loan'],
    'virtru': ['virtru', 'secure reader', 'secure email']
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

  // Modified: Add IOC to the correct 'iocs' array within the main object
  function addIOC(mainObject, type, value, context, confidence = "medium") {
    // Ensure the iocs array exists
    if (!mainObject.iocs) mainObject.iocs = [];

    // Don't add duplicates
    if (mainObject.iocs.some(ioc => ioc.type === type && ioc.value === value)) {
      return false;
    }

    mainObject.iocs.push({
      type: type,
      value: value,
      context: context,
      confidence: confidence
    });

    return true;
  }

  // Modified: Add Tactic to the correct 'tactics' array
  function addUniqueTactic(mainObject, tactic) {
    if (!mainObject.tactics) mainObject.tactics = [];
    if (!mainObject.tactics.includes(tactic)) {
      mainObject.tactics.push(tactic);
      return true;
    }
    return false;
  }

  // Modified: Add Note to the correct 'classification.notes' array
  function addClassificationNote(mainObject, note) {
    if (!mainObject.classification) mainObject.classification = { notes: [] };
    if (!mainObject.classification.notes) mainObject.classification.notes = [];
    if (!mainObject.classification.notes.includes(note)) {
      mainObject.classification.notes.push(note);
    }
  }

  // Modified: Add Resource to the correct 'external_resources' array
  function addExternalResource(mainObject, type, url) {
    if (!mainObject.external_resources) mainObject.external_resources = [];

    // Don't add duplicates
    if (mainObject.external_resources.some(resource => resource.url === url)) {
      return false;
    }

    mainObject.external_resources.push({
      type: type,
      url: url
    });

    return true;
  }

  // --- Detection Functions (detectBrands, detectPhishingKit, etc.) ---
  // These functions remain largely the same but will be called with the main 'iocsObject'

  // Replace the existing detectBrands function

function detectBrands(doc) {
    // Function to normalize text: remove diacritics, common confusables, zero-width spaces
    function normalizeText(text) {
        if (!text) return "";
        // Basic normalization and removal of zero-width spaces and common confusables
        return text.normalize("NFD").replace(/[\u0300-\u036f\u200B-\u200D\uFEFF]/g, "")
                   .toLowerCase()
                   // Replace common visually similar characters (add more as needed)
                   .replace(/і/g, 'i')
                   .replace(/с/g, 'c')
                   .replace(/г/g, 'r')
                   .replace(/о/g, 'o')
                   .replace(/ѕ/g, 's')
                   .replace(/f‏/g, 'f')
                   .replace(/t /g, 't');
    }

    const titleText = normalizeText(doc.title);
    const headingsText = normalizeText(Array.from(doc.querySelectorAll('h1, h2, h3, h4'))
      .map(el => el.innerText)
      .join(' '));
    const visibleText = titleText + ' ' + headingsText;

    const detectedBrands = [];

    for (const [brand, keywords] of Object.entries(knownBrands)) {
      // Check normalized keywords against normalized text
      if (keywords.some(keyword => visibleText.includes(normalizeText(keyword)))) {
        detectedBrands.push(brand);
      }
    }

    return detectedBrands;
}

  function detectPhishingKit(html) {
    for (const [kit, indicators] of Object.entries(phishingKitIndicators)) {
      if (indicators.some(indicator => html.includes(indicator))) {
        return {
          name: kit,
          indicators: indicators.filter(ind => html.includes(ind))
        };
      }
    }
    
    return null;
  }

  // Modified: Pass mainObject to populate correctly
  function detectSuspiciousIframes(doc, mainObject) {
    doc.querySelectorAll('iframe').forEach(iframe => {
      if (iframe.src === 'about:blank' || !iframe.src) {
        addUniqueTactic(mainObject, "suspicious_iframe");
        addIOC(
          mainObject, // Pass the main object
          "suspicious_element",
          "blank_iframe",
          "Empty iframe detected (common in phishing kits)",
          "medium"
        );
        addClassificationNote(mainObject, "Suspicious blank iframe detected");
      }
    });
  }

  // Modified: Pass mainObject to populate correctly
  function detectCredentialForms(doc, mainObject) {
    const passwordFields = doc.querySelectorAll('input[type="password"]');
    const emailFields = doc.querySelectorAll('input[type="email"], input[name*="email"], input[name*="user"]');

    if (passwordFields.length > 0 || emailFields.length > 0) {
      addUniqueTactic(mainObject, "credential_form_detected");

      addIOC(
        mainObject, // Pass the main object
        "credential_harvesting",
        `Found ${passwordFields.length} password fields and ${emailFields.length} email/username fields`,
        "Credential harvesting form detected",
        "high"
      );

      addClassificationNote(mainObject, `Credential harvesting form detected with ${passwordFields.length} password fields`);

      // Check for exfiltration endpoints
      doc.querySelectorAll('form').forEach(form => {
        if (form.action && !form.action.startsWith('javascript:')) {
          // Ensure network_behavior and exfil_endpoints exist
          if (!mainObject.network_behavior) mainObject.network_behavior = { exfil_endpoints: [] };
          if (!mainObject.network_behavior.exfil_endpoints) mainObject.network_behavior.exfil_endpoints = [];

          if (!mainObject.network_behavior.exfil_endpoints.includes(form.action)) {
             mainObject.network_behavior.exfil_endpoints.push(form.action);
          }

          addIOC(
            mainObject, // Pass the main object
            "exfil_endpoint",
            form.action,
            "Form submission endpoint for credential theft",
            "high"
          );
        }
      });
    }
  }

  // Modified: Pass mainObject to populate correctly
  function collectExternalResources(doc, mainObject) {
    doc.querySelectorAll('script[src], link[href], img[src], iframe[src]').forEach(el => {
      const url = el.src || el.href;
      if (!url || url.startsWith('data:') || url === 'about:blank') return;

      // Add to external resources
      addExternalResource(mainObject, el.tagName.toLowerCase(), url); // Pass the main object

      // Skip legitimate domains
      if (isLegitimateDomain(url)) return;

      // Check for suspicious patterns
      if (url.includes('cdn.jsdelivr.net/gh/') ||
          url.includes('unpkg.com/') ||
          url.match(/[a-zA-Z0-9]{30,}/)) {

        addUniqueTactic(mainObject, "suspicious_external_resource"); // Pass the main object

        addIOC(
          mainObject, // Pass the main object
          "suspicious_url",
          url,
          "External resource loaded from potentially suspicious source",
          "medium"
        );
      }
    });
  }

   // Modified: Pass mainObject to populate correctly
  function detectBase64Obfuscation(doc, mainObject) {
    const scripts = Array.from(doc.querySelectorAll('script'));
    const scriptContents = scripts
      .map(s => s.textContent)
      .join(' ');
    const htmlContent = doc.documentElement.innerHTML;
    const combinedContent = scriptContents + ' ' + htmlContent;

    // Improved regex to find more potential Base64 strings
    const base64Regex = /["'`]([A-Za-z0-9+/]{16,}={0,2})["'`]/g;
    const potentialStrings = [];
    let match;

    while ((match = base64Regex.exec(combinedContent)) !== null) {
        potentialStrings.push(match[1]);
    }

    // Also check for standalone base64 strings not in quotes
    const strictBase64Regex = /^[A-Za-z0-9+/]{20,}={0,2}$/;
    const textNodes = document.createTreeWalker(doc.body, NodeFilter.SHOW_TEXT);
    let node;
    while (node = textNodes.nextNode()) {
        const text = node.nodeValue.trim();
        if (strictBase64Regex.test(text)) {
            potentialStrings.push(text);
        }
    }

    // Also check for atob usage
    const usesAtob = /atob\s*\(/i.test(combinedContent);
    let foundObfuscation = usesAtob;
    let decodedUrls = [];

    potentialStrings.forEach(str => {
        try {
            const decoded = atob(str);
            // Basic check if decoded string looks like a URL
            if (decoded.startsWith('http://') || decoded.startsWith('https://')) {
                if (!decodedUrls.includes(decoded)) {
                    decodedUrls.push(decoded);
                }
                foundObfuscation = true; // Mark as obfuscation if a URL is found
            }
        } catch (e) {
            // Not valid Base64 or decoding error, ignore
        }
    });

    if (foundObfuscation) {
      if (!mainObject.obfuscation_signals) mainObject.obfuscation_signals = {};
      mainObject.obfuscation_signals.base64_strings_found = true;
      addUniqueTactic(mainObject, "base64_obfuscation");

      addIOC(
        mainObject,
        "obfuscation_technique",
        "base64_encoding",
        `Uses base64 encoding/decoding.${decodedUrls.length > 0 ? ' Decoded URLs: ' + decodedUrls.join(', ') : ''}`,
        "high"
      );
      addClassificationNote(mainObject, "Base64 obfuscation detected in page code");

      // Add decoded URLs as potential exfil endpoints
      decodedUrls.forEach(url => {
          addIOC(
              mainObject,
              "potential_exfil_endpoint",
              url,
              "URL decoded from Base64 string",
              "high"
          );
          // Also add to network_behavior
          if (!mainObject.network_behavior) mainObject.network_behavior = { exfil_endpoints: [] };
          if (!mainObject.network_behavior.exfil_endpoints) mainObject.network_behavior.exfil_endpoints = [];
          if (!mainObject.network_behavior.exfil_endpoints.includes(url)) {
             mainObject.network_behavior.exfil_endpoints.push(url);
          }
      });

      // Store decoded URLs in metadata
       if (!mainObject.metadata) mainObject.metadata = {};
       mainObject.metadata.base64_decoded_urls = decodedUrls;
    }
}

  // Modified: Calculate score based on data in mainObject
  function calculateThreatScore(mainObject) {
    let score = 0;
    const tactics = mainObject.tactics || [];
    const iocs = mainObject.iocs || [];
    const detectedBrands = mainObject.detected_brands || [];

    // Base score for tactics
    if (tactics.includes("credential_form_detected")) score += 0.2;
    if (tactics.includes("brand_impersonation")) score += 0.1;
    if (detectedBrands.length > 1) score += 0.2; // Multiple brands
    if (tactics.includes("base64_obfuscation")) score += 0.15;
    if (tactics.includes("challenge_page_evasion")) score += 0.1; // Assuming this tactic exists
    if (tactics.includes("suspicious_url_pattern")) score += 0.15; // Assuming this tactic exists
    if (tactics.includes("phishing_kit_detected")) score += 0.2;
    if (tactics.includes("suspicious_iframe")) score += 0.15;
    if (tactics.includes("suspicious_external_resource")) score += 0.1;

    // Count high confidence IOCs
    const highConfidenceCount = iocs.filter(ioc => ioc.confidence === "high").length;
    score += Math.min(highConfidenceCount * 0.1, 0.3);

    // Boost for multiple indicators
    if (tactics.length >= 3) score += 0.1;

    // Set minimum score for pages with detected brands
    if (detectedBrands.length > 0 && score < 0.3) {
      score = 0.3;
    }

    // Cap score at 1.0
    score = Math.min(score, 1.0);

    // Set severity based on score
    const severity = score >= 0.7 ? "high" : score >= 0.4 ? "medium" : "low";

    // Update classification within mainObject
    if (!mainObject.classification) mainObject.classification = {};
    mainObject.classification.severity = severity;
    mainObject.classification.confidence_score = parseFloat(score.toFixed(2)); // Format score

    // Add final classification note
    if (score >= 0.7) {
      addClassificationNote(mainObject, `HIGH RISK: Multiple strong phishing indicators detected (${tactics.length} tactics)`);
    } else if (score >= 0.4) {
      addClassificationNote(mainObject, `MEDIUM RISK: Some phishing indicators detected (${tactics.length} tactics)`);
    } else {
      addClassificationNote(mainObject, `LOW RISK: Few phishing indicators detected (${tactics.length} tactics)`);
    }
  }

// Add this function before collectIOCs

function detectAntiAnalysis(doc, mainObject) {
    const bodyAttributes = doc.body.attributes;
    const htmlContent = doc.documentElement.innerHTML;
    let detected = [];

    // Check for disabled context menu
    if (bodyAttributes.oncontextmenu && bodyAttributes.oncontextmenu.value.includes('return false')) {
        detected.push('disabled_context_menu');
    }

    // Check for F12/DevTools blocking scripts
    if (htmlContent.includes('event.keyCode == 123') || htmlContent.includes('event.key == "F12"')) {
         detected.push('devtools_block');
    }
    
    // Check for navigator.webdriver check
    if (htmlContent.includes('navigator.webdriver')) {
        detected.push('navigator_webdriver_check');
    }

    if (detected.length > 0) {
        addUniqueTactic(mainObject, "anti_analysis");
        if (!mainObject.obfuscation_signals) mainObject.obfuscation_signals = {};
        if (!mainObject.obfuscation_signals.anti_bot_checks) mainObject.obfuscation_signals.anti_bot_checks = [];

        detected.forEach(technique => {
            if (!mainObject.obfuscation_signals.anti_bot_checks.includes(technique)) {
                mainObject.obfuscation_signals.anti_bot_checks.push(technique);
            }
            addIOC(
                mainObject,
                "anti_analysis_technique",
                technique,
                `Detected anti-analysis technique: ${technique.replace(/_/g, ' ')}`,
                "medium"
            );
        });
        addClassificationNote(mainObject, `Anti-analysis techniques detected: ${detected.join(', ')}`);
    }
}

  // --- Main Collection Function ---
  function collectIOCs() {
    debugLog("Starting enhanced IOC collection with new structure");

    // Initialize the main object with the new structure
    const iocsObject = {
      report_id: `iocscout-${Date.now()}`, // Simple unique ID
      scan_timestamp: new Date().toISOString(), // ISO 8601 format timestamp
      url: document.location.href,
      domain: document.location.hostname,
      page_title: document.title,
      classification: { // Initialize classification block
        severity: "low",
        confidence_score: 0,
        notes: []
      },
      detected_brands: [],
      iocs: [],
      tactics: [],
      external_resources: [],
      network_behavior: { // Initialize network_behavior block
        redirects: [],
        exfil_endpoints: []
      },
      obfuscation_signals: { // Initialize obfuscation_signals block
        base64_strings_found: false,
        anti_bot_checks: []
      },
      metadata: {} // Initialize metadata block
    };

    try {
      // --- Run Detection Functions ---
      // Pass the main 'iocsObject' to each function

      // Detect brands
      const detectedBrands = detectBrands(document);
      iocsObject.detected_brands = detectedBrands; // Store detected brands

      // Handle brand detection tactics and notes
      if (detectedBrands.length > 0) {
        if (detectedBrands.length > 1) {
          addUniqueTactic(iocsObject, "multi_brand_abuse");
          addIOC(
            iocsObject,
            "brand_abuse",
            detectedBrands.join(", "),
            `Multiple brand impersonation: ${detectedBrands.join(", ")}`,
            "high"
          );
          addClassificationNote(iocsObject, `Multiple brand abuse detected: ${detectedBrands.join(', ')}`);
        } else {
          addUniqueTactic(iocsObject, "brand_impersonation");
          addIOC(
            iocsObject,
            "brand_abuse",
            detectedBrands[0],
            `Brand impersonation: ${detectedBrands[0]}`,
            "medium"
          );
           addClassificationNote(iocsObject, `Brand impersonation detected: ${detectedBrands[0]}`);
        }
      }

      // Detect phishing kit
      const html = document.documentElement.innerHTML;
      const kitInfo = detectPhishingKit(html);
      if (kitInfo) {
        addUniqueTactic(iocsObject, "phishing_kit_detected");
        addIOC(
          iocsObject,
          "phishing_kit",
          kitInfo.name,
          `Phishing kit framework detected: ${kitInfo.name}`,
          "high"
        );
        iocsObject.metadata.phishing_kit_name = kitInfo.name; // Store kit name in metadata
        addClassificationNote(iocsObject, `Phishing kit detected: ${kitInfo.name}`);
        // Example: Add version if available (adapt based on kitInfo structure)
        // if (kitInfo.version) iocsObject.metadata.phishing_kit_version = kitInfo.version;
      }

      // Detect suspicious iframes
      detectSuspiciousIframes(document, iocsObject);

      // Detect credential forms
      detectCredentialForms(document, iocsObject);

      // Detect Base64
      detectBase64Obfuscation(document, iocsObject);

      // Collect external resources
      collectExternalResources(document, iocsObject);

      // Detect Anti-Analysis techniques
      detectAntiAnalysis(document, iocsObject);

      // --- Final Calculation ---
      calculateThreatScore(iocsObject); // Calculate score based on collected data

      // Add this right after calculateThreatScore(iocsObject) but before sending the message

      // If few indicators were found, schedule a delayed second scan
      const shouldRunDelayedScan = iocsObject.iocs.length < 2 && iocsObject.tactics.length < 2;
      
      // Send immediate results
      debugLog(`Collected ${iocsObject.iocs.length} IOCs and ${iocsObject.tactics.length} tactics`);
      chrome.runtime.sendMessage({
        type: "save_iocs",
        data: iocsObject
      }, response => {
        if (chrome.runtime.lastError) {
          debugLog(`Error sending message: ${chrome.runtime.lastError.message}`);
        } else if (response && response.status === "ok") {
          debugLog("IOCs saved successfully");
        } else {
          debugLog("IOCs sent to background script");
        }
      });
      
      // Run delayed scan if needed
      if (shouldRunDelayedScan) {
        debugLog("Few indicators found, scheduling delayed scan for dynamic content");
        setTimeout(() => {
          const deepScanObject = {
            ...JSON.parse(JSON.stringify(iocsObject)), // Deep clone
            report_id: `iocscout-delayed-${Date.now()}`,
            scan_timestamp: new Date().toISOString(),
            scan_type: "delayed_scan",
            iocs: [],
            tactics: [],
            external_resources: []
          };
          
          debugLog("Running delayed scan for dynamic content");
          
          // Run detection again with the clean object
          const delayedBrands = detectBrands(document);
          deepScanObject.detected_brands = delayedBrands;
          
          // Handle brand detection for delayed scan
          if (delayedBrands.length > 0) {
            if (delayedBrands.length > 1) {
              addUniqueTactic(deepScanObject, "multi_brand_abuse");
              addIOC(
                deepScanObject,
                "brand_abuse",
                delayedBrands.join(", "),
                `Multiple brand impersonation: ${delayedBrands.join(", ")}`,
                "high"
              );
            } else {
              addUniqueTactic(deepScanObject, "brand_impersonation");
              addIOC(
                deepScanObject,
                "brand_abuse",
                delayedBrands[0],
                `Brand impersonation: ${delayedBrands[0]}`,
                "medium"
              );
            }
          }

          // Run other detection functions
          detectSuspiciousIframes(document, deepScanObject);
          detectCredentialForms(document, deepScanObject);
          detectBase64Obfuscation(document, deepScanObject);
          detectAntiAnalysis(document, deepScanObject);
          collectExternalResources(document, deepScanObject);
          
          // Calculate score based on delayed findings
          calculateThreatScore(deepScanObject);
          
          // Send delayed results
          debugLog(`Delayed scan collected ${deepScanObject.iocs.length} IOCs and ${deepScanObject.tactics.length} tactics`);
          chrome.runtime.sendMessage({
            type: "save_iocs",
            data: deepScanObject
          });
        }, 3000); // 3 second delay
      }

      // --- Log and Send ---
      debugLog("IOC collection complete");

    } catch (error) {
      console.error("Error in IOC collection:", error);
      // Send error message with the new structure if needed, or keep simple
      chrome.runtime.sendMessage({
        type: "collection_error",
        error: error.message,
        stack: error.stack // Include stack trace for better debugging
      });
    }
  }

  // --- Event Listener ---
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg === "collect_iocs") {
      collectIOCs();
      // Indicate that the response will be sent asynchronously (important if collectIOCs becomes async)
      // return true;
    } else if (msg === "blur_and_capture") {
      document.querySelectorAll('input').forEach(el => el.style.filter = 'blur(8px)');
      setTimeout(() => {
        sendResponse({ status: "blurred" });
        debugLog("Inputs blurred for screenshot.");
      }, 500);
      return true; // Keep channel open for async response
    }
    // Return false or nothing for synchronous messages
  });

  debugLog("Content script loaded.");
  debugLog("Content script initialized and ready.");
})();
