document.getElementById("scan").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const blurEnabled = document.getElementById("blurToggle").checked;

  if (blurEnabled) {
    try {
      await chrome.tabs.sendMessage(tab.id, "blur_and_capture"); 
      console.log("[IOCScout] Blur requested.");
    } catch (error) {
      console.error("[IOCScout] Error sending blur message:", error);
    }
  }

  // Send message to background to capture screenshot
  chrome.runtime.sendMessage({ action: "capture_screenshot" }, (screenshotData) => {
    if (chrome.runtime.lastError) {
        console.error("[IOCScout] Error receiving screenshot data:", chrome.runtime.lastError.message);
        return;
    }
    if (!screenshotData) {
        console.warn("[IOCScout] No screenshot data received from background.");
        return;
    }

    console.log("[IOCScout] Screenshot data received in popup.");

    // Get session, add screenshot blob, save session
    chrome.storage.local.get(["iocscout_session"], (result) => {
      if (chrome.runtime.lastError) {
          console.error("[IOCScout] Error getting session storage for screenshot:", chrome.runtime.lastError.message);
          return;
      }
      
      const session = result.iocscout_session || [];
      if (session.length > 0) {
        const latestIndex = session.length - 1; 
        const timestamp = Date.now();
        const screenshotFile = `screenshot_${timestamp}.png`;
        
        if (session[latestIndex]) {
            session[latestIndex].screenshot_file = screenshotFile;
            session[latestIndex].screenshot_blob = screenshotData; 
            
            chrome.storage.local.set({ iocscout_session: session }, () => {
                if (chrome.runtime.lastError) {
                    console.error("[IOCScout] Error saving session with screenshot:", chrome.runtime.lastError.message);
                } else {
                    console.log("[IOCScout] Screenshot attached to session and saved.");
                }
            });
        } else {
             console.error("[IOCScout] Latest session entry not found when trying to save screenshot.");
        }
      } else {
         debugLog("[IOCScout Debug] No session found yet for screenshot attachment (expected timing)."); 
      }
    });
  });

  // Trigger content script scan (ensure this happens after setting up screenshot handling or in parallel)
  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    files: ['content.js']
  }).then(() => {
    console.log("[IOCScout] Injected content script.");
  }).catch(err => console.error("[IOCScout] Failed to inject content script:", err));
});

// Finish button listener (Backup code + safety check)
document.getElementById("finish").addEventListener("click", () => {
  chrome.storage.local.get(["iocscout_session"], (result) => {
    if (chrome.runtime.lastError) {
        console.error("[IOCScout] Error getting session for export:", chrome.runtime.lastError.message);
        alert("Error retrieving scan results for export.");
        return;
    }
    
    const session = result.iocscout_session || [];

    if (!Array.isArray(session) || session.length === 0) {
      alert("No IOCs were collected. Try scanning a page first.");
      return;
    }

    const latest = session[session.length - 1];
    const timestamp = Date.now();

    if (!latest) {
        alert("Error: Latest scan data is missing.");
        return;
    }
    
    // *** CRITICAL SAFETY CHECK ***
    if (!latest.screenshot_blob) {
        console.warn("[IOCScout] Screenshot data missing in latest session entry during export. ZIP will not include screenshot.");
    }

    const zip = new JSZip();
    const jsonName = `iocscout_report_${timestamp}.json`;
    const pngName = latest.screenshot_file || `screenshot_${timestamp}.png`; 

    // Prepare clean report (remove base64 image from JSON)
    const cleanedSession = structuredClone(session);
    if (cleanedSession.length > 0 && cleanedSession[cleanedSession.length - 1]) {
        delete cleanedSession[cleanedSession.length - 1].screenshot_blob;
    }

    const jsonString = JSON.stringify(cleanedSession, null, 2);
    zip.file(jsonName, jsonString);

    // Add screenshot to zip ONLY IF IT EXISTS (using the safety check above)
    if (latest.screenshot_blob) {
      try {
        const base64Image = latest.screenshot_blob.replace(/^data:image\/png;base64,/, ""); 
        zip.file(pngName, base64Image, { base64: true });
      } catch (e) {
         console.error("[IOCScout] Error processing screenshot blob for ZIP:", e);
         zip.file("screenshot_error.txt", "Error processing screenshot data for inclusion in ZIP.");
      }
    } else {
       zip.file("screenshot_missing.txt", "Screenshot data was not available or failed to save.");
    }

    zip.generateAsync({ type: "blob" }).then((zipBlob) => {
      const zipName = `iocscout_bundle_${timestamp}.zip`;
      const url = URL.createObjectURL(zipBlob);
      const a = document.createElement("a");
      a.href = url;
      a.download = zipName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url); 

      // Clear storage after successful export
      chrome.storage.local.remove(["iocscout_session"], () => {
         if (chrome.runtime.lastError) {
             console.error("[IOCScout] Error clearing session storage:", chrome.runtime.lastError.message);
         } else {
             console.log("[IOCScout] ZIP report exported successfully and session cleared.");
         }
      });
      
    }).catch(err => {
        console.error("[IOCScout] Error generating ZIP file:", err);
        alert("Error generating ZIP file for export.");
    });
  });
});
