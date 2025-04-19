chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "save_iocs") {
    chrome.storage.local.get(["iocscout_session"], (result) => {
      const session = result.iocscout_session || [];
      session.push(request.data);
      chrome.storage.local.set({ iocscout_session: session }, () => {
        console.log("[IOCScout] Saved IOCs to chrome.storage");
        sendResponse({ status: "ok" });
      });
    });
    return true; // Indicate async response
  }

  if (request === "capture_screenshot") {
    chrome.tabs.captureVisibleTab(null, { format: "png" }, (dataUrl) => {
      if (chrome.runtime.lastError) { // Add basic error check
          console.error("[IOCScout] Error capturing visible tab:", chrome.runtime.lastError.message);
          sendResponse({ error: chrome.runtime.lastError.message }); 
          return;
      }
      sendResponse({ screenshot: dataUrl });
    });
    return true; // Indicate async response
  }
});

console.log("[IOCScout] Background script loaded (Backup Version).");
