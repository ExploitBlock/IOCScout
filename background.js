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
    return true;
  }

  if (request === "capture_screenshot") {
    chrome.tabs.captureVisibleTab(null, { format: "png" }, (dataUrl) => {
      sendResponse({ screenshot: dataUrl });
    });
    return true;
  }
});
