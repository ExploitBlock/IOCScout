document.getElementById("scan").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const blurEnabled = document.getElementById("blurToggle").checked;

  if (blurEnabled) {
    await chrome.tabs.sendMessage(tab.id, "blur_and_capture");
  }

  chrome.tabs.sendMessage(tab.id, "collect_iocs");

  chrome.runtime.sendMessage("capture_screenshot", (response) => {
    if (!response?.screenshot) return;

    // Store screenshot data temporarily
    const screenshotData = response.screenshot;

    chrome.storage.local.get(["iocscout_session"], (result) => {
      const session = result.iocscout_session || [];
      if (session.length > 0) {
        const timestamp = Date.now();
        const screenshotFile = `screenshot_${timestamp}.png`;
        session[session.length - 1].screenshot_file = screenshotFile;
        session[session.length - 1].screenshot_blob = screenshotData;
        chrome.storage.local.set({ iocscout_session: session });
      }
    });
  });
});

document.getElementById("finish").addEventListener("click", () => {
  chrome.storage.local.get(["iocscout_session"], (result) => {
    const session = result.iocscout_session || [];

    if (!Array.isArray(session) || session.length === 0) {
      alert("No IOCs were collected. Try scanning a page first.");
      return;
    }

    const latest = session[session.length - 1];
    const timestamp = Date.now();

    const zip = new JSZip();
    const jsonName = `iocscout_report_${timestamp}.json`;
    const pngName = latest.screenshot_file;

    // Prepare clean report (remove base64 image from JSON)
    const cleanedSession = structuredClone(session);
    delete cleanedSession[cleanedSession.length - 1].screenshot_blob;

    const jsonString = JSON.stringify(cleanedSession, null, 2);
    zip.file(jsonName, jsonString);

    // Add screenshot to zip
    const base64Image = latest.screenshot_blob.replace(/^data:image\/png;base64,/, "");
    zip.file(pngName, base64Image, { base64: true });

    zip.generateAsync({ type: "blob" }).then((zipBlob) => {
      const zipName = `iocscout_bundle_${timestamp}.zip`;
      const url = URL.createObjectURL(zipBlob);
      const a = document.createElement("a");
      a.href = url;
      a.download = zipName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);

      chrome.storage.local.remove(["iocscout_session"]);
      console.log("[IOCScout] ZIP report exported successfully.");
    });
  });
});
