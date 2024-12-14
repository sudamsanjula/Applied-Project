// Listen for tab updates (URL changes) to analyze each updated URL
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    console.log("Updated URL:", changeInfo.url); // Debug: Log the updated URL
    analyzeURL(changeInfo.url);
  }
});

// Analyze URL, skip if whitelisted, and notify if reported
async function analyzeURL(url) {
  if (!url || !url.startsWith("http")) {
    console.log("Invalid or unsupported URL:", url); // Debug: Notify invalid URL
    return;
  }

  // Retrieve both the whitelist and reportedSites from storage
  const { whitelist = [], reportedSites = [] } = await chrome.storage.local.get(["whitelist", "reportedSites"]);

  // Check if URL is whitelisted
  if (whitelist.includes(url)) {
    console.log("URL is whitelisted and will be skipped:", url); // Debug: Log whitelisted URL
    return;
  }

  // Check if URL is reported
  if (reportedSites.includes(url)) {
    console.log("URL is reported as suspicious:", url); // Debug: Log reported URL
    chrome.action.setBadgeText({ text: "⚠️" });

    // Display a notification that the URL has been previously reported
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon.png",
      title: "Previously Reported Site",
      message: "This site was previously reported as suspicious by the user."
    });
    return;
  }

  // Proceed with other checks if the URL is not whitelisted or reported
  const isHTTP = url.startsWith("http:");
  const suspiciousKeywords = /login|verify|secure/i.test(url);

  let notificationMessage = ""; // Initialize an empty message

  if (isHTTP) {
    notificationMessage += "This site is not using HTTPS. "; // Message for HTTP detection
  }

  if (suspiciousKeywords) {
    notificationMessage += "Suspicious keywords found in the URL. ";
  }

  // If there are issues with the URL, show a notification
  if (notificationMessage) {
    console.log("Flagged URL:", url); // Debug: Log flagged URL
    chrome.action.setBadgeText({ text: "⚠️" });

    // Display a notification with the custom message
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon.png",
      title: "Suspicious Site Detected",
      message: notificationMessage
    });
  } else {
    console.log("Safe URL:", url); // Debug: Log safe URL
    chrome.action.setBadgeText({ text: "" });
  }
}

// Listen for messages from popup script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "reportSite") {
    storeReportedSite(request.url);
    sendResponse({ status: "Site reported successfully!" });
  } else if (request.action === "removeReportedSite") {
    removeReportedSite(request.url, sendResponse);
    return true; // Required to keep sendResponse callback open for async
  }
});

// Store reported sites in the blacklist
function storeReportedSite(url) {
  chrome.storage.local.get({ reportedSites: [] }, (data) => {
    const reportedSites = data.reportedSites || [];
    if (!reportedSites.includes(url)) {
      reportedSites.push(url);
      chrome.storage.local.set({ reportedSites: reportedSites }, () => {
        console.log("Site stored in reportedSites (blacklist):", url);
      });
    } else {
      console.log("URL is already in reportedSites:", url);
    }
  });
}

// Remove a site from the reported list (blacklist)
function removeReportedSite(url, sendResponse) {
  chrome.storage.local.get({ reportedSites: [] }, (data) => {
    let reportedSites = data.reportedSites || [];
    if (reportedSites.includes(url)) {
      reportedSites = reportedSites.filter((site) => site !== url);
      chrome.storage.local.set({ reportedSites: reportedSites }, () => {
        console.log("Site removed from reportedSites:", url); // Debug: Confirm removal
        sendResponse({ status: "Site removed from reported list." });
      });
    } else {
      console.log("Site not found in reportedSites:", url); // Debug: Site not in list
      sendResponse({ status: "Site not found in reported list." });
    }
  });
}

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "detectedTechnologies" && sender.tab) {
    const url = new URL(sender.tab.url).hostname;
    const technologies = request.technologies;

    // Store the detected technologies in local storage
    chrome.storage.local.set({ [url]: { technologies, timestamp: Date.now() } }, () => {
      console.log(`Technologies detected on ${url}:`, technologies);
      
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon.png",
        title: "Technology Stack Detected",
        message: `Technologies on ${url}: ${technologies.join(", ")}`
      });
    });
  }
});


chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "detectedContactDetails" && sender.tab) {
    const url = new URL(sender.tab.url).hostname;
    const contactDetails = request.contactDetails;

    // Store the contact details in local storage
    chrome.storage.local.set({ [url + "_contacts"]: { contactDetails, timestamp: Date.now() } }, () => {
      console.log(`Contact details detected on ${url}:`, contactDetails);

      if (contactDetails.length > 0) {
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icons/icon.png",
          title: "Contact Details Detected",
          message: `Contact details on ${url}: ${contactDetails.join(", ")}`
        });
      } else {
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icons/icon.png",
          title: "No Contact Details Found",
          message: `No contact details were found on ${url}.`
        });
      }
    });
  }
});

