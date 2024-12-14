// Check page content for phishing phrases
const phishingPhrases = ["Your account has been suspended", "Please verify your information"];

document.addEventListener("DOMContentLoaded", () => {
  const content = document.body.innerText;
  phishingPhrases.forEach(phrase => {
    if (content.includes(phrase)) {
      chrome.runtime.sendMessage({action: "suspiciousContent", message: `Phishing phrase detected: ${phrase}`});
    }
  });
});

// Function to detect technologies on the current page
// Function to detect technologies and versions on the current page
function detectTechnologies() {
  const technologies = [];

  // Check for WordPress (meta tag with version)
  const wpMeta = document.querySelector('meta[name="generator"][content*="WordPress"]');
  if (wpMeta) {
    const wpVersion = wpMeta.getAttribute("content").match(/WordPress\s([\d.]+)/i);
    technologies.push(wpVersion ? `WordPress ${wpVersion[1]}` : "WordPress");
  } else if (document.body.innerHTML.includes("wp-content")) {
    technologies.push("WordPress");
  }

  // Check for Shopify
  if (document.querySelector('[id^="shopify-section"]') || document.body.innerHTML.includes("cdn.shopify.com")) {
    technologies.push("Shopify");
  }

  // Check for Google Analytics
  if (document.querySelector('script[src*="googletagmanager.com/gtag/js"]') || document.body.innerHTML.includes("GoogleAnalyticsObject")) {
    technologies.push("Google Analytics");
  }

  // Check for jQuery (global variable with version)
  if (window.jQuery) {
    technologies.push(`jQuery ${window.jQuery.fn.jquery}`);
  } else if (typeof $ === 'function') {
    technologies.push("jQuery (unknown version)");
  }

  // Check for React (global variable or version in file name)
  if (window.React) {
    technologies.push("React");
  } else if (document.body.innerHTML.includes("react-dom")) {
    const reactVersion = document.querySelector('script[src*="react-dom"]')?.src.match(/react-dom@([\d.]+)/);
    technologies.push(reactVersion ? `React ${reactVersion[1]}` : "React");
  }

  // Check for Angular (global variable or AngularJS version)
  if (window.angular) {
    const angularVersion = window.angular.version ? window.angular.version.full : "unknown version";
    technologies.push(`Angular ${angularVersion}`);
  } else if (document.querySelector('[ng-app]')) {
    technologies.push("Angular");
  }

  // Check for Bootstrap (look for version in CSS file URL)
  const bootstrapLink = document.querySelector('link[href*="bootstrap.min.css"]');
  if (bootstrapLink) {
    const bootstrapVersion = bootstrapLink.href.match(/bootstrap(?:\.min)?\.css\?v=([\d.]+)/);
    technologies.push(bootstrapVersion ? `Bootstrap ${bootstrapVersion[1]}` : "Bootstrap");
  } else if (document.querySelector('.container, .btn, .navbar')) {
    technologies.push("Bootstrap");
  }

  // Check for Vue.js
  if (window.Vue) {
    technologies.push("Vue.js");
  } else if (document.querySelector('[data-v-app]')) {
    technologies.push("Vue.js");
  }

  // Check for YouTube Embed
  if (document.querySelector('iframe[src*="youtube.com/embed"]') || document.body.innerHTML.includes("www.youtube.com")) {
    technologies.push("YouTube Embed");
  }

  // Send detected technologies and versions to the background script
  chrome.runtime.sendMessage({ action: "detectedTechnologies", technologies: technologies });
}

// Run the detection function
detectTechnologies();

// Function to detect contact details on the current page
function detectContactDetails() {
  const contactDetails = [];

  // Debugging: Log start of contact detection
  console.log("Starting contact details detection...");

  // Regular expression to find email addresses
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const bodyText = document.body.innerText; // Use innerText to avoid HTML tags

  // Find email addresses
  const emails = bodyText.match(emailRegex);
  if (emails) {
    console.log("Emails found:", emails); // Debugging: Log found emails
    contactDetails.push(...new Set(emails)); // Add unique emails
  } else {
    console.log("No emails found."); // Debugging: Log if no emails found
  }

  // Search for "mailto" links directly in anchor tags
  const mailtoLinks = Array.from(document.querySelectorAll('a[href^="mailto:"]')).map(link => link.href);
  if (mailtoLinks.length > 0) {
    console.log("Mailto links found:", mailtoLinks); // Debugging: Log mailto links
    contactDetails.push(...mailtoLinks);
  } else {
    console.log("No mailto links found."); // Debugging: Log if no mailto links found
  }

  // Search for links that might lead to a contact page
  const contactLinks = Array.from(document.querySelectorAll('a')).filter(link => {
    const href = link.getAttribute('href') || '';
    const text = link.innerText.toLowerCase();
    return href.includes('contact') || text.includes('contact');
  });

  if (contactLinks.length > 0) {
    console.log("Contact links found:", contactLinks.map(link => link.href)); // Debugging: Log contact links
    contactDetails.push(...contactLinks.map(link => link.href));
  } else {
    console.log("No contact links found."); // Debugging: Log if no contact links found
  }

  // Send the detected contact details to the background script
  chrome.runtime.sendMessage({ action: "detectedContactDetails", contactDetails: contactDetails });
}

// Run the detection function
detectContactDetails();
