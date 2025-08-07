/**
 * Main Application Entry Point
 *
 * This file handles the UI interactions and coordinates with the
 * verification logic in verification.js
 *
 * Project Structure:
 * ==================
 * - main.js (this file): UI handling, user interactions, display logic
 * - verification.js: Core cryptographic verification logic and DID resolution
 * - style.css: All styling and animations
 *
 * For developers interested in the verification process:
 * ======================================================
 * Please see verification.js for:
 * - Complete list of cryptographic libraries used
 * - Detailed verification flow documentation
 * - DID resolution implementation
 * - Signature verification logic
 *
 * The verification process is completely transparent and uses
 * standard W3C specifications and open-source libraries.
 */

// Import verification logic from separate module
import { verifyCredentialSignature, PROGRESS_STEPS } from "./verification.js";

// Import Vite-managed CSS
import "./style.css";

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Sample credential for demonstration purposes
 * This credential showcases the expected format and can be used for testing
 * @const {Object}
 */
const SAMPLE_CREDENTIAL = {
  issuanceDate: "2025-08-07T17:34:52.054Z",
  credentialSubject: {
    zipCode: "10007",
    ownerPhone: "(617) 495-1000",
    city: "New York",
    latitude: "40.7161708",
    type: ["DPP"],
    ownerEmail: "admin+harvard.ui@realizse.com",
    ownerName: "Harvard University",
    streetAddress: "33 Thomas St",
    name: "33 Thomas St",
    proofOfOwnership: {
      name: "proof-of-ownership-1754588086.pdf",
      type: "application/pdf",
      etag: "d2d9ee7c97e97d3767c735f8b739a03e",
    },
    id: "did:web:api-vera.susi.spherity.dev:did-registry:realizse-asset-passport-e65d6dc3137f3b67",
    state: "NY",
    longitude: "-74.0056597",
  },
  id: "urn:dpp:building-asset-0-0-8:c1d9a074-6e4e-41a9-9c8e-fa9071cb0d33",
  proof: {
    proofPurpose: "assertionMethod",
    type: "Ed25519Signature2018",
    verificationMethod:
      "did:web:api-vera.susi.spherity.dev:did-registry:realizse-mvp-509d5aa5c0707240#2a820e937af6379baa0d336a268eb0566fc10463305305113c944a17c1d9f6e7",
    created: "2025-08-07T17:34:52Z",
    jws: "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..36yLo7-CPZD_LrQ9K-8Dy9YA40a6Pjuru4CbudCBG7kTCkNGYIUGtToHuL4kuQ2448Y5EukrwJyUP29D62ikCg",
  },
  type: ["VerifiableCredential"],
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://api-andromeda.susi.spherity.dev/templates/v2/building-asset-0-0-8.jsonld",
  ],
  issuer:
    "did:web:api-vera.susi.spherity.dev:did-registry:realizse-mvp-509d5aa5c0707240",
};

// ============================================================================
// GLOBAL STATE
// ============================================================================

/**
 * DOM element references cached for performance
 * @type {Object}
 */
let elements = {};

// ============================================================================
// INITIALIZATION & SETUP
// ============================================================================

/**
 * Initialize the application when DOM is ready
 */
document.addEventListener("DOMContentLoaded", () => {
  initializeElements();
  setupEventListeners();
});

/**
 * Cache all DOM element references for efficient access
 * This prevents repeated DOM queries and improves performance
 */
function initializeElements() {
  elements = {
    // Main sections
    dropZone: document.getElementById("dropZone"),
    fileInput: document.getElementById("fileInput"),
    loadSampleBtn: document.getElementById("loadSampleBtn"),
    downloadSampleBtn: document.getElementById("downloadSampleBtn"),
    viewSampleBtn: document.getElementById("viewSampleBtn"),
    credentialInfo: document.getElementById("credentialInfo"),
    verificationProgress: document.getElementById("verificationProgress"),
    results: document.getElementById("results"),

    // Progress indicators
    progressSteps: document.getElementById("progressSteps"),

    // Credential display fields
    credentialId: document.getElementById("credentialId"),
    credentialType: document.getElementById("credentialType"),
    credentialIssuer: document.getElementById("credentialIssuer"),
    credentialDate: document.getElementById("credentialDate"),
    proofType: document.getElementById("proofType"),

    // Results container
    resultContent: document.getElementById("resultContent"),
  };
}

/**
 * Set up all event listeners for user interactions
 * Handles file upload, drag-and-drop, and button clicks
 */
function setupEventListeners() {
  // File input change event
  elements.fileInput.addEventListener("change", handleFileSelect);

  // Drag and drop events
  elements.dropZone.addEventListener("click", () => elements.fileInput.click());
  elements.dropZone.addEventListener("dragover", handleDragOver);
  elements.dropZone.addEventListener("dragleave", handleDragLeave);
  elements.dropZone.addEventListener("drop", handleDrop);

  // Sample credential buttons
  elements.loadSampleBtn.addEventListener("click", loadSampleCredential);
  elements.downloadSampleBtn.addEventListener(
    "click",
    downloadSampleCredential
  );
  elements.viewSampleBtn.addEventListener("click", viewSampleCredential);
}

// ============================================================================
// FILE HANDLING & USER INPUT
// ============================================================================

/**
 * Handle file selection from the file input
 * @param {Event} event - The change event from file input
 */
function handleFileSelect(event) {
  const file = event.target.files[0];
  if (file) {
    readAndProcessFile(file);
  }
}

/**
 * Handle drag over event for visual feedback
 * @param {DragEvent} event - The dragover event
 */
function handleDragOver(event) {
  event.preventDefault();
  elements.dropZone.classList.add("drag-over");
}

/**
 * Handle drag leave event to reset visual state
 * @param {DragEvent} event - The dragleave event
 */
function handleDragLeave(event) {
  event.preventDefault();
  elements.dropZone.classList.remove("drag-over");
}

/**
 * Handle file drop event
 * @param {DragEvent} event - The drop event containing files
 */
function handleDrop(event) {
  event.preventDefault();
  elements.dropZone.classList.remove("drag-over");

  const file = event.dataTransfer.files[0];
  if (!file) return;

  if (file.type === "application/json" || file.name.endsWith(".json")) {
    readAndProcessFile(file);
  } else {
    showError("Please drop a JSON file");
  }
}

/**
 * Read and parse the dropped/selected file
 * @param {File} file - The file to read
 */
function readAndProcessFile(file) {
  // Show loading state
  elements.dropZone.classList.add("processing");

  const reader = new FileReader();

  reader.onload = (e) => {
    elements.dropZone.classList.remove("processing");
    try {
      const credential = JSON.parse(e.target.result);
      processCredential(credential);
    } catch (error) {
      showError("Invalid JSON file: " + error.message);
    }
  };

  reader.onerror = () => {
    elements.dropZone.classList.remove("processing");
    showError("Failed to read file");
  };

  reader.readAsText(file);
}

/**
 * Load the sample credential for demonstration
 */
function loadSampleCredential() {
  processCredential(SAMPLE_CREDENTIAL);
}

/**
 * Download the sample credential as a JSON file
 */
function downloadSampleCredential() {
  // Convert the credential object to a formatted JSON string
  const jsonString = JSON.stringify(SAMPLE_CREDENTIAL, null, 2);

  // Create a blob with the JSON data
  const blob = new Blob([jsonString], { type: "application/json" });

  // Create a temporary download link
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "sample-credential.json";

  // Trigger the download
  document.body.appendChild(link);
  link.click();

  // Clean up
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * View the sample credential in a new tab
 */
function viewSampleCredential() {
  // Convert the credential to formatted JSON
  const jsonString = JSON.stringify(SAMPLE_CREDENTIAL, null, 2);

  // Create a blob with proper MIME type
  const blob = new Blob([jsonString], { type: "application/json" });
  const url = URL.createObjectURL(blob);

  // Open in a new tab
  window.open(url, "_blank");

  // Clean up the blob URL after a short delay
  setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 1000);
}

// ============================================================================
// CREDENTIAL PROCESSING & VALIDATION
// ============================================================================

/**
 * Process a credential by validating its structure and starting verification
 * @param {Object} credential - The credential object to process
 */
function processCredential(credential) {
  // Reset UI to clean state
  resetUI();

  // Validate the credential has required structure
  if (!validateCredentialStructure(credential)) {
    return;
  }

  // Display credential information to user
  displayCredentialInfo(credential);

  // Start the verification process
  verifyCredential(credential);
}

/**
 * Validate that the credential has all required fields and supported proof type
 * @param {Object} credential - The credential to validate
 * @returns {boolean} True if valid, false otherwise
 */
function validateCredentialStructure(credential) {
  // Check if credential is a valid object
  if (!credential || typeof credential !== "object") {
    showError("Invalid credential: must be a JSON object");
    return false;
  }

  // Check for proof field
  if (!credential.proof || !credential.proof.type) {
    showError("Invalid credential: missing proof");
    return false;
  }

  // Check for verification method
  if (!credential.proof.verificationMethod) {
    showError("Invalid credential: missing verificationMethod");
    return false;
  }

  // Verify proof type is supported
  if (credential.proof.type !== "Ed25519Signature2018") {
    showError(
      `Unsupported proof type: ${credential.proof.type}. This verifier only supports Ed25519Signature2018`
    );
    return false;
  }

  return true;
}

/**
 * Display credential information in the UI
 * @param {Object} credential - The credential to display
 */
function displayCredentialInfo(credential) {
  // Populate credential fields with safe fallbacks
  elements.credentialId.textContent = credential.id || "Not specified";
  elements.credentialType.textContent = Array.isArray(credential.type)
    ? credential.type.join(", ")
    : credential.type;

  // Display issuer with clickable link for did:web
  const issuerDid = credential.issuer || "Not specified";
  if (issuerDid.startsWith("did:web:")) {
    const didUrl = `https://${issuerDid
      .replace("did:web:", "")
      .replace(/:/g, "/")}/did.json`;
    elements.credentialIssuer.innerHTML = `<a href="${didUrl}" target="_blank" rel="noopener">${issuerDid}</a>`;
  } else {
    elements.credentialIssuer.textContent = issuerDid;
  }

  elements.credentialDate.textContent =
    credential.issuanceDate || "Not specified";
  elements.proofType.textContent = credential.proof.type;

  // Show the credential info section
  elements.credentialInfo.classList.remove("hidden");
}

// ============================================================================
// CREDENTIAL VERIFICATION
// ============================================================================

/**
 * Main verification function that orchestrates the entire verification process
 * @param {Object} credential - The credential to verify
 */
async function verifyCredential(credential) {
  // Show verification progress section
  elements.verificationProgress.classList.remove("hidden");
  elements.progressSteps.innerHTML = "";

  try {
    addProgressStep(
      "Starting verification",
      "Initializing cryptographic verification process..."
    );

    addProgressStep("Checking proof format", `Type: ${credential.proof.type}`);

    // Call verification function with progress callback
    const result = await verifyCredentialSignature(
      credential,
      (progress, message) => {
        // Add progress steps for major milestones
        switch (progress) {
          case PROGRESS_STEPS.RESOLVE_DID:
            addProgressStep(
              "Resolving DID",
              "Fetching decentralized identifier document..."
            );
            break;
          case PROGRESS_STEPS.CREATE_KEY:
            addProgressStep("Creating verification key");
            break;
          case PROGRESS_STEPS.VERIFY:
            addProgressStep("Verifying signature");
            break;
        }
      }
    );

    // Show appropriate result
    if (result.verified) {
      showSuccess(credential);
    } else if (result.errors && result.errors.includes("CORS")) {
      showPartialSuccess(credential);
    } else if (result.errorType === "SAFE_MODE") {
      // Show partial success for safe mode errors
      showPartialSuccessForSafeMode(credential, result.error);
    } else if (result.errorType === "TIMEOUT") {
      // Show timeout error
      showTimeoutError(credential);
    } else {
      showFailure(result.error || result.errors || "Verification failed");
    }
  } catch (error) {
    showError(error.message);
  }
}

// ============================================================================
// UI UPDATE FUNCTIONS
// ============================================================================

/**
 * Mark all progress steps as completed
 * Used when verification process finishes (success or failure)
 */
function completeAllProgressSteps() {
  const allSteps = elements.progressSteps.querySelectorAll(".progress-step");
  allSteps.forEach((step) => {
    step.classList.remove("active");
    step.classList.add("completed");
    const icon = step.querySelector(".step-icon");
    if (icon) icon.innerHTML = "✓";
  });
}

/**
 * Add a step to the verification progress display
 * @param {string} title - The step title
 * @param {string} detail - Optional detailed description or HTML content
 */
function addProgressStep(title, detail = null) {
  // Mark previous steps as completed
  const previousSteps = elements.progressSteps.querySelectorAll(
    ".progress-step.active"
  );
  previousSteps.forEach((step) => {
    step.classList.remove("active");
    step.classList.add("completed");
    const icon = step.querySelector(".step-icon");
    if (icon) icon.innerHTML = "✓";
  });

  // Create new step
  const step = document.createElement("div");
  step.className = "progress-step active";
  step.innerHTML = `
    <div class="step-icon"><span class="spinner"></span></div>
    <div class="step-content">
      <div class="step-title">${title}</div>
      ${detail ? `<div class="step-detail">${detail}</div>` : ""}
    </div>
  `;

  elements.progressSteps.appendChild(step);
}

/**
 * Reset the UI to initial state
 */
function resetUI() {
  elements.credentialInfo.classList.add("hidden");
  elements.verificationProgress.classList.add("hidden");
  elements.results.classList.add("hidden");
}

// ============================================================================
// RESULT DISPLAY FUNCTIONS
// ============================================================================

/**
 * Display verification result with appropriate styling and message
 * @param {string} type - Result type: 'success', 'partial', 'timeout', 'failure', 'error'
 * @param {string} title - Result title
 * @param {string} message - Result message
 * @param {Array} details - Array of detail items with icon and text
 * @param {string} errorText - Optional error text for failure cases
 */
function showResult(type, title, message, details = [], errorText = null) {
  completeAllProgressSteps();
  elements.results.classList.remove("hidden");

  // Determine icon based on type
  let iconSvg;
  switch (type) {
    case "success":
      iconSvg = `<svg class="result-icon result-success" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>`;
      break;
    case "warning":
    case "partial":
    case "timeout":
      iconSvg = `<svg class="result-icon result-warning" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>`;
      break;
    case "error":
    case "failure":
      iconSvg = `<svg class="result-icon result-error" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>`;
      break;
  }

  // Build details HTML
  const detailsHtml =
    details.length > 0
      ? `
    <div class="result-details">
      ${details
        .map(
          (item) => `
        <div class="detail-item">
          <span>${item.icon}</span>
          <span>${item.text}</span>
        </div>
      `
        )
        .join("")}
      ${
        errorText
          ? `<p style="color: var(--error-color);">${errorText}</p>`
          : ""
      }
    </div>
  `
      : errorText
      ? `<div class="result-details"><p style="color: var(--error-color);">${errorText}</p></div>`
      : "";

  // Determine button text
  const buttonText =
    type === "error"
      ? "Try Again"
      : type === "timeout"
      ? "Try Again"
      : "Verify Another Credential";

  elements.resultContent.innerHTML = `
    ${iconSvg}
    <h3 class="result-title ${
      type === "success"
        ? "result-success"
        : type === "error" || type === "failure"
        ? "result-error"
        : ""
    }">${title}</h3>
    <p class="result-message">${message}</p>
    ${detailsHtml}
    <button class="btn ${
      type === "error" ? "btn-secondary" : "btn-primary"
    }" style="margin-top: 1rem;" onclick="location.reload()">${buttonText}</button>
  `;
}

/**
 * Display successful verification result
 * @param {Object} credential - The verified credential
 */
function showSuccess(credential) {
  showResult(
    "success",
    "Verification Successful",
    "The credential signature has been cryptographically verified.",
    [
      { icon: "✓", text: "Digital signature is valid" },
      { icon: "✓", text: "Issuer identity confirmed" },
      { icon: "✓", text: "Credential has not been tampered with" },
    ]
  );
}

/**
 * Display partial verification result for safe mode errors
 * @param {Object} credential - The credential
 * @param {string} errorMessage - The error message
 */
function showPartialSuccessForSafeMode(credential, errorMessage) {
  showResult(
    "partial",
    "Browser Verification Limited",
    "The credential structure is valid, but full cryptographic verification cannot be completed in the browser due to security restrictions.",
    [
      { icon: "✅", text: "Credential structure is valid" },
      { icon: "✅", text: "Proof format is correct (Ed25519Signature2018)" },
      { icon: "✅", text: "DID resolved successfully" },
      { icon: "⚠️", text: "JSON-LD processing restricted by browser security" },
      {
        icon: "ℹ️",
        text: "Server-side verification recommended for production use",
      },
    ]
  );
}

/**
 * Display timeout error
 * @param {Object} credential - The credential that timed out
 */
function showTimeoutError(credential) {
  showResult(
    "timeout",
    "Verification Timeout",
    "The verification process took too long to complete. This may be due to network issues or complex credential processing.",
    [
      { icon: "✅", text: "Credential structure validated" },
      { icon: "✅", text: "DID resolved successfully" },
      { icon: "⏱️", text: "Cryptographic verification timed out" },
      { icon: "ℹ️", text: "Try refreshing the page and verifying again" },
    ]
  );
}

/**
 * Display partial verification result (when CORS prevents full verification)
 * @param {Object} credential - The partially verified credential
 */
function showPartialSuccess(credential) {
  showResult(
    "partial",
    "Partial Verification",
    "Structure verified, but signature verification requires server-side processing.",
    [
      { icon: "✓", text: "Credential structure is valid" },
      { icon: "✓", text: "Proof format is correct (Ed25519Signature2018)" },
      { icon: "!", text: "CORS prevents DID resolution in browser" },
      { icon: "i", text: "Full verification available via API endpoint" },
    ]
  );
}

/**
 * Display verification failure result
 * @param {Error} error - The verification error
 */
function showFailure(error) {
  // Extract meaningful error message
  let errorMessage = "Unknown verification error";
  if (error) {
    if (typeof error === "string") {
      errorMessage = error;
    } else if (error.message) {
      errorMessage = error.message;
    } else if (error.errors && Array.isArray(error.errors)) {
      // Handle jsonld-signatures error format
      errorMessage = error.errors.map((e) => e.message || e).join(", ");
    }
  }

  showResult(
    "failure",
    "Verification Failed",
    "The credential signature could not be verified.",
    [],
    errorMessage
  );
}

/**
 * Display an error message
 * @param {string} message - The error message to display
 */
function showError(message) {
  elements.verificationProgress.classList.add("hidden");
  elements.credentialInfo.classList.add("hidden");
  showResult("error", "Error", message);
}
