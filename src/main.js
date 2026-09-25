/**
 * UI handling for the credential verifier.
 * See lib/credential-verifier.ts (copied from realizse-platform-ui) for the
 * cryptographic verification logic.
 */

import {
  verifyCredentialSignature,
  PROGRESS_STEPS,
  didWebToHttpsUrls,
  getCredentialIssuerId,
} from "./lib/credential-verifier.ts";
import { createLatestRunTracker } from "./latest-run.js";
import "./style.css";

const verificationRuns = createLatestRunTracker();

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function normalizeErrorString(value) {
  if (!value) return "";
  return typeof value === "string" ? value : value.message || String(value);
}

// Map technical verification errors to user-friendly messages
function getUserFriendlyVerificationError(technicalError) {
  const errorStr = normalizeErrorString(technicalError);
  if (!errorStr) return "Verification failed. The credential signature could not be verified.";

  const normalized = errorStr.toLowerCase();

  if (normalized.includes("cors") || normalized.includes("failed to fetch")) {
    return "Unable to reach the issuer's server. This may be a network issue or the issuer's server may not allow browser verification.";
  }
  if (normalized.includes("timeout")) {
    return "Verification took too long. Please try again.";
  }
  if (normalized.includes("unsupported proof type")) {
    return "This credential uses a signature type this verifier doesn't support. Only Ed25519Signature2020 credentials can be verified.";
  }
  if (normalized.includes("verification method") && normalized.includes("not found")) {
    return "The issuer's public key could not be found. The credential may be invalid or the issuer's records may have changed.";
  }
  if (normalized.includes("safe mode")) {
    return "The credential contains untrusted external references that cannot be verified in the browser.";
  }
  if (normalized.includes("missing proof")) {
    return "This credential doesn't contain a valid signature.";
  }
  return "Verification failed. The credential signature could not be verified.";
}

let elements = {};

document.addEventListener("DOMContentLoaded", () => {
  initializeElements();
  setupEventListeners();
});

function initializeElements() {
  elements = {
    dropZone: document.getElementById("dropZone"),
    fileInput: document.getElementById("fileInput"),
    credentialInfo: document.getElementById("credentialInfo"),
    verificationProgress: document.getElementById("verificationProgress"),
    results: document.getElementById("results"),

    progressSteps: document.getElementById("progressSteps"),
    credentialId: document.getElementById("credentialId"),
    credentialType: document.getElementById("credentialType"),
    credentialIssuer: document.getElementById("credentialIssuer"),
    credentialDate: document.getElementById("credentialDate"),
    proofType: document.getElementById("proofType"),
    resultContent: document.getElementById("resultContent"),
  };
}

function setupEventListeners() {
  elements.fileInput.addEventListener("change", handleFileSelect);
  elements.dropZone.addEventListener("click", () => elements.fileInput.click());
  elements.dropZone.addEventListener("dragover", handleDragOver);
  elements.dropZone.addEventListener("dragleave", handleDragLeave);
  elements.dropZone.addEventListener("drop", handleDrop);
}

// Every upload attempt supersedes the previous one: clear what it showed and
// stop its results from appearing, before the new file is checked or read.
function beginUpload() {
  elements.dropZone.classList.remove("processing");
  resetUI();
  return verificationRuns.start();
}

function handleFileSelect(event) {
  const file = event.target.files[0];
  if (file) {
    readAndProcessFile(file, beginUpload());
  }
}

function handleDragOver(event) {
  event.preventDefault();
  elements.dropZone.classList.add("drag-over");
}

function handleDragLeave(event) {
  event.preventDefault();
  elements.dropZone.classList.remove("drag-over");
}

function handleDrop(event) {
  event.preventDefault();
  elements.dropZone.classList.remove("drag-over");

  const file = event.dataTransfer.files[0];
  if (!file) return;

  const isCurrent = beginUpload();
  if (file.type === "application/json" || file.name.endsWith(".json")) {
    readAndProcessFile(file, isCurrent);
  } else {
    showUserError("Please drop a JSON file");
  }
}

function readAndProcessFile(file, isCurrent) {
  elements.dropZone.classList.add("processing");
  const reader = new FileReader();

  reader.onload = (e) => {
    if (!isCurrent()) return;
    elements.dropZone.classList.remove("processing");
    try {
      const credential = JSON.parse(e.target.result);
      processCredential(credential, isCurrent);
    } catch (error) {
      showUserError("Invalid JSON file: " + error.message);
    }
  };

  reader.onerror = () => {
    if (!isCurrent()) return;
    elements.dropZone.classList.remove("processing");
    showUserError("Failed to read file");
  };

  reader.readAsText(file);
}

function processCredential(credential, isCurrent) {
  resetUI();

  if (!validateCredentialStructure(credential)) {
    return;
  }
  displayCredentialInfo(credential);
  verifyCredential(credential, isCurrent);
}

function validateCredentialStructure(credential) {
  if (!credential || typeof credential !== "object") {
    showUserError("Invalid credential: must be a JSON object");
    return false;
  }
  if (!credential.proof || !credential.proof.type) {
    showUserError("Invalid credential: missing proof");
    return false;
  }
  if (!credential.proof.verificationMethod) {
    showUserError("Invalid credential: missing verificationMethod");
    return false;
  }
  return true;
}

function displayCredentialInfo(credential) {
  elements.credentialId.textContent = credential.id || "Not specified";
  elements.credentialType.textContent = Array.isArray(credential.type)
    ? credential.type.join(", ")
    : credential.type;

  const issuerDid = getCredentialIssuerId(credential.issuer) || "Not specified";
  if (issuerDid.startsWith("did:web:")) {
    try {
      const [didUrl] = didWebToHttpsUrls(issuerDid);
      const link = document.createElement("a");
      link.href = didUrl;
      link.target = "_blank";
      link.rel = "noopener";
      link.textContent = issuerDid;
      elements.credentialIssuer.textContent = "";
      elements.credentialIssuer.appendChild(link);
    } catch {
      elements.credentialIssuer.textContent = issuerDid;
    }
  } else {
    elements.credentialIssuer.textContent = issuerDid;
  }

  elements.credentialDate.textContent = credential.issuanceDate || "Not specified";
  elements.proofType.textContent = credential.proof.type;
  elements.credentialInfo.classList.remove("hidden");
}

async function verifyCredential(credential, isCurrent) {
  elements.verificationProgress.classList.remove("hidden");
  elements.progressSteps.innerHTML = "";

  try {
    addProgressStep("Starting verification", "Initializing cryptographic verification process...");
    addProgressStep("Checking proof format", `Type: ${credential.proof.type}`);

    const result = await verifyCredentialSignature(
      credential,
      (progress, message) => {
        if (!isCurrent()) return;
        switch (progress) {
          case PROGRESS_STEPS.SETUP_SUITE:
            addProgressStep("Setting up verification");
            break;
          case PROGRESS_STEPS.VERIFY:
            addProgressStep("Checking issuer and signature", "Fetching the issuer's DID document...");
            break;
        }
      }
    );

    if (!isCurrent()) return;
    if (result.verified) {
      showSuccess(getCredentialIssuerId(credential.issuer));
    } else if (result.errorType === "TIMEOUT") {
      showTimeoutError();
    } else if (result.errorType === "ISSUER_MISMATCH") {
      showIssuerMismatch(result.error);
    } else if (result.errorType === "ISSUER_UNRESOLVED") {
      showIssuerUnresolved(result.error);
    } else {
      showFailure(result.error || "Verification failed");
    }
  } catch (error) {
    if (!isCurrent()) return;
    showError(error);
  }
}

// The last step shows how verification ended: ✓ passed, ✗ failed, ! not confirmed
function completeAllProgressSteps(lastStepIcon = "✓") {
  const allSteps = elements.progressSteps.querySelectorAll(".progress-step");
  allSteps.forEach((step, index) => {
    step.classList.remove("active");
    step.classList.add("completed");
    const icon = step.querySelector(".step-icon");
    if (icon) {
      const isLast = index === allSteps.length - 1;
      icon.innerHTML = isLast ? lastStepIcon : "✓";
    }
  });
}

function addProgressStep(title, detail = null) {
  const previousSteps = elements.progressSteps.querySelectorAll(".progress-step.active");
  previousSteps.forEach((step) => {
    step.classList.remove("active");
    step.classList.add("completed");
    const icon = step.querySelector(".step-icon");
    if (icon) icon.innerHTML = "✓";
  });

  const step = document.createElement("div");
  step.className = "progress-step active";
  const safeTitle = escapeHtml(title);
  const safeDetail = detail ? escapeHtml(detail) : null;
  step.innerHTML = `
    <div class="step-icon"><span class="spinner"></span></div>
    <div class="step-content">
      <div class="step-title">${safeTitle}</div>
      ${safeDetail ? `<div class="step-detail">${safeDetail}</div>` : ""}
    </div>
  `;
  elements.progressSteps.appendChild(step);
}

function resetUI() {
  elements.credentialInfo.classList.add("hidden");
  elements.verificationProgress.classList.add("hidden");
  elements.results.classList.add("hidden");
}

function showResult(type, title, message, details = [], errorText = null) {
  const lastStepIcon =
    type === "failure" || type === "error"
      ? '<span style="color: var(--error-color)">✗</span>'
      : type === "success"
      ? "✓"
      : '<span style="color: var(--warning-color)">!</span>';
  completeAllProgressSteps(lastStepIcon);
  elements.results.classList.remove("hidden");

  const safeTitle = escapeHtml(title);
  const safeMessage = escapeHtml(message);
  const safeErrorText = errorText ? escapeHtml(errorText) : null;

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

  // Build details HTML with collapsible technical error
  const technicalErrorHtml = safeErrorText
    ? `
      <details class="technical-details">
        <summary>Show technical details</summary>
        <pre>${safeErrorText}</pre>
      </details>
    `
    : "";

  const detailsHtml =
    details.length > 0
      ? `
    <div class="result-details">
      ${details
        .map(
          (item) => `
        <div class="detail-item">
          <span>${escapeHtml(item.icon)}</span>
          <span>${escapeHtml(item.text)}</span>
        </div>
      `
        )
        .join("")}
      ${technicalErrorHtml}
    </div>
  `
      : technicalErrorHtml
      ? `<div class="result-details">${technicalErrorHtml}</div>`
      : "";

  const buttonText = type === "error" || type === "timeout" ? "Try Again" : "Verify Another Credential";

  elements.resultContent.innerHTML = `
    ${iconSvg}
    <h3 class="result-title ${
      type === "success" ? "result-success" : type === "error" || type === "failure" ? "result-error" : ""
    }">${safeTitle}</h3>
    <p class="result-message">${safeMessage}</p>
    ${detailsHtml}
    <button class="btn ${
      type === "error" ? "btn-secondary" : "btn-primary"
    }" style="margin-top: 1rem;" onclick="location.reload()">${buttonText}</button>
  `;
}

function showSuccess(issuerId) {
  showResult(
    "success",
    "Verification Successful",
    "The signature is valid and was made with a key the named issuer authorized.",
    [
      { icon: "✓", text: "Digital signature is valid" },
      { icon: "✓", text: `Signed with a key authorized by ${issuerId}` },
      { icon: "✓", text: "Credential has not been changed since it was signed" },
      { icon: "i", text: "Expiry and revocation are not checked" },
    ]
  );
}

function showIssuerMismatch(error) {
  showResult(
    "failure",
    "Issuer Not Confirmed",
    "This credential could not be tied to the issuer it names. Do not rely on it.",
    [],
    normalizeErrorString(error) || null
  );
}

function showIssuerUnresolved(error) {
  const technical = normalizeErrorString(error);
  const message = technical.startsWith("Issuer unreachable")
    ? "The issuer's records could not be reached, so this credential could not be confirmed. This may be temporary; try again later."
    : "The issuer's published records could not be read, so this credential could not be confirmed.";
  showResult("warning", "Issuer Could Not Be Checked", message, [], technical || null);
}

function showTimeoutError() {
  showResult(
    "timeout",
    "Verification Timeout",
    "The verification process took too long to complete. This may be due to network issues or complex credential processing.",
    [
      { icon: "✓", text: "Credential structure validated" },
      { icon: "!", text: "Verification timed out" },
      { icon: "i", text: "Try refreshing the page and verifying again" },
    ]
  );
}

function showFailure(error) {
  let technicalError = "Unknown verification error";
  if (error) {
    if (typeof error === "string") {
      technicalError = error;
    } else if (error.errors && Array.isArray(error.errors)) {
      technicalError = error.errors.map((e) => e.message || e).join(", ");
    } else if (error.message) {
      technicalError = error.message;
    }
  }

  // Extract inner errors if top-level message is generic
  if (
    technicalError === "Verification error(s)." &&
    error?.errors?.length > 0
  ) {
    technicalError = error.errors
      .map((innerError) => innerError?.message || String(innerError))
      .join(", ");
  }

  const friendlyError = getUserFriendlyVerificationError(technicalError);

  showResult(
    "failure",
    "Verification Failed",
    friendlyError,
    [],
    technicalError !== friendlyError ? technicalError : null
  );
}

function showError(message) {
  elements.verificationProgress.classList.add("hidden");
  elements.credentialInfo.classList.add("hidden");
  const technicalMessage = normalizeErrorString(message);
  const friendlyMessage = getUserFriendlyVerificationError(technicalMessage);
  showResult(
    "error",
    "Error",
    friendlyMessage,
    [],
    technicalMessage !== friendlyMessage ? technicalMessage : null
  );
}

function showUserError(message) {
  elements.verificationProgress.classList.add("hidden");
  elements.credentialInfo.classList.add("hidden");
  showResult("error", "Error", normalizeErrorString(message) || "Error");
}
