/**
 * UI handling for the credential verifier.
 * See verification.js for the cryptographic verification logic.
 */

import {
  verifyCredentialSignature,
  PROGRESS_STEPS,
  didWebToHttpsUrls,
} from "./verification.js";
import "./style.css";

// Sample credential for testing
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

let elements = {};

document.addEventListener("DOMContentLoaded", () => {
  initializeElements();
  setupEventListeners();
});

function initializeElements() {
  elements = {
    dropZone: document.getElementById("dropZone"),
    fileInput: document.getElementById("fileInput"),
    loadSampleBtn: document.getElementById("loadSampleBtn"),
    downloadSampleBtn: document.getElementById("downloadSampleBtn"),
    viewSampleBtn: document.getElementById("viewSampleBtn"),
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
  elements.loadSampleBtn.addEventListener("click", loadSampleCredential);
  elements.downloadSampleBtn.addEventListener(
    "click",
    downloadSampleCredential
  );
  elements.viewSampleBtn.addEventListener("click", viewSampleCredential);
}

function handleFileSelect(event) {
  const file = event.target.files[0];
  if (file) {
    readAndProcessFile(file);
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

  if (file.type === "application/json" || file.name.endsWith(".json")) {
    readAndProcessFile(file);
  } else {
    showError("Please drop a JSON file");
  }
}

function readAndProcessFile(file) {
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

function loadSampleCredential() {
  processCredential(SAMPLE_CREDENTIAL);
}

function downloadSampleCredential() {
  const jsonString = JSON.stringify(SAMPLE_CREDENTIAL, null, 2);
  const blob = new Blob([jsonString], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "sample-credential.json";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function viewSampleCredential() {
  const jsonString = JSON.stringify(SAMPLE_CREDENTIAL, null, 2);
  const blob = new Blob([jsonString], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank");
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function processCredential(credential) {
  resetUI();

  if (!validateCredentialStructure(credential)) {
    return;
  }
  displayCredentialInfo(credential);
  verifyCredential(credential);
}

function validateCredentialStructure(credential) {
  if (!credential || typeof credential !== "object") {
    showError("Invalid credential: must be a JSON object");
    return false;
  }
  if (!credential.proof || !credential.proof.type) {
    showError("Invalid credential: missing proof");
    return false;
  }
  if (!credential.proof.verificationMethod) {
    showError("Invalid credential: missing verificationMethod");
    return false;
  }
  if (credential.proof.type !== "Ed25519Signature2018") {
    showError(
      `Unsupported proof type: ${credential.proof.type}. This verifier only supports Ed25519Signature2018`
    );
    return false;
  }
  return true;
}

function displayCredentialInfo(credential) {
  elements.credentialId.textContent = credential.id || "Not specified";
  elements.credentialType.textContent = Array.isArray(credential.type)
    ? credential.type.join(", ")
    : credential.type;

  const issuerDid = credential.issuer || "Not specified";
  if (issuerDid.startsWith("did:web:")) {
    const [didUrl] = didWebToHttpsUrls(issuerDid);
    elements.credentialIssuer.innerHTML = `<a href="${didUrl}" target="_blank" rel="noopener">${issuerDid}</a>`;
  } else {
    elements.credentialIssuer.textContent = issuerDid;
  }

  elements.credentialDate.textContent =
    credential.issuanceDate || "Not specified";
  elements.proofType.textContent = credential.proof.type;
  elements.credentialInfo.classList.remove("hidden");
}

async function verifyCredential(credential) {
  elements.verificationProgress.classList.remove("hidden");
  elements.progressSteps.innerHTML = "";

  try {
    addProgressStep(
      "Starting verification",
      "Initializing cryptographic verification process..."
    );
    addProgressStep("Checking proof format", `Type: ${credential.proof.type}`);

    const result = await verifyCredentialSignature(
      credential,
      (progress, message) => {
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

    if (result.verified) {
      showSuccess();
    } else if (result.errorType === "TIMEOUT") {
      showTimeoutError();
    } else {
      showFailure(result.error || "Verification failed");
    }
  } catch (error) {
    showError(error.message);
  }
}

function completeAllProgressSteps(failed = false) {
  const allSteps = elements.progressSteps.querySelectorAll(".progress-step");
  allSteps.forEach((step, index) => {
    step.classList.remove("active");
    step.classList.add("completed");
    const icon = step.querySelector(".step-icon");
    if (icon) {
      const isLast = index === allSteps.length - 1;
      icon.innerHTML =
        failed && isLast
          ? '<span style="color: var(--error-color)">✗</span>'
          : "✓";
    }
  });
}

function addProgressStep(title, detail = null) {
  const previousSteps = elements.progressSteps.querySelectorAll(
    ".progress-step.active"
  );
  previousSteps.forEach((step) => {
    step.classList.remove("active");
    step.classList.add("completed");
    const icon = step.querySelector(".step-icon");
    if (icon) icon.innerHTML = "✓";
  });

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

function resetUI() {
  elements.credentialInfo.classList.add("hidden");
  elements.verificationProgress.classList.add("hidden");
  elements.results.classList.add("hidden");
}

function showResult(type, title, message, details = [], errorText = null) {
  const isFailed = type === "failure" || type === "error";
  completeAllProgressSteps(isFailed);
  elements.results.classList.remove("hidden");

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

  const buttonText =
    type === "error" || type === "timeout"
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

function showSuccess() {
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

function showTimeoutError() {
  showResult(
    "timeout",
    "Verification Timeout",
    "The verification process took too long to complete. This may be due to network issues or complex credential processing.",
    [
      { icon: "✓", text: "Credential structure validated" },
      { icon: "✓", text: "DID resolved successfully" },
      { icon: "!", text: "Cryptographic verification timed out" },
      { icon: "i", text: "Try refreshing the page and verifying again" },
    ]
  );
}

function showFailure(error) {
  let errorMessage = "Unknown verification error";
  if (error) {
    if (typeof error === "string") {
      errorMessage = error;
    } else if (error.errors && Array.isArray(error.errors)) {
      errorMessage = error.errors.map((e) => e.message || e).join(", ");
    } else if (error.message) {
      errorMessage = error.message;
    }
  }

  // Extract inner errors if top-level message is generic
  if (errorMessage === "Verification error(s)." && error?.errors?.length > 0) {
    errorMessage = error.errors
      .map((innerError) => innerError?.message || String(innerError))
      .join(", ");
  }

  showResult(
    "failure",
    "Verification Failed",
    "The credential signature could not be verified.",
    [],
    errorMessage
  );
}

function showError(message) {
  elements.verificationProgress.classList.add("hidden");
  elements.credentialInfo.classList.add("hidden");
  showResult("error", "Error", message);
}
