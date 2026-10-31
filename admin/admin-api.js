const ADMIN_API_URL = "http://127.0.0.1:5000";

function adminEscape(value) {
    const element = document.createElement("span");
    element.textContent = value === null || value === undefined ? "" : String(value);
    return element.innerHTML;
}

function adminDate(value) {
    if (!value) return "-";
    const parsed = new Date(String(value).replace(" ", "T"));
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
}

async function adminApiRequest(endpoint, options = {}) {
    const token = localStorage.getItem("smart_outpass_token");
    let user = null;

    try {
        user = JSON.parse(localStorage.getItem("smart_outpass_user") || "null");
    } catch (error) {
        user = null;
    }

    if (!token || !user || user.role !== "admin") {
        localStorage.removeItem("smart_outpass_token");
        localStorage.removeItem("smart_outpass_user");
        window.location.href = "../index.html";
        throw new Error("Admin sign-in is required.");
    }

    const response = await fetch(ADMIN_API_URL + endpoint, {
        ...options,
        headers: {
            "Authorization": "Bearer " + token,
            ...(options.body ? { "Content-Type": "application/json" } : {}),
            ...(options.headers || {})
        }
    });

    if (response.status === 401) {
        localStorage.removeItem("smart_outpass_token");
        localStorage.removeItem("smart_outpass_user");
        window.location.href = "../index.html";
        throw new Error("Your admin session has expired. Please sign in again.");
    }

    const data = await response.json();
    if (!response.ok || data.success === false) {
        throw new Error(data.message || "The request could not be completed.");
    }
    return data;
}

function showAdminError(message) {
    let alert = document.getElementById("adminApiError");
    if (!alert) {
        alert = document.createElement("div");
        alert.id = "adminApiError";
        alert.className = "alert alert-danger mx-auto mt-3";
        alert.style.maxWidth = "1200px";
        document.querySelector("main, .page-container")?.before(alert);
    }
    alert.textContent = message;
    alert.style.display = "block";
}

function clearAdminError() {
    const alert = document.getElementById("adminApiError");
    if (alert) alert.style.display = "none";
}

function adminLogout() {
    localStorage.removeItem("smart_outpass_token");
    localStorage.removeItem("smart_outpass_user");
    window.location.href = "../index.html";
}
