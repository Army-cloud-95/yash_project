/**
 * API client for OT Sentinel backend.
 * Uses configurable base URL and handles bearer token authentication.
 */

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

let onUnauthorizedCallback = null;

export const setUnauthorizedHandler = (cb) => {
  onUnauthorizedCallback = cb;
};

export const getAuthToken = () => {
  try {
    return sessionStorage.getItem("ots_token") || null;
  } catch {
    return null;
  }
};

export const setAuthToken = (token) => {
  try {
    if (token) {
      sessionStorage.setItem("ots_token", token);
    } else {
      sessionStorage.removeItem("ots_token");
    }
  } catch {
    // ignore sessionStorage errors in restricted environments
  }
};

export const clearAuthSession = () => {
  try {
    sessionStorage.removeItem("ots_token");
    sessionStorage.removeItem("ots_u");
  } catch {
    // ignore
  }
};

async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  const token = getAuthToken();

  const headers = { ...options.headers };

  if (token && !headers["Authorization"]) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // Do not set Content-Type if body is FormData (browser automatically sets boundary)
  const isFormData = options.body instanceof FormData;
  if (!isFormData && options.body && typeof options.body === "object") {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(options.body);
  }

  let response;
  try {
    response = await fetch(url, {
      ...options,
      headers
    });
  } catch (err) {
    throw new Error(
      `Unable to connect to backend service at ${API_BASE_URL}. Ensure FastAPI is running on port 8000.`
    );
  }

  if (response.status === 401) {
    clearAuthSession();
    if (onUnauthorizedCallback) {
      onUnauthorizedCallback();
    }
    let detail = "Session expired or invalid credentials.";
    try {
      const errJson = await response.json();
      if (errJson && errJson.detail) detail = errJson.detail;
    } catch {
      // ignore
    }
    throw new Error(detail);
  }

  if (!response.ok) {
    let errorDetail = `Request failed (${response.status} ${response.statusText})`;
    try {
      const errJson = await response.json();
      if (errJson && errJson.detail) {
        errorDetail = errJson.detail;
      }
    } catch {
      // ignore
    }
    const error = new Error(errorDetail);
    error.status = response.status;
    throw error;
  }

  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return await response.json();
  } else if (contentType.includes("text/csv") || contentType.includes("text/plain")) {
    return await response.text();
  }

  return response;
}

export const api = {
  getBaseUrl() {
    return API_BASE_URL;
  },

  async login(username, password) {
    const data = await apiRequest("/auth/login", {
      method: "POST",
      body: { username, password }
    });
    if (data.access_token) {
      setAuthToken(data.access_token);
    }
    return data;
  },

  async getMe() {
    return await apiRequest("/me", { method: "GET" });
  },

  async getPlants() {
    return await apiRequest("/plants", { method: "GET" });
  },

  async getAssets(plantId) {
    return await apiRequest(`/plants/${plantId}/assets`, { method: "GET" });
  },

  async addAsset(plantId, asset) {
    return await apiRequest(`/plants/${plantId}/assets`, {
      method: "POST",
      body: asset
    });
  },

  async uploadPcap(plantId, file) {
    const formData = new FormData();
    formData.append("file", file);
    return await apiRequest(`/plants/${plantId}/uploads/pcap`, {
      method: "POST",
      body: formData
    });
  },

  async uploadTelemetry(plantId, file, { column = "pressure_bar", lo, hi }) {
    const formData = new FormData();
    formData.append("file", file);
    const params = new URLSearchParams({ column, lo: String(lo), hi: String(hi) });
    return await apiRequest(`/plants/${plantId}/uploads/telemetry?${params.toString()}`, {
      method: "POST",
      body: formData
    });
  },

  async getFindings(plantId) {
    return await apiRequest(`/plants/${plantId}/findings`, { method: "GET" });
  },

  async getCorrelation(plantId, window = 120) {
    return await apiRequest(`/plants/${plantId}/correlation?window=${window}`, {
      method: "GET"
    });
  },

  async getReportCsv(plantId) {
    return await apiRequest(`/plants/${plantId}/report.csv`, {
      method: "GET",
      headers: {
        Accept: "text/csv"
      }
    });
  }
};

