import { create } from "zustand";
import type {
  Analytics,
  ApiKey,
  AuditLogEntry,
  AuditLogsQuery,
  NotificationItem,
  SecurityLog,
  TeamInvitePayload,
  TeamMember,
  TeamRole,
  UsageSummary,
  UserAccount,
  UserSettings,
} from "../types";
import { getAccessToken, getDisplayName, hasStoredSession } from "../services/auth";
import { buildBackendWebSocketUrl } from "../services/api";
import { HttpError, authedFetch, authedFetchJson } from "../services/authenticatedFetch";
import { normalizeRiskLevel, normalizeRiskScore } from "../lib/riskScore";
import {
  fetchAuditLogs as fetchAuditLogsApi,
  fetchTeamMembers as fetchTeamMembersApi,
  fetchUsageSummary as fetchUsageSummaryApi,
  getUsageAlertPreference,
  inviteTeamMember as inviteTeamMemberApi,
  removeTeamMember as removeTeamMemberApi,
  setUsageAlertPreference,
  updateTeamMemberRole as updateTeamMemberRoleApi,
} from "../services/enterprise";

const MAX_LOG_BUFFER = 500;
const REALTIME_RECONNECT_BASE_MS = 1000;
const REALTIME_RECONNECT_MAX_MS = 30000;
const REALTIME_AUTH_CLOSE_CODE = 1008;
const REALTIME_SERVER_ERROR_CLOSE_CODE = 1011;
const REALTIME_RETRYABLE_CLOSE_CODES = new Set([1001, 1006, 1011, 1012, 1013]);

type LogsQueryParams = {
  limit?: number;
  offset?: number;
  status?: string;
  threat_type?: string;
  api_key_id?: string | number;
  start_time?: string;
  end_time?: string;
  q?: string;
};

function unwrapApi<T>(payload: any): T {
  if (payload && typeof payload === "object" && "success" in payload && "data" in payload) {
    return payload.data as T;
  }
  return payload as T;
}

function extractListPayload<T>(payload: unknown, keys: string[] = []): T[] {
  if (Array.isArray(payload)) return payload as T[];
  if (!payload || typeof payload !== "object") return [];

  const record = payload as Record<string, unknown>;
  const candidates: unknown[] = [record.data, record.items, record.results, ...keys.map((key) => record[key])];

  for (const candidate of candidates) {
    if (Array.isArray(candidate)) return candidate as T[];
    if (candidate && typeof candidate === "object") {
      for (const key of keys) {
        const nestedValue = (candidate as Record<string, unknown>)[key];
        if (Array.isArray(nestedValue)) return nestedValue as T[];
      }
    }
  }

  return [];
}

function normalizeApiKey(item: any): ApiKey {
  const rawItem = item && typeof item === "object" ? item : {};
  const status = String(rawItem?.status || "ACTIVE");
  const normalizedStatus = status?.toLowerCase() || "";
  return {
    id: String(rawItem?.id),
    name: String(rawItem?.name || "API Key"),
    key: rawItem?.key ? String(rawItem.key) : undefined,
    created_at: String(rawItem?.created_at ?? ""),
    last_used: rawItem?.last_used ? String(rawItem.last_used) : null,
    status: normalizedStatus as any,
    usage_count: Number(rawItem?.usage_count || 0),
  };
}

function normalizeLog(item: any): SecurityLog {
  const rawItem = item && typeof item === "object" ? item : {};
  const timestampValue = rawItem?.timestamp ?? rawItem?.created_at ?? "";
  const normalizedRiskScore = normalizeRiskScore(rawItem);

  return {
    ...rawItem,
    id: String(rawItem?.id ?? rawItem?.request_id ?? timestampValue),
    timestamp: String(timestampValue),
    created_at:
      rawItem?.created_at == null
        ? (rawItem?.timestamp == null ? null : String(rawItem.timestamp))
        : String(rawItem.created_at),
    api_key_id: rawItem?.api_key_id == null ? null : String(rawItem.api_key_id),
    status: rawItem?.status == null ? "" : String(rawItem.status),
    threat_type: rawItem?.threat_type == null ? "NONE" : String(rawItem.threat_type),
    tokens_used: Number(rawItem?.tokens_used ?? 0),
    endpoint: rawItem?.endpoint == null ? null : String(rawItem.endpoint),
    method: rawItem?.method == null ? null : String(rawItem.method),
    risk_score: normalizedRiskScore,
    threat_score: normalizedRiskScore / 100,
    risk_level: normalizeRiskLevel(rawItem?.risk_level, normalizedRiskScore),
  } as SecurityLog;
}

function normalizeNotification(item: any): NotificationItem {
  return {
    id: String(item?.id),
    user_id: String(item?.user_id),
    title: String(item?.title || ""),
    message: String(item?.message || ""),
    type: item?.type == null ? null : String(item.type).toUpperCase(),
    timestamp: item?.timestamp == null ? (item?.created_at == null ? null : String(item.created_at)) : String(item.timestamp),
    is_read: Boolean(item?.is_read),
    created_at: String(item?.created_at ?? item?.timestamp ?? ""),
  };
}

function emptyAnalytics(): Analytics {
  return {
    totalThreatsBlocked: 0,
    promptInjectionsDetected: 0,
    dataLeaksPrevented: 0,
    apiRequestsToday: 0,
    securityScore: 0,
    threatsOverTime: [],
    usageVsLimit: { used: 0, limit: 1 },
    threatActivityFeed: [],
    policyTriggerCounts: {},
    attackSeverityChart: [],
    toolInterceptionMetrics: { totalToolCalls: 0, requires2FA: 0, intercepted: 0, approved: 0 },
    leakPreventionMetrics: { findings: 0, blockedEvents: 0, redactedEvents: 0 },
    topAttackSignatures: [],
    userRiskHeatmap: [],
    securityTimeline: [],
  };
}

interface AppState {
  user: UserAccount | null;
  analytics: Analytics | null;
  apiKeys: ApiKey[];
  logs: SecurityLog[];
  auditLogs: AuditLogEntry[];
  usageSummary: UsageSummary | null;
  usageAlertEnabled: boolean;
  teamMembers: TeamMember[];
  notifications: NotificationItem[];
  settings: UserSettings | null;
  reasoningLogs: { timestamp: string; message: string; threat_level: string }[];
  isLoading: boolean;
  auditLogsLoading: boolean;
  usageLoading: boolean;
  teamLoading: boolean;

  initSocket: () => void;
  disconnectRealtime: () => void;
  loadMe: () => Promise<boolean>;
  fetchAnalytics: () => Promise<void>;
  fetchApiKeys: () => Promise<void>;
  fetchLogs: (params?: LogsQueryParams) => Promise<void>;
  fetchAuditLogs: (params?: AuditLogsQuery) => Promise<void>;
  fetchUsageSummary: () => Promise<void>;
  setUsageAlertEnabled: (enabled: boolean) => void;
  fetchTeamMembers: () => Promise<void>;
  inviteTeamMember: (payload: TeamInvitePayload) => Promise<TeamMember>;
  updateTeamMemberRole: (id: string, role: TeamRole) => Promise<void>;
  removeTeamMember: (id: string) => Promise<void>;
  fetchNotifications: () => Promise<void>;
  markNotificationRead: (id: string) => Promise<void>;
  markAllNotificationsRead: () => Promise<void>;
  fetchSettings: () => Promise<void>;
  updateSettings: (patch: Partial<UserSettings>) => Promise<void>;

  // Resolves with the new key (including its one-time secret). Rejects with the underlying error so the UI can show it.
  generateApiKey: (name: string) => Promise<ApiKey>;
  revokeApiKey: (id: string) => Promise<void>;

  addLiveLog: (log: SecurityLog) => void;
  addReasoningLog: (message: string, threat_level: string) => void;
  addLiveNotification: (n: NotificationItem) => void;
}

type RealtimeChannelName = "logs" | "notifications";

let logSocket: WebSocket | null = null;
let notificationSocket: WebSocket | null = null;
let realtimeInitialized = false;
const reconnectTimers: Partial<Record<RealtimeChannelName, number>> = {};
const reconnectAttempts: Record<RealtimeChannelName, number> = {
  logs: 0,
  notifications: 0,
};

function getRealtimeSocket(channel: RealtimeChannelName): WebSocket | null {
  return channel === "logs" ? logSocket : notificationSocket;
}

function setRealtimeSocket(channel: RealtimeChannelName, socket: WebSocket | null): void {
  if (channel === "logs") {
    logSocket = socket;
    return;
  }
  notificationSocket = socket;
}

function clearReconnectTimer(channel: RealtimeChannelName): void {
  const timer = reconnectTimers[channel];
  if (typeof timer === "number") {
    window.clearTimeout(timer);
    delete reconnectTimers[channel];
  }
}

function disconnectRealtimeChannels(): void {
  realtimeInitialized = false;
  clearReconnectTimer("logs");
  clearReconnectTimer("notifications");

  for (const channel of ["logs", "notifications"] as const) {
    const socket = getRealtimeSocket(channel);
    setRealtimeSocket(channel, null);
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.close(1000, "client_logout");
    } else if (socket) {
      socket.close();
    }
  }
}

function connectRealtimeChannel(
  channel: RealtimeChannelName,
  path: string,
  onPayload: (payload: any) => void,
): void {
  clearReconnectTimer(channel);
  if (!hasStoredSession()) return;

  const token = getAccessToken();
  if (!token) {
    console.warn(`Skipping realtime ${channel} connection because no access token is available.`);
    return;
  }
  if (getRealtimeSocket(channel)) return;

  const socket = new WebSocket(buildBackendWebSocketUrl(path, { token }));
  setRealtimeSocket(channel, socket);

  socket.onopen = () => {
    reconnectAttempts[channel] = 0;
    console.info(`Realtime ${channel} websocket connected.`);
  };

  socket.onmessage = (event) => {
    try {
      const payload = JSON.parse(String(event.data));
      if (payload?.type === "ping") return;
      onPayload(payload);
    } catch (error) {
      console.warn(`Failed to parse realtime ${channel} payload:`, error);
    }
  };

  socket.onerror = () => {
    console.warn(`Realtime ${channel} websocket errored.`);
  };

  socket.onclose = (event) => {
    if (getRealtimeSocket(channel) === socket) {
      setRealtimeSocket(channel, null);
    }

    if (!realtimeInitialized || !hasStoredSession()) {
      return;
    }

    if (event.code === REALTIME_AUTH_CLOSE_CODE) {
      console.warn(`Realtime ${channel} websocket rejected authentication. Reconnect disabled.`);
      return;
    }

    if (event.code === 1000) {
      return;
    }

    const closeCode = event.code || REALTIME_SERVER_ERROR_CLOSE_CODE;
    if (!REALTIME_RETRYABLE_CLOSE_CODES.has(closeCode)) {
      console.warn(`Realtime ${channel} websocket closed permanently (code=${closeCode}). Reconnect disabled.`);
      return;
    }

    reconnectAttempts[channel] += 1;
    const delay = Math.min(REALTIME_RECONNECT_MAX_MS, REALTIME_RECONNECT_BASE_MS * 2 ** (reconnectAttempts[channel] - 1));
    clearReconnectTimer(channel);
    console.warn(
      `Realtime ${channel} websocket closed (code=${closeCode}). Reconnecting in ${delay}ms.`,
    );
    reconnectTimers[channel] = window.setTimeout(() => {
      connectRealtimeChannel(channel, path, onPayload);
    }, delay);
  };
}

export const useStore = create<AppState>((set, get) => ({
  user: null,
  analytics: null,
  apiKeys: [],
  logs: [],
  auditLogs: [],
  usageSummary: null,
  usageAlertEnabled: getUsageAlertPreference(),
  teamMembers: [],
  notifications: [],
  settings: null,
  reasoningLogs: [],
  isLoading: false,
  auditLogsLoading: false,
  usageLoading: false,
  teamLoading: false,

  initSocket: () => {
    if (realtimeInitialized) return;

    realtimeInitialized = true;
    connectRealtimeChannel("logs", "/ws/logs", (log: any) => {
      const normalizedLog = normalizeLog(log);
      get().addLiveLog(normalizedLog);

      const status = String(normalizedLog?.status || "").toUpperCase();
      const threatType = String(normalizedLog?.threat_type || "UNKNOWN");
      if (status === "BLOCKED" || status === "REDACTED") {
        get().addReasoningLog(`Threat detected: ${threatType}`, "HIGH");
      }
    });
    connectRealtimeChannel("notifications", "/ws/notifications", (notification: any) => {
      const normalizedNotification = normalizeNotification(notification);
      get().addLiveNotification(normalizedNotification);

      if (String(normalizedNotification?.type || "").toUpperCase() === "REMEDIATION") {
        get().addReasoningLog(`Remediation triggered: ${String(normalizedNotification.message || "")}`, "HIGH");
      }
    });
  },

  disconnectRealtime: () => {
    disconnectRealtimeChannels();
  },

  loadMe: async () => {
    if (!hasStoredSession()) {
      set({ user: null });
      return false;
    }
    try {
      const data = await authedFetchJson<any>("/api/v1/auth/me");
      const displayName = getDisplayName();
      set({
        user: {
          id: String(data?.id),
          email: String(data?.email || ""),
          tier: String(data?.tier || "FREE") as any,
          isActive: Boolean(data?.is_active ?? true),
          organizationName: data?.organization_name ? String(data.organization_name) : null,
          name: displayName || (data?.name ? String(data.name) : undefined),
        },
      });
      return true;
    } catch (err) {
      console.error("Failed to load /auth/me:", err);
      set({ user: null });
      return false;
    }
  },

  fetchAnalytics: async () => {
    set({ isLoading: true });
    try {
      const data = await authedFetchJson<Analytics>("/api/v1/analytics");
      set({ analytics: data, isLoading: false });
    } catch (error) {
      if (error instanceof HttpError && error.status === 404) {
        set({ analytics: emptyAnalytics(), isLoading: false });
        return;
      }
      console.error("Failed to fetch analytics:", error);
      set({ isLoading: false });
    }
  },

  fetchApiKeys: async () => {
    set({ isLoading: true });
    try {
      const data = await authedFetchJson<unknown>("/api/v1/keys");
      const apiKeys = extractListPayload<any>(data, ["keys", "api_keys"]).map(normalizeApiKey);
      set({ apiKeys, isLoading: false });
    } catch (error) {
      if (error instanceof HttpError && error.status === 404) {
        set({ apiKeys: [], isLoading: false });
        return;
      }
      console.error("Failed to fetch API keys:", error);
      set((state) => ({ apiKeys: Array.isArray(state.apiKeys) ? state.apiKeys : [], isLoading: false }));
    }
  },

  fetchLogs: async (params?: LogsQueryParams) => {
    set({ isLoading: true });
    try {
      const search = new URLSearchParams();
      const p = params || {};
      if (p.limit != null) search.set("limit", String(p.limit));
      if (p.offset != null) search.set("offset", String(p.offset));
      if (p.status) search.set("status", p.status);
      if (p.threat_type) search.set("threat_type", p.threat_type);
      if (p.api_key_id != null && String(p.api_key_id).length) search.set("api_key_id", String(p.api_key_id));
      if (p.start_time) search.set("start_time", p.start_time);
      if (p.end_time) search.set("end_time", p.end_time);
      if (p.q) search.set("q", p.q);

      const qs = search.toString();
      const data = await authedFetchJson<unknown>(qs ? `/api/v1/logs?${qs}` : "/api/v1/logs");
      const normalized = extractListPayload<any>(data, ["logs"]).map(normalizeLog) as SecurityLog[];
      set({ logs: normalized.slice(0, MAX_LOG_BUFFER), isLoading: false });
    } catch (error) {
      if (error instanceof HttpError && error.status === 404) {
        set({ logs: [], isLoading: false });
        return;
      }
      console.error("Failed to fetch logs:", error);
      set((state) => ({ logs: Array.isArray(state.logs) ? state.logs : [], isLoading: false }));
    }
  },

  fetchAuditLogs: async (params?: AuditLogsQuery) => {
    set({ auditLogsLoading: true });
    try {
      const auditLogs = await fetchAuditLogsApi(params);
      set({ auditLogs, auditLogsLoading: false });
    } catch (error) {
      set({ auditLogsLoading: false });
      throw error;
    }
  },

  fetchUsageSummary: async () => {
    set({ usageLoading: true });
    try {
      const usageSummary = await fetchUsageSummaryApi();
      set({
        usageSummary,
        usageAlertEnabled: usageSummary.notifyAt80,
        usageLoading: false,
      });
    } catch (error) {
      set({ usageLoading: false });
      throw error;
    }
  },

  setUsageAlertEnabled: (enabled: boolean) => {
    setUsageAlertPreference(enabled);
    set((state) => ({
      usageAlertEnabled: enabled,
      usageSummary: state.usageSummary ? { ...state.usageSummary, notifyAt80: enabled } : state.usageSummary,
    }));
  },

  fetchTeamMembers: async () => {
    set({ teamLoading: true });
    try {
      const teamMembers = await fetchTeamMembersApi();
      set({ teamMembers, teamLoading: false });
    } catch (error) {
      set({ teamLoading: false });
      throw error;
    }
  },

  inviteTeamMember: async (payload: TeamInvitePayload) => {
    const optimisticMember: TeamMember = {
      id: `temp-${Date.now()}`,
      name: payload.email.split("@")[0] || "Pending teammate",
      email: payload.email,
      role: payload.role,
      status: "PENDING",
      invite_link: payload.generateInviteLink ? "Generating secure invite link..." : null,
    };

    set((state) => ({
      teamMembers: [optimisticMember, ...state.teamMembers],
    }));

    try {
      const createdMember = await inviteTeamMemberApi(payload);
      set((state) => ({
        teamMembers: state.teamMembers.map((member) => member.id === optimisticMember.id ? createdMember : member),
      }));
      return createdMember;
    } catch (error) {
      set((state) => ({
        teamMembers: state.teamMembers.filter((member) => member.id !== optimisticMember.id),
      }));
      throw error;
    }
  },

  updateTeamMemberRole: async (id: string, role: TeamRole) => {
    const currentMember = get().teamMembers.find((member) => member.id === id);
    if (!currentMember) return;

    set((state) => ({
      teamMembers: state.teamMembers.map((member) => member.id === id ? { ...member, role } : member),
    }));

    try {
      const updatedMember = await updateTeamMemberRoleApi(id, role);
      set((state) => ({
        teamMembers: state.teamMembers.map((member) => member.id === id ? updatedMember : member),
      }));
    } catch (error) {
      set((state) => ({
        teamMembers: state.teamMembers.map((member) => member.id === id ? currentMember : member),
      }));
      throw error;
    }
  },

  removeTeamMember: async (id: string) => {
    const currentMember = get().teamMembers.find((member) => member.id === id);
    if (!currentMember) return;

    set((state) => ({
      teamMembers: state.teamMembers.filter((member) => member.id !== id),
    }));

    try {
      await removeTeamMemberApi(id);
    } catch (error) {
      set((state) => ({
        teamMembers: [currentMember, ...state.teamMembers],
      }));
      throw error;
    }
  },

  fetchNotifications: async () => {
    try {
      const data = await authedFetchJson<unknown>("/api/v1/notifications");
      const notifications = extractListPayload<any>(data, ["notifications"]).map(normalizeNotification);
      set({ notifications });
    } catch (err) {
      if (err instanceof HttpError && err.status === 404) {
        set({ notifications: [] });
        return;
      }
      console.error("Failed to fetch notifications:", err);
    }
  },

  markNotificationRead: async (id: string) => {
    const numericId = Number(id);
    if (!Number.isFinite(numericId)) return;
    try {
      await authedFetch(`/api/v1/notifications/${numericId}/read`, { method: "POST" });
      set((state) => ({
        notifications: state.notifications.map((n) => (n.id === id ? { ...n, is_read: true } : n)),
      }));
    } catch (err) {
      if (err instanceof HttpError && err.status === 404) return;
      console.error("Failed to mark notification read:", err);
    }
  },

  markAllNotificationsRead: async () => {
    try {
      await authedFetch("/api/v1/notifications/read-all", { method: "POST" });
      set((state) => ({ notifications: state.notifications.map((n) => ({ ...n, is_read: true })) }));
    } catch (err) {
      if (err instanceof HttpError && err.status === 404) return;
      console.error("Failed to mark all notifications read:", err);
    }
  },

  fetchSettings: async () => {
    try {
      const data = await authedFetchJson<UserSettings>("/api/v1/settings");
      set({ settings: data });
    } catch (err) {
      console.error("Failed to fetch settings:", err);
      throw err;
    }
  },

  updateSettings: async (patch: Partial<UserSettings>) => {
    try {
      const data = await authedFetchJson<UserSettings>("/api/v1/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
      set({ settings: data });
    } catch (err) {
      console.error("Failed to update settings:", err);
      throw err;
    }
  },

  generateApiKey: async (name: string) => {
    const created = await authedFetchJson<any>("/api/v1/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    if (!created || typeof created !== "object" || created.id == null) {
      throw new Error("The server returned an empty response while creating the API key.");
    }
    const apiKey = normalizeApiKey(created);
    set((state) => ({ apiKeys: [apiKey, ...state.apiKeys] }));
    return apiKey;
  },

  revokeApiKey: async (id: string) => {
    const numericId = Number(id);
    if (!Number.isFinite(numericId)) return;
    try {
      const res = await authedFetch(`/api/v1/keys/${numericId}`, { method: "DELETE" });
      const payload = await res.json().catch(() => null);
      const updated = payload ? unwrapApi<any>(payload) : null;
      if (updated) {
        set((state) => ({
          apiKeys: state.apiKeys.map((k) => (k.id === id ? normalizeApiKey(updated) : k)),
        }));
      } else {
        await get().fetchApiKeys();
      }
    } catch (error) {
      console.error("Failed to revoke API key:", error);
      throw error; // let the caller show a message instead of silently doing nothing
    }
  },

  addLiveLog: (log: SecurityLog) => {
    set((state) => ({
      logs: [normalizeLog(log), ...(Array.isArray(state.logs) ? state.logs : [])].slice(0, MAX_LOG_BUFFER),
    }));
  },

  addReasoningLog: (message: string, threat_level: string) => {
    set((state) => ({
      reasoningLogs: [{ timestamp: new Date().toLocaleTimeString(), message, threat_level }, ...state.reasoningLogs].slice(
        0,
        100
      ),
    }));
  },

  addLiveNotification: (n: NotificationItem) => {
    set((state) => ({
      notifications: [normalizeNotification(n), ...(Array.isArray(state.notifications) ? state.notifications : [])].slice(0, 200),
    }));
  },
}));