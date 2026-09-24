// Typed API client. Every response passes through a contracts.ts parser:
// NETWORK (fetch throws) vs BACKEND (error envelope) vs INVALID (parse
// throws) stay three distinct UI states. Same-origin: the Go binary serves
// both UI and API, so no base URL configuration exists.
export class ApiError extends Error {
  code: string;
  httpStatus: number;
  constructor(code: string, message: string, httpStatus: number) {
    super(message);
    this.code = code;
    this.httpStatus = httpStatus;
  }
}

const KEY_STORAGE = "blueveil.api.key";

// apiFetch is the single fetch surface for API calls: it attaches the
// stored API key (session scope, never persisted to disk) and reports
// 401s so the shell can show the unlock panel exactly once.
type AuthListener = (needsKey: boolean) => void;
const authListeners = new Set<AuthListener>();
let needsKey = false;

function notifyAuth(required: boolean) {
  if (required === needsKey) return;
  needsKey = required;
  for (const fn of authListeners) fn(required);
}

export function onAuthRequired(fn: AuthListener): () => void {
  authListeners.add(fn);
  return () => {
    authListeners.delete(fn);
  };
}

export function isAuthRequired(): boolean {
  return needsKey;
}

export function setApiKey(key: string) {
  if (key) sessionStorage.setItem(KEY_STORAGE, key);
  else sessionStorage.removeItem(KEY_STORAGE);
  notifyAuth(false);
}

export function hasApiKey(): boolean {
  return sessionStorage.getItem(KEY_STORAGE) !== null;
}

export async function apiFetch(
  path: string,
  init?: RequestInit,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  const key = sessionStorage.getItem(KEY_STORAGE);
  if (key) headers.set("Authorization", `Bearer ${key}`);
  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) notifyAuth(true);
  return res;
}

async function fetchJSON(path: string): Promise<unknown> {
  let res: Response;
  try {
    res = await apiFetch(path);
  } catch (e) {
    throw new ApiError(
      "NETWORK",
      `cannot reach Blueveil API (${String(e)})`,
      0,
    );
  }
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    throw new ApiError("INVALID", `non-JSON response from ${path}`, res.status);
  }
  if (!res.ok) {
    const err = (body as { error?: { code?: string; message?: string } }).error;
    throw new ApiError(
      err?.code ?? "BACKEND",
      err?.message ?? `request failed: ${path}`,
      res.status,
    );
  }
  return body;
}

function dataList<T>(
  body: unknown,
  path: string,
  parse: (v: unknown) => T,
): T[] {
  const obj = body as { data?: unknown };
  if (!Array.isArray(obj?.data))
    throw new ApiError("INVALID", `bad envelope from ${path}`, 200);
  return obj.data.map((item, i) => {
    try {
      return parse(item);
    } catch (e) {
      throw new ApiError(
        "INVALID",
        `item ${i} from ${path}: ${(e as Error).message}`,
        200,
      );
    }
  });
}

function dataItem<T>(body: unknown, path: string, parse: (v: unknown) => T): T {
  const obj = body as { data?: unknown };
  if (obj?.data === undefined)
    throw new ApiError("INVALID", `bad envelope from ${path}`, 200);
  try {
    return parse(obj.data);
  } catch (e) {
    throw new ApiError("INVALID", `${path}: ${(e as Error).message}`, 200);
  }
}

export const api = {
  async list<T>(path: string, parse: (v: unknown) => T): Promise<T[]> {
    return dataList(await fetchJSON(path), path, parse);
  },
  async get<T>(path: string, parse: (v: unknown) => T): Promise<T> {
    return dataItem(await fetchJSON(path), path, parse);
  },
  async health(): Promise<void> {
    await fetchJSON("/api/v1/healthz");
  },
};
