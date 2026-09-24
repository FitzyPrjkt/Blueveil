import { afterEach, describe, expect, it, vi } from "vitest";
import { apiFetch, hasApiKey, onAuthRequired, setApiKey } from "./api";

afterEach(() => {
  sessionStorage.clear();
  vi.unstubAllGlobals();
});

function mockFetch(status: number, body: unknown = {}) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  });
  return calls;
}

describe("apiFetch key handling", () => {
  it("attaches the stored key as Bearer", async () => {
    mockFetch(200);
    const calls = mockFetch(200);
    setApiKey("k-secret");
    expect(hasApiKey()).toBe(true);
    await apiFetch("/api/v1/assets");
    const headers = new Headers(calls[0]?.init?.headers);
    expect(headers.get("Authorization")).toBe("Bearer k-secret");
  });

  it("never places credentials in URLs", async () => {
    const calls = mockFetch(200);
    setApiKey("k-secret-in-header-only");
    await apiFetch("/api/v1/assets?status=ACTIVE");
    expect(calls[0]?.url).toBe("/api/v1/assets?status=ACTIVE");
    expect(calls[0]?.url).not.toContain("k-secret");
  });

  it("sends no credential when none is stored", async () => {
    const calls = mockFetch(200);
    await apiFetch("/api/v1/assets");
    const headers = new Headers(calls[0]?.init?.headers);
    expect(headers.get("Authorization")).toBeNull();
  });

  it("notifies on 401 and clears on forget", async () => {
    mockFetch(401, { error: { code: "UNAUTHORIZED", message: "nope" } });
    const seen: boolean[] = [];
    const off = onAuthRequired((v) => seen.push(v));
    setApiKey("k-old");
    await apiFetch("/api/v1/assets");
    expect(seen).toEqual([true]);
    off();
    setApiKey("");
    expect(hasApiKey()).toBe(false);
  });
});
