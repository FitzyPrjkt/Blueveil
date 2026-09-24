// Shared fetch mock: routes map path → JSON body (or {status, body}).
// Unmatched paths 404 like the real API would for unknown ids.
export function mockApi(routes: Record<string, unknown>) {
  (globalThis as Record<string, unknown>).fetch = (async (
    input: RequestInfo | URL,
  ) => {
    const path = typeof input === "string" ? input : input.toString();
    const clean = path.split("?")[0] ?? path;
    if (Object.hasOwn(routes, clean)) {
      const v = routes[clean] as { status?: unknown; body?: unknown };
      if (
        v !== null &&
        typeof v === "object" &&
        typeof v.status === "number" &&
        "body" in v
      ) {
        return new Response(JSON.stringify(v.body), {
          status: v.status,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify(routes[clean]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(
      JSON.stringify({ error: { code: "NOT_FOUND", message: "no mock" } }),
      {
        status: 404,
        headers: { "Content-Type": "application/json" },
      },
    );
  }) as typeof fetch;
}

export function mockApiError(code: string, message: string, status = 500) {
  (globalThis as Record<string, unknown>).fetch = (async () =>
    new Response(JSON.stringify({ error: { code, message } }), {
      status,
      headers: { "Content-Type": "application/json" },
    })) as typeof fetch;
}

export function mockApiFailure() {
  (globalThis as Record<string, unknown>).fetch = (async () => {
    throw new TypeError("fetch failed");
  }) as typeof fetch;
}
