import { useEffect, useState } from "react";
import { ApiError, apiFetch } from "../api";

export type LoadState<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T[] }
  | { kind: "empty" }
  | { kind: "backend-error"; message: string }
  | { kind: "invalid"; message: string };

// listOf normalizes ready|empty to an array (possibly empty); loading and
// error states yield null so callers cannot mistake them for empty data.
export function listOf<T>(s: LoadState<T>): T[] | null {
  if (s.kind === "ready") return s.data;
  if (s.kind === "empty") return [];
  return null;
}

export type LoadOne<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T }
  | { kind: "backend-error"; message: string }
  | { kind: "invalid"; message: string };

// useApiObject: same state discipline as useApiList for single-object
// envelopes (relationships, findings bundles).
export function useApiObject<T>(
  path: string | null,
  parse: (v: unknown) => T,
): LoadOne<T> {
  const [state, setState] = useState<LoadOne<T>>({ kind: "loading" });
  useEffect(() => {
    if (!path) return;
    let cancelled = false;
    setState({ kind: "loading" });
    (async () => {
      try {
        const res = await apiFetch(path);
        const body: unknown = await res.json().catch(() => {
          throw new ApiError(
            "INVALID",
            `non-JSON response from ${path}`,
            res.status,
          );
        });
        if (!res.ok) {
          const err = (body as { error?: { code?: string; message?: string } })
            .error;
          throw new ApiError(
            err?.code ?? "BACKEND",
            err?.message ?? `request failed: ${path}`,
            res.status,
          );
        }
        const obj = body as { data?: unknown };
        if (obj?.data === undefined)
          throw new ApiError("INVALID", `bad envelope from ${path}`, 200);
        let parsed: T;
        try {
          parsed = parse(obj.data);
        } catch (e) {
          throw new ApiError(
            "INVALID",
            `${path}: ${(e as Error).message}`,
            200,
          );
        }
        if (!cancelled) setState({ kind: "ready", data: parsed });
      } catch (e) {
        if (cancelled) return;
        if (e instanceof ApiError) {
          if (e.code === "INVALID")
            setState({ kind: "invalid", message: e.message });
          else setState({ kind: "backend-error", message: e.message });
        } else {
          setState({ kind: "backend-error", message: String(e) });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [path, parse]);
  return state;
}

// useApiList: loading → ready | empty | backend-error | invalid. Backend
// failure and invalid payloads are NEVER rendered as empty tables.
export function useApiList<T>(
  path: string | null,
  parse: (v: unknown) => T,
): LoadState<T> {
  const [state, setState] = useState<LoadState<T>>({ kind: "loading" });
  useEffect(() => {
    if (!path) {
      setState({ kind: "empty" });
      return;
    }
    let cancelled = false;
    setState({ kind: "loading" });
    (async () => {
      try {
        const res = await apiFetch(path);
        let body: unknown;
        try {
          body = await res.json();
        } catch {
          throw new ApiError(
            "INVALID",
            `non-JSON response from ${path}`,
            res.status,
          );
        }
        if (!res.ok) {
          const err = (body as { error?: { code?: string; message?: string } })
            .error;
          throw new ApiError(
            err?.code ?? "BACKEND",
            err?.message ?? `request failed: ${path}`,
            res.status,
          );
        }
        const obj = body as { data?: unknown };
        if (!Array.isArray(obj?.data))
          throw new ApiError("INVALID", `bad envelope from ${path}`, 200);
        const items = obj.data.map((item, i) => {
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
        if (!cancelled)
          setState(
            items.length === 0
              ? { kind: "empty" }
              : { kind: "ready", data: items },
          );
      } catch (e) {
        if (cancelled) return;
        if (e instanceof ApiError) {
          if (
            e.code === "NETWORK" ||
            e.code === "BACKEND" ||
            e.code === "INTERNAL" ||
            e.code === "NOT_FOUND" ||
            e.code === "INTEGRITY_FAILURE" ||
            e.code === "METHOD_NOT_ALLOWED"
          ) {
            setState({ kind: "backend-error", message: e.message });
          } else {
            setState({ kind: "invalid", message: e.message });
          }
        } else {
          setState({ kind: "backend-error", message: String(e) });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [path, parse]);
  return state;
}

export function fmtTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}
