import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App";
import { setApiKey } from "./api";
import { mockApi } from "./test-utils";

afterEach(() => {
  cleanup();
  sessionStorage.clear();
  setApiKey("");
});

describe("UI lock on 401", () => {
  it("shows the unlock panel when the API demands authentication", async () => {
    mockApi({
      "/api/v1/alerts": {
        status: 401,
        body: { error: { code: "UNAUTHORIZED", message: "auth" } },
      },
      "/api/v1/assets": {
        status: 401,
        body: { error: { code: "UNAUTHORIZED", message: "auth" } },
      },
      "/api/v1/incidents": {
        status: 401,
        body: { error: { code: "UNAUTHORIZED", message: "auth" } },
      },
    });
    render(<App />);
    expect(
      await screen.findByText("Authentication required"),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("API key")).toBeInTheDocument();
  });

  it("stores the key on unlock (session scope only)", async () => {
    const user = userEvent.setup();
    mockApi({
      "/api/v1/alerts": {
        status: 401,
        body: { error: { code: "UNAUTHORIZED", message: "auth" } },
      },
      "/api/v1/assets": {
        status: 401,
        body: { error: { code: "UNAUTHORIZED", message: "auth" } },
      },
      "/api/v1/incidents": {
        status: 401,
        body: { error: { code: "UNAUTHORIZED", message: "auth" } },
      },
    });
    render(<App />);
    await screen.findByText("Authentication required");
    await user.type(screen.getByLabelText("API key"), "k-test");
    await user.click(screen.getByText("Unlock"));
    await waitFor(() =>
      expect(sessionStorage.getItem("blueveil.api.key")).toBe("k-test"),
    );
    // sessionStorage only: the key must never touch persistent storage.
    // (localStorage is asserted where the environment provides it.)
    const ls = typeof localStorage === "undefined" ? null : localStorage;
    expect(ls?.getItem("blueveil.api.key") ?? null).toBeNull();
  });
});
