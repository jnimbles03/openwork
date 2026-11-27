import type { createApp } from "../app-factory.js";

export const TEST_HOST_TOKEN = "placeholder-test-host-token";

/** Sends the test host token on every in-process request that does not already carry credentials. */
export function authorizeRequests<T extends ReturnType<typeof createApp>>(app: T, token = TEST_HOST_TOKEN): T {
  const request = app.request.bind(app);
  app.request = ((input, init, env, executionCtx) => {
    const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
    if (!headers.has("authorization") && !headers.has("x-openwork-host-token")) {
      headers.set("X-OpenWork-Host-Token", token);
    }
    return request(input, { ...init, headers }, env, executionCtx);
  }) as T["request"];
  return app;
}
