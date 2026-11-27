import "../../den-api/test/desktop-handoff-env.js"
import assert from "node:assert/strict"
import { createServer, type IncomingMessage, type ServerResponse } from "node:http"
import { once } from "node:events"
import { after, test } from "node:test"
import { act, createElement, useEffect } from "react"
import { createRoot, type Root } from "react-dom/client"
import { Window } from "happy-dom"
import {
  closeHandoffDb,
  createHandoffApp,
  desktopSchemeOf,
  exclusive,
  isAllowedDesktopScheme,
  PLACEHOLDER_SESSION_TOKEN,
  seedVictimSession,
  VICTIM_EMAIL,
} from "../../den-api/test/desktop-handoff-harness.js"

const ATTACK_URL = "https://app.openworklabs.com/?desktopAuth=1&desktopScheme=web%2Bowgrab&mode=sign-in"
const nodeFetch = globalThis.fetch.bind(globalThis)

type RecordedRequest = {
  url: string
  body: string
}

const handoffPosts: RecordedRequest[] = []
const socialPosts: RecordedRequest[] = []
const assignments: string[] = []

let server: ReturnType<typeof createServer> | null = null
let apiBase = ""

async function readRequestBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  }
  return Buffer.concat(chunks)
}

async function startApi() {
  const app = createHandoffApp()
  server = createServer(async (request: IncomingMessage, response: ServerResponse) => {
    const body = request.method === "GET" || request.method === "HEAD" ? undefined : await readRequestBody(request)
    const headers = new Headers()
    for (const [key, value] of Object.entries(request.headers)) {
      if (Array.isArray(value)) {
        headers.set(key, value.join(", "))
      } else if (value) {
        headers.set(key, value)
      }
    }
    const upstream = await app.request(`http://den.local${request.url ?? "/"}`, {
      method: request.method,
      headers,
      body,
    })
    response.statusCode = upstream.status
    upstream.headers.forEach((value, key) => {
      response.setHeader(key, value)
    })
    response.end(Buffer.from(await upstream.arrayBuffer()))
  })
  server.listen(0, "127.0.0.1")
  await once(server, "listening")
  const address = server.address()
  if (!address || typeof address === "string") {
    throw new Error("Handoff API test server did not bind a port")
  }
  apiBase = `http://127.0.0.1:${address.port}`
  process.env.DEN_API_BASE = apiBase
  process.env.DEN_AUTH_FALLBACK_BASE = apiBase
}

function installBrowser(searchUrl: string) {
  const window = new Window({
    url: searchUrl,
    settings: {
      disableJavaScriptFileLoading: true,
      disableCSSFileLoading: true,
    },
  })
  window.localStorage.setItem("openwork:web:auth-token", PLACEHOLDER_SESSION_TOKEN)
  const assign = (value: string | URL) => {
    assignments.push(String(value))
  }
  Object.defineProperty(window.location, "assign", {
    configurable: true,
    value: assign,
  })
  const globals = globalThis as typeof globalThis & Record<string, unknown>
  globals.window = window
  globals.document = window.document
  globals.HTMLElement = window.HTMLElement
  globals.Element = window.Element
  globals.Node = window.Node
  globals.navigator = window.navigator
  globals.localStorage = window.localStorage
  globals.sessionStorage = window.sessionStorage
  globals.IS_REACT_ACT_ENVIRONMENT = true
  globals.MutationObserver = window.MutationObserver
  globals.getComputedStyle = window.getComputedStyle.bind(window)
  globals.requestAnimationFrame = (callback: FrameRequestCallback) => window.setTimeout(() => callback(Date.now()), 0)
  globals.cancelAnimationFrame = (handle: number) => window.clearTimeout(handle)
  globals.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url
    const parsed = new URL(url, window.location.origin)
    if (parsed.origin === new URL(apiBase).origin) {
      return nodeFetch(input, init)
    }
    const body = typeof init?.body === "string" ? init.body : ""
    if (parsed.pathname === "/api/den/v1/auth/desktop-handoff") {
      handoffPosts.push({ url: parsed.toString(), body })
    }
    if (parsed.pathname === "/api/auth/sign-in/social") {
      socialPosts.push({ url: parsed.toString(), body })
    }
    if (
      parsed.pathname === "/api/den/v1/me"
      || parsed.pathname === "/api/den/v1/auth/desktop-handoff"
      || parsed.pathname === "/api/auth/sign-in/social"
    ) {
      const { GET, POST } = await import("../app/api/den/[...path]/route.js")
      const { NextRequest } = await import("next/server")
      const headers = new Headers(init?.headers)
      const method = init?.method ?? "GET"
      const request = new NextRequest(`https://app.openworklabs.com${parsed.pathname}${parsed.search}`, {
        method,
        headers,
        body: method === "GET" || method === "HEAD" ? undefined : body,
      })
      if (parsed.pathname.startsWith("/api/den/")) {
        return method === "POST" ? POST(request) : GET(request)
      }
      return new Response(JSON.stringify({ url: "https://github.com/login/oauth/authorize?client_id=placeholder" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    }
    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    })
  }) as typeof fetch
  return window
}

async function flush() {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 30))
  })
}

function callbackScheme(body: string): string | null {
  const payload = JSON.parse(body) as { callbackURL?: string }
  if (!payload.callbackURL) {
    return null
  }
  return new URL(payload.callbackURL).searchParams.get("desktopScheme")
}

let root: Root | null = null

after(async () => {
  root?.unmount()
  if (server) {
    server.close()
    await once(server, "close")
  }
  await closeHandoffDb()
})

test("a signed-in cloud page does not hand a session grant to an untrusted desktop scheme", async () => {
  await exclusive(async () => {
    handoffPosts.length = 0
    assignments.length = 0
    await startApi()
    const victim = await seedVictimSession(PLACEHOLDER_SESSION_TOKEN)
    assert.equal(victim.email, VICTIM_EMAIL)
    const window = installBrowser(ATTACK_URL)
    const { DenFlowProvider } = await import("../app/(den)/_providers/den-flow-provider.js")
    root = createRoot(window.document.createElement("div"))
    await act(async () => {
      root?.render(createElement(DenFlowProvider, null, createElement("div")))
    })
    await flush()
    await flush()
    await flush()

    const postedSchemes = handoffPosts.map((post) => {
      const payload = JSON.parse(post.body) as { desktopScheme?: string }
      return payload.desktopScheme ?? ""
    })
    const assignedSchemes = assignments.map((value) => desktopSchemeOf(value) ?? "unparsed")
    assert.deepEqual(
      { posts: postedSchemes, navigations: assignedSchemes },
      { posts: [], navigations: [] },
      "desktop handoff ran without a confirmation click",
    )

    const buttons = [...window.document.querySelectorAll("button")]
    const confirm = buttons.find((button) => /openwork/i.test(button.textContent ?? ""))
    if (confirm) {
      await act(async () => {
        confirm.dispatchEvent(new window.MouseEvent("click", { bubbles: true }))
      })
      await flush()
      await flush()
    }

    for (const post of handoffPosts) {
      const payload = JSON.parse(post.body) as { desktopScheme?: string }
      assert.ok(
        isAllowedDesktopScheme(payload.desktopScheme),
        "handoff request kept an untrusted desktopScheme",
      )
    }
    for (const assignment of assignments) {
      assert.ok(
        isAllowedDesktopScheme(desktopSchemeOf(assignment)),
        "navigation used an untrusted desktop scheme",
      )
    }
  })
})

test("social sign-in does not carry an untrusted desktop scheme through the callback", async () => {
  await exclusive(async () => {
    socialPosts.length = 0
    assignments.length = 0
    if (!apiBase) {
      await startApi()
    }
    const window = installBrowser(ATTACK_URL)
    const { DenFlowProvider, useDenFlow } = await import("../app/(den)/_providers/den-flow-provider.js")
    const { getSocialCallbackUrl } = await import("../app/(den)/_lib/den-flow.js")

    function StartSocialAuth() {
      const flow = useDenFlow()
      useEffect(() => {
        void flow.beginSocialAuth("github")
      }, [flow])
      return null
    }

    root?.unmount()
    root = createRoot(window.document.createElement("div"))
    await act(async () => {
      root?.render(createElement(DenFlowProvider, null, createElement(StartSocialAuth)))
    })
    await flush()
    await flush()

    const directScheme = new URL(getSocialCallbackUrl()).searchParams.get("desktopScheme")
    const postedSchemes = socialPosts.map((post) => callbackScheme(post.body))
    assert.ok(socialPosts.length > 0, "social sign-in did not post a callback URL")
    assert.deepEqual(
      {
        helper: directScheme === null || isAllowedDesktopScheme(directScheme) ? null : directScheme,
        posted: postedSchemes.filter((scheme) => scheme && !isAllowedDesktopScheme(scheme)),
      },
      { helper: null, posted: [] },
      "social sign-in kept an untrusted desktopScheme",
    )
  })
})
