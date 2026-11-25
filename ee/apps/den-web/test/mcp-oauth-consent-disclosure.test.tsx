import { afterEach, expect, test } from "bun:test"
import { Window } from "happy-dom"
import { createElement, type ComponentType } from "react"
import { createRoot, type Root } from "react-dom/client"

type ClientRecord = {
  client_id: string
  client_name: string
  client_uri: string
  logo_uri: string
  user_id: string | null
}

type FetchCall = {
  url: string
  body: string | null
}

const calls: FetchCall[] = []
let currentClient: ClientRecord
let root: Root | null = null
let dom: Window | null = null

function installDom(url: string) {
  const win = new Window({ url })
  const names = [
    "navigator",
    "HTMLElement",
    "Element",
    "Node",
    "DocumentFragment",
    "Event",
    "MouseEvent",
    "KeyboardEvent",
    "CustomEvent",
    "MutationObserver",
    "HTMLInputElement",
    "HTMLButtonElement",
    "SVGElement",
    "Text",
    "Comment",
    "Document",
    "NodeFilter",
    "DOMParser",
  ]
  globalThis.window = win as unknown as Window & typeof globalThis.window
  globalThis.document = win.document as unknown as Document
  globalThis.navigator = win.navigator
  globalThis.IS_REACT_ACT_ENVIRONMENT = true
  for (const name of names) {
    const value = (win as unknown as Record<string, unknown>)[name]
    if (value !== undefined) {
      ;(globalThis as Record<string, unknown>)[name] = value
    }
  }
  globalThis.getComputedStyle = win.getComputedStyle.bind(win)
  globalThis.requestAnimationFrame = win.requestAnimationFrame.bind(win)
  globalThis.cancelAnimationFrame = win.cancelAnimationFrame.bind(win)
  dom = win
  return win
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

function installFetch(client: ClientRecord) {
  currentClient = client
  calls.length = 0
  const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url
    const body = typeof init?.body === "string" ? init.body : null
    calls.push({ url, body })

    if (url.includes("/api/den/v1/me/orgs")) {
      return jsonResponse({
        orgs: [{
          id: "org_victim",
          name: "Victim Workspace",
          slug: "victim",
          role: "owner",
          isActive: true,
        }],
      })
    }

    if (url.includes("/api/auth/oauth2/public-client")) {
      return jsonResponse(currentClient)
    }

    if (url.includes("/api/auth/organization/set-active")) {
      return jsonResponse({ ok: true })
    }

    if (url.includes("/api/auth/oauth2/consent")) {
      return jsonResponse({ url: "https://attacker.example/cb?code=placeholder" })
    }

    return jsonResponse({ error: "not_found" }, 404)
  }
  globalThis.fetch = fetchImpl as typeof fetch
  window.fetch = fetchImpl as typeof fetch
}

async function flush() {
  const { act } = await import("react")
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 30))
  })
}

function authorizeButton(container: ParentNode) {
  return [...container.querySelectorAll("button")].find((button) => {
    const label = button.textContent ?? ""
    return /authorize/i.test(label) && !/cancel|deny/i.test(label)
  }) ?? null
}

async function renderConsent(page: ComponentType, search: string, client: ClientRecord) {
  const { act } = await import("react")
  const win = installDom(`http://127.0.0.1:3005/mcp/consent?${search}`)
  installFetch(client)
  const container = win.document.createElement("div")
  win.document.body.appendChild(container)
  root = createRoot(container)
  await act(async () => {
    root?.render(createElement(page))
  })
  return container
}

async function waitUntilAuthorizeEnabled(container: ParentNode) {
  const deadline = Date.now() + 2000
  let button = authorizeButton(container)
  while (Date.now() < deadline) {
    button = authorizeButton(container)
    if (button && !button.disabled) return button
    await flush()
  }
  return button
}

afterEach(() => {
  root?.unmount()
  root = null
  dom?.close()
  dom = null
})

const attackQuery = new URLSearchParams({
  response_type: "code",
  client_id: "client-attacker",
  redirect_uri: "https://attacker.example/cb",
  scope: "openid profile email offline_access mcp:read mcp:write",
  code_challenge: "placeholder-challenge",
  code_challenge_method: "S256",
  state: "state-placeholder",
  client_name: "OpenWork Official",
}).toString()

const dynamicClient: ClientRecord = {
  client_id: "client-attacker",
  client_name: "Hostile Connector",
  client_uri: "https://brand.example",
  logo_uri: "https://attacker.example/logo.png",
  user_id: null,
}

const ownedClient: ClientRecord = {
  ...dynamicClient,
  client_id: "client-owned",
  client_name: "Workspace Connector",
  user_id: "usr_owner",
}

async function expectDisclosure(page: ComponentType, client: ClientRecord, search: string) {
  const container = await renderConsent(page, search, client)
  const button = await waitUntilAuthorizeEnabled(container)

  expect(button).not.toBeNull()
  expect(button?.disabled).toBe(false)
  expect(container.querySelector("[data-oauth-client-name]")?.textContent?.trim()).toBe(client.client_name)
  expect(container.querySelector("[data-oauth-client-id]")?.textContent?.trim()).toBe(client.client_id)
  expect(container.querySelector("[data-oauth-redirect-host]")?.textContent?.trim()).toBe("attacker.example")
  expect(container.querySelector("[data-oauth-client-trust]")?.textContent?.trim().toLowerCase()).toBe(client.user_id ? "verified" : "unverified")
  expect(container.querySelector("[data-oauth-scopes]")?.textContent ?? "").toContain("mcp:write")
  expect(container.querySelector("[data-oauth-scopes]")?.textContent ?? "").toContain("mcp:read")
  expect(container.querySelector(`img[src="${client.logo_uri}"]`)).not.toBeNull()
  expect(calls.some((call) => call.url.includes("/api/auth/oauth2/public-client") && call.url.includes(client.client_id))).toBe(true)

  button?.click()
  await flush()

  const consent = calls.find((call) => call.url.includes("/api/auth/oauth2/consent") && call.body?.includes('"accept":true'))
  expect(consent?.body).toBeTruthy()
  const posted = JSON.parse(consent?.body ?? "{}") as { oauth_query?: string }
  const postedQuery = new URLSearchParams(posted.oauth_query ?? "")
  expect(new URL(postedQuery.get("redirect_uri") ?? "").host).toBe(
    container.querySelector("[data-oauth-redirect-host]")?.textContent?.trim(),
  )
  expect(postedQuery.get("client_id")).toBe(client.client_id)
}

test("workspace consent screen identifies the requesting client before authorization", async () => {
  const page = (await import("../app/mcp/select-organization/page.tsx")).default
  await expectDisclosure(page, dynamicClient, attackQuery)
})

test("workspace consent screen marks an owned client as verified", async () => {
  const page = (await import("../app/mcp/select-organization/page.tsx")).default
  const search = new URLSearchParams(attackQuery)
  search.set("client_id", ownedClient.client_id)
  await expectDisclosure(page, ownedClient, search.toString())
})

test("legacy mcp consent screen identifies the requesting client before authorization", async () => {
  const page = (await import("../app/mcp/consent/page.tsx")).default
  await expectDisclosure(page, dynamicClient, attackQuery)
})
