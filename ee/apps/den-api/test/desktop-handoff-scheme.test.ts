import assert from "node:assert/strict"
import { after, before, test } from "node:test"
import {
  closeHandoffDb,
  countHandoffGrants,
  createDesktopHandoff,
  createHandoffApp,
  desktopSchemeOf,
  exchangeDesktopHandoff,
  exclusive,
  isAllowedDesktopScheme,
  PLACEHOLDER_SESSION_TOKEN,
  seedVictimSession,
  sessionFromBearer,
  VICTIM_EMAIL,
} from "./desktop-handoff-harness.js"

const app = createHandoffApp()

const UNTRUSTED_SCHEMES = [
  "web+owgrab",
  "WEB+OWGRAB",
  "https",
  "http",
  "javascript",
  "data",
  "file",
  "openwork.attacker",
  "openwork-dev.attacker",
  "openwork+evil",
  "openwork-attacker",
]

before(async () => {
  await seedVictimSession()
})

after(async () => {
  await closeHandoffDb()
})

test("allowlisted desktop schemes still mint a grant the desktop app can exchange", async () => {
  await exclusive(async () => {
    for (const desktopScheme of ["openwork", "OpenWork", "openwork-dev", "OPENWORK-DEV"]) {
      const victim = await seedVictimSession(`${PLACEHOLDER_SESSION_TOKEN}-${desktopScheme}`)
      const beforeCount = await countHandoffGrants()
      const response = await createDesktopHandoff(app, victim.token, desktopScheme)
      assert.equal(response.status, 200)
      const body = await response.json() as { openworkUrl?: string; grant?: string }
      const openworkUrl = body.openworkUrl ?? ""
      const scheme = desktopSchemeOf(openworkUrl)
      assert.equal(scheme, desktopScheme.toLowerCase())
      assert.ok(isAllowedDesktopScheme(scheme))
      assert.equal(await countHandoffGrants(), beforeCount + 1)

      const grant = new URL(openworkUrl).searchParams.get("grant") ?? ""
      assert.equal(grant, body.grant)
      const exchange = await exchangeDesktopHandoff(app, grant)
      assert.equal(exchange.status, 200)
      const exchanged = await exchange.json() as { token?: string; user?: { email?: string } }
      assert.equal(exchanged.token, victim.token)
      assert.equal(exchanged.user?.email, VICTIM_EMAIL)

      const session = await sessionFromBearer(exchanged.token ?? "")
      assert.equal(session?.user?.email, VICTIM_EMAIL)
      assert.equal(session?.session?.token, victim.token)
    }
  })
})

test("omitted desktop scheme stays on the registered openwork scheme", async () => {
  await exclusive(async () => {
    const victim = await seedVictimSession(`${PLACEHOLDER_SESSION_TOKEN}-default`)
    const response = await createDesktopHandoff(app, victim.token)
    assert.equal(response.status, 200)
    const body = await response.json() as { openworkUrl?: string }
    assert.equal(desktopSchemeOf(body.openworkUrl ?? ""), "openwork")
  })
})

test("an untrusted desktop scheme cannot deliver a redeemable session grant", async () => {
  await exclusive(async () => {
    for (const desktopScheme of UNTRUSTED_SCHEMES) {
      const victim = await seedVictimSession(`${PLACEHOLDER_SESSION_TOKEN}-untrusted`)
      const beforeCount = await countHandoffGrants()
      const response = await createDesktopHandoff(app, victim.token, desktopScheme)
      const body = await response.json() as { openworkUrl?: string; grant?: string; error?: string }
      const openworkUrl = typeof body.openworkUrl === "string" ? body.openworkUrl : ""
      const deliveredScheme = openworkUrl ? desktopSchemeOf(openworkUrl) : null

      let redeemedUntrustedGrant = false
      if (openworkUrl && deliveredScheme && !isAllowedDesktopScheme(deliveredScheme)) {
        const grant = new URL(openworkUrl).searchParams.get("grant") ?? ""
        const exchange = await exchangeDesktopHandoff(app, grant)
        const exchanged = exchange.ok
          ? await exchange.json() as { token?: string }
          : null
        redeemedUntrustedGrant = exchanged?.token === victim.token
      }

      if (!response.ok) {
        assert.equal(
          await countHandoffGrants(),
          beforeCount,
          `${desktopScheme} was refused after a handoff grant was stored`,
        )
        assert.equal(body.grant, undefined)
        assert.equal(body.openworkUrl, undefined)
      }

      assert.equal(redeemedUntrustedGrant, false, `${desktopScheme} grant was exchanged for the victim session`)
      assert.ok(
        !deliveredScheme || isAllowedDesktopScheme(deliveredScheme),
        `${desktopScheme} was copied into the handoff URL`,
      )
      if (response.ok) {
        assert.notEqual(deliveredScheme, desktopScheme.toLowerCase())
      }
    }
  })
})

test("exchange without a grant does not return a session", async () => {
  await exclusive(async () => {
    await seedVictimSession()
    const exchange = await exchangeDesktopHandoff(app, "placeholder-grant-value")
    assert.equal(exchange.status, 404)
    const body = await exchange.json() as { token?: string }
    assert.equal(body.token, undefined)
  })
})
