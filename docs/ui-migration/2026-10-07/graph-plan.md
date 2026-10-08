# Warm Precision frontend migration

Labs visual identity was subsequently replaced by the independent studio design; see `labs-redesign/plan.md` and its source fingerprint for current Labs evidence. Perp is unchanged.

## Contract
- Source: https://github.com/Arcora-labs/arcora-perp, main 73e87c18d2431e7b0815906c216c7fd99db61dea, verified with ls-remote. Dedicated clone and feat/warm-precision-ui branch. Original dirty checkout untouched.
- Design: Arcora-Warm-Precision-UI-Motion.zip SHA256 985f8e72535a125422ae07932f82e3e4329d4357f44999ed8b4af2a2c2403dea.
- Deliverable: integrated landing and complete responsive frontend using supplied design, preserving existing protocol adapters and account/receipt semantics. English Arcora Labs portfolio with all five project links. Production deployments to Vercel and the two named domains are explicitly authorized by the follow-up request. User selected an explicitly labeled browser demo, with gateway integration deferred. Preserve dirty original checkout. No merge, financial transaction or startup application submission.
- Design contract: canvas #FAF7F2, surface #FFFEFB, ink #292523, coral #F47B60, apricot #FFBF78, line #E8E0D8; bundled Inter (reference fallback) plus mono for identifiers. Left sidebar, horizontal market summary, chart/pulse/ticket, finality and account tables. Mobile Chart/Trade/Activity. Follow supplied direction rather than invent a new look.
- Budget: initial implementation plus up to two targeted correction rounds per check; a further round requires a new documented cause.

## Acceptance and graph
| Node | Input / responsibility / output | Validator | Side effects | Transition |
|---|---|---|---|---|
| N1 | Current repository + ZIP -> feature inventory and source identity | Git remote, ZIP integrity, source review | Read + isolated clone | PASS -> N2 |
| N2 | Inventory -> theme, shell, landing, responsive page integration | Build, design comparison | Local frontend/docs/assets edits | PASS -> N3; FAIL -> repair |
| N3 | Existing adapters -> complete search, navigation, review/error states | Relevant unit regressions + real browser interaction | Local frontend edits only | PASS -> N4; FAIL -> two targeted repairs |
| N4 | Integrated source -> verified desktop/mobile + original regression suite | Unit tests, browser tests, console/assets, screenshots, fingerprint | Local processes/evidence | PASS -> N5 |
| N5 | Verified output -> two staged production deployments | Artifact inventory, Vercel READY, HTTP and production browser checks | Prebuilt static deployment; no backend mutation | PASS -> N6 |
| N6 | Tested production -> custom domains and source handoff | Promotion, DNS verification, public HTTP, GitHub branch/PR | Existing DNS record transition, branch push/draft PR | PASS -> delivery; explicit platform confirmation -> affected DNS branch BLOCKED |

## Feature coverage (required)
| Surface | Existing behavior to preserve | New package mapping |
|---|---|---|
| Entry | Current trading app | Landing, film with captions, docs, design system, launch app |
| Trade | Market selection, chart intervals/drawings, book price prefill | Search, summary, chart, private market pulse, ticket |
| Orders | Bigint size/price, TIF, reduce-only, receipt finality, cancellation | Order review; account/read/mode changes guarded; history/receipt detail |
| Portfolio | Account health, positions, deposits, withdrawals, claims, deposit recovery | Portfolio / Account warm styling |
| Recovery | Wallet-authorized credential rotation, storage warnings | Dedicated recovery navigation |
| Vault | Capability-gated LP demo and unsupported gateway state | Vault navigation and styling |
| Explorer | Batches, chain and execution evidence | Explorer navigation and styling |
| Health | Oracle/settlement/attestation status | Health navigation and styling |
| API | API access guidance / capabilities | API navigation and styling |
| Global | Wallet and test environment, notifications, unavailable states, CloseOnly | Warm shell, keyboard, mobile, reduced motion, gateway retry |

## Current status
N1–N6 PASS. DONE for the authorized browser-demo and portfolio release. Both production builds are promoted, and arcoralabs.xyz and perp.arcoralabs.xyz are verified over public HTTPS. Source delivered in draft PR #28; no merge performed.

## Current evidence
- Source: source-fingerprint.json (154 frontend/site files; SHA-256 724d6569ada31c09cd3511b23e716eaca5ce1142db7a28ae15dadd909d8f0f00). pnpm lockfile unchanged. Node 24.12.0; Vite 6.4.3; Playwright 1.58.2; Vercel CLI 59.16.0.
- Baseline: 481 passed / 1 skipped. Final: 488 passed / 1 skipped (unit-final.log). The existing live-gateway sealed-order test requires GATEWAY_URL and is intentionally outside this authorized demo release.
- Production compilation: build.log and vercel-build-perp.log; exact same hashed CSS/JS. No dependencies added. Static output has no source maps, .env files, node_modules or application source.
- Browser regressions: 78 passed in Chromium and WebKit (browser-regression-final.log). Uses real browsers against synthetic wallet/HTTP fixtures, not real-chain evidence.
- UI and Labs checks: ui-browser.log, labs-browser.log, chart-mode-browser.log. Six widths (360,390,760,1024,1440,1600); no overflow, broken images or page errors. Order review/confirmation/receipt, search, every navigation destination, mobile panels, film/captions, reduced motion, MA/fullscreen, globally visible CloseOnly checked.
- Production: perp-custom-domain-browser.log on perp.arcoralabs.xyz (all checks pass, zero page errors); perp-custom-domain-http.json confirms the HTML, docs, design system and compiled CSS/JS match the tested build byte-for-byte. domain-perp-final.json reports configured-correctly. Earlier perp-live-browser.log on arcora-perp.vercel.app; labs-live-browser.log on arcoralabs.xyz. Corresponding deployment and promote logs identify immutable releases.
- Perp: dpl_L9Frjuj7NWpBta8LuPhqivizsTSc, https://arcora-perp-beqyzo4z2-kubudak90s-projects.vercel.app.
- Labs: dpl_43bZmmXs5988pd51uZJMxXbFi18o, https://arcora-labs-11711o9in-kubudak90s-projects.vercel.app.

## Repairs and limits
- Updated old navigation test expectations without weakening protocol checks; new order confirmation regressions cover bigint sizing, cancel, changed market/mode, unreadable account, double submission and rejection. Unreadable account summary shows unavailable values instead of zero.
- Corrected narrow-screen chart toolbar and decorative Labs orbit overflow; all widths now pass. Headed screenshot capture timed out under local desktop load; headless Chromium completed equivalent interaction checks and captures. Full-page tiled screenshot artifact was reviewed with a separate viewport capture at the project section (DOM has one hero and five projects).
- Initial nested Labs `vercel build` produced an empty output because the configured monorepo root was applied twice. Rebuilt in isolated labs-release root with apps/labs-site intact; inspected nine allowlisted static files before upload. Empty output was not deployed.
- Gateway remains deferred by user decision. No claim of real settlement, attestation verification, live-chain trading, or production fund custody.
- Domain completed: the user changed existing perp A record rec_8d38154e72f2109aeb21b63f from 104.42.53.250 to Vercel's rank-1 recommended A target 216.198.79.1 after interactive confirmation. The earlier attempt to change the record type to CNAME was rejected by Vercel. Keeping type A and updating only its value succeeded. Public DNS, Vercel verification, HTTPS, artifact identity and full browser flow all pass. Mail DNS and other projects are untouched.

## Reproduction and release
Perp: from repository root, `vercel link --project arcora-perp --scope kubudak90s-projects`, `vercel pull --yes --environment=production`, `vercel build --prod`; inspect .vercel/output/static, then `vercel deploy --prebuilt --prod --skip-domain`. Keep VITE_API_URL empty for this demo. Promote the tested immutable production URL.

Labs: use an isolated release root containing apps/labs-site with only index.html, style.css, script.js, assets, fonts, robots.txt, sitemap.xml and vercel.json. Link that root to arcora-labs; project rootDirectory is apps/labs-site. Pull/build/deploy from the release root, not the nested app directory. Inspect static output before promotion. The same rootDirectory supports future Git integration builds after source review/merge.

Do not publish .vercel files, pulled environments, or source maps. A domain verification error is not success; after any future DNS change, rerun verification and public HTTPS/browser checks.
Financial and chain semantics remain owned by existing adapters. ZIP trade.js simulation is excluded from the application. Local mock and mocked HTTP verification do not establish live settlement or deployment.
