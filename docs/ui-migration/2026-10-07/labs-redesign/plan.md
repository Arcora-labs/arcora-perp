# Arcora Labs independent identity revision

## Brief and authority
User rejected the Labs site because it inherited Perp's warm design and used inaccurate product illustrations. Replace the Labs site with a distinct authored identity and representations faithful to each linked live product. Existing production-deployment authority continues. No Perp code, backend, other project sites, or DNS changes.

## Design plan
- Palette: cloud #e8f0f5, white #ffffff, deep ocean #153443, slate #527080, blue #295dca, mist #c5d9e7. No Perp cream/coral/orange system.
- Type: locally hosted Archivo; very large dense headlines, quiet readable body. Existing brand name becomes a purpose-drawn typographic Labs lockup.
- Layout: a broad blue studio cover with oversized headline and a selectable product contact sheet; below, spacious alternating product spreads with actual website screenshots; concise studio statement; large typographic footer.
- Unique element: the interactive contact sheet shows the five actual product worlds together. Their original palettes and typography are preserved; no invented mockups or filters.
- Copy: English; describe actual product and network only. Correct ArcoraDEX from Arc to Base Sepolia. Keep testnet/demo/release boundaries.

Cover: [Arcora Labs                       Work / Studio / GitHub]
       [Good ideas       [selected product / actual screen      ]]
       [get built.   [five named selectors                   ]]
       [what the studio builds                 Explore projects ]
Work:  [Project title + summary     [large real product screenshot]]
       [[large real screenshot]     Project title + summary     ]
Studio:[Products with a point of view.  Research / build / iterate]
Footer:[Arcora Labs                                                   ]

## Critique before implementation
Discarded the previous orbit/logo hero, gradient buttons, generic invented dashboard art and uniform warm cards. The contact sheet gives the cover content that is specific to this five-product studio. Actual screenshots supply the product identity; the Labs canvas and type supply its independent identity. Avoid generic dark/neon or cream/serif defaults. Restrict motion to user-selected previews and a single introductory transition; reduced-motion support is mandatory.

## Graph and gates
R1 live reference capture -> screenshots and factual inventory (PASS when visually reviewed).
R2 implement independent Labs identity -> static site (PASS after visual critique).
R3 responsive, links, selectors, keyboard, console/assets and reduced-motion -> browser evidence (PASS required).
R4 build allowlisted static output -> staged production and review -> promote Labs only -> verify domain artifact hashes and browser (PASS required).
R5 source review handoff on existing PR, updated evidence -> DONE.

Each node may receive two targeted corrections; additional attempts require a new observed cause. Existing dirty work preserved; source identity and files recorded for this revision separately from the original Perp release.

## Final evidence and disposition
- R1 PASS: all five sites visited and visually inspected in Chromium; unedited 1440×1000 JPEG captures are in apps/labs-site/assets/projects. Reference URL/date/hash inventory is references.json. Celari English locale captured. The live ArcoraDEX screen identifies Base Sepolia; the website description was corrected accordingly.
- R2 PASS: complete independent blue/white identity, Archivo typography, new Labs monogram, selectable real-product cover, alternating product spreads, studio section and oversized typographic footer. Removed unused Perp orange brand assets and old Inter font from the Labs package. Desktop, every project spread, mobile and footer captures reviewed visually. Final refinements: reduced headline tracking, removed a label overlapping the stacked imagery, 44px mobile picker targets. These are design assessments, not user sign-off.
- R3 PASS: browser-local-final.log and browser-production.log: all five preview states change both image and destination; category counts match; five distinct project destinations; no overflow at 320/360/390/760/1024/1440/1600; all images decode; reduced motion and keyboard verified; no console or page errors. Node syntax check passed. No backend, dependency or Perp code changes; its protocol tests are not rerun for this isolated static-site revision.
- WebKit production check: browser-webkit-production.log. Initial capture run produced eight CSP messages from Playwright's own screenshot animation synchronization (coreBundle.js inPagePrepareForScreenshots injects a temporary `body {}` inline stylesheet when syncAnimations is true). A fresh navigation and interaction-only rerun emits no CSP/console/page errors. Website CSP was not weakened. WebKit's default Tab preference focuses form controls rather than links; verified native first-control focus separately and skip-link Enter activation after explicit focus. Chromium's Tab-to-skip-link path also passed. Initial run retained as browser-webkit-first.log.
- R4 PASS: source-fingerprint.json identifies all 15 deployable files, fingerprint dbf2f3dc123ff4c66c6ef2ab84dd1bd5d6e7c3255fefde4c2a12e5d04fd176da. Staged HTTP HTML/CSS/JS/image hashes match local tested files (staged-http.json). Production dpl_669zNJoF1uGaK1phAbXAyQ7MbjTx was staged and promoted unchanged. https://arcoralabs.xyz serves all 14 public static files with identical SHA-256 hashes (public-http.json); vercel.json is deployment configuration, not a public file. Browser checks rerun on public HTTPS. Runtime error scan found no logs; this is a static site, not proof of ongoing telemetry.
- R5: source and evidence delivered on feat/warm-precision-ui / PR #28. Original dirty checkout remains untouched; no merge or DNS changes.

Result: DONE. Source changes are restricted to apps/labs-site and its verification records. Other projects' websites and Perp deployment are unchanged.
