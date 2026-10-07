# Arcora Labs

Independent blue/white studio identity at arcoralabs.xyz. Static HTML/CSS/JS, locally hosted Archivo font, no analytics or runtime dependencies. Perp's Warm Precision palette and product illustrations are not used by the corporate theme.

Local: `python3 -m http.server 5189 --bind 127.0.0.1 --directory apps/labs-site`

The five project JPEGs in `assets/projects/` are unaltered browser screenshots captured at 1440×1000 from the linked public websites on 2026-10-07. They preserve the original product typography, colors, layouts and visible state. Celari uses its English locale. Screenshots are dated in the page captions and are not live data. ArcoraDEX is on Base Sepolia (not Arc); Arcora Pay is on Arc testnet. Product content is based on the actual current websites.

Project selector controls the cover screenshot and link; category filters show matching project spreads. Both are native buttons with visible focus and `aria-pressed`. All project links remain available without JavaScript. Reduced motion removes transitions.

Vercel project: kubudak90s-projects/arcora-labs; rootDirectory: apps/labs-site. Deploy from a repository-shaped isolated root, not from the nested site directory. Stage a production build, verify it, then promote the same immutable URL. Do not change Perp or DNS when deploying Labs.
