# BlueShield — Design System

**Register:** Product (UI serves the product, not the other way around).
This is a tactical security console. It is not marketing. Density and rigor over decoration.

**Aesthetic lane:** Defense-grade operations console — Palantir Gotham × Anduril Lattice × CrowdStrike Falcon. Not consumer SaaS. Not Linear. Not "AI startup."

## Reflex-reject list (do not introduce)
- Pure black `#000` — use tinted neutrals (Zinc-950 with cool tint)
- Pure white `#FFF` — use warm off-white in light mode
- Inter, Roboto, Arial, Open Sans (not used, per the design guide)
- Side-stripe `border-left: Npx solid <accent>` decorative borders on hover/active
- Glassmorphism (`backdrop-filter: blur` on cards)
- Gradient text on body copy (allowed only on the brand mark itself)
- Bounce/elastic easing on functional motion
- Hero metric template (5 identical equal-weight cards)
- Em dashes in UI copy (use commas, periods, or colons)
- Generic AI cliches: "elevate", "seamless", "unleash", "intelligent"
- `h-screen` / fixed-100vh — use `min-height: 100dvh`
- Three-equal-column card rows of identical visual weight
- Spinner loaders — use skeleton loaders sized to expected content

## Color tokens (OKLCH)
All colors expressed in OKLCH for perceptual consistency. Hex provided as fallback.

**Canvas (dark mode — default for ops console):**
- `--bg-0` → `oklch(0.16 0.02 240)` ≈ `#05070C` — deep ops black, slight cool tint
- `--bg-1` → `oklch(0.19 0.02 240)` ≈ `#0A0E16` — chrome (sidebar, topbar)
- `--bg-2` → `oklch(0.22 0.02 240)` ≈ `#0E131D` — cards
- `--bg-3` → `oklch(0.25 0.02 240)` ≈ `#141A26` — inputs / surfaces
- `--bg-4` → `oklch(0.30 0.02 240)` ≈ `#1C2333` — active / hover

**Text (4 steps, perceptual):**
- `--tx-1` → `oklch(0.92 0.01 240)` ≈ `#E6EDF3` — primary
- `--tx-2` → `oklch(0.65 0.02 240)` ≈ `#8B949E` — secondary
- `--tx-3` → `oklch(0.42 0.02 240)` ≈ `#484F58` — tertiary
- `--tx-4` → `oklch(0.30 0.02 240)` ≈ `#2C3138` — quaternary / disabled

**Accent — phosphor amber (THE signature, single accent rule):**
- `--accent` → `oklch(0.78 0.16 75)` ≈ `#FFB000` — terminal heritage, defense aesthetic

**Semantic (DEFCON-style threat conditions):**
- `--green`  → `oklch(0.74 0.18 145)` ≈ `#3FB950` — DEFCON 5 (normal)
- `--blue`   → `oklch(0.70 0.16 240)` ≈ `#58A6FF` — DEFCON 4 (elevated)
- `--orange` → `oklch(0.75 0.16 65)`  ≈ `#D29922` — DEFCON 3 (above normal)
- `--amber`  → `oklch(0.72 0.18 50)`  ≈ `#FF7B00` — DEFCON 2 (near max)
- `--red`    → `oklch(0.65 0.21 25)`  ≈ `#F85149` — DEFCON 1 (max threat)
- `--purple` → `oklch(0.55 0.27 295)` ≈ `#8B00FF` — anomaly / shadow devices

## Typography
- **Display:** `Space Grotesk` 600/700 — system labels, brand mark
- **Body:** `Geist` 400/500 — UI labels, descriptions, paragraphs (replaces Inter)
- **Monospace:** `JetBrains Mono` 400/500/600 — all data, MAC addresses, RSSI, timestamps

**Scale (modular, contrast-driven):**
- `--fs-xs`: 10px (eyebrow / status pills)
- `--fs-sm`: 11.5px (table cells, secondary labels)
- `--fs-md`: 13px (body)
- `--fs-lg`: 15px (panel titles)
- `--fs-xl`: 22px (page titles)
- `--fs-2xl`: 32px (hero numerics)

## Motion
**Easing:** exponential only. No bounce, no elastic.
- `--ease-out`: `cubic-bezier(0.16, 1, 0.3, 1)` — ease-out-expo, default for entries
- `--ease-in-out`: `cubic-bezier(0.7, 0, 0.3, 1)` — for state transitions
- `--ease-snap`: `cubic-bezier(0.25, 1, 0.25, 1)` — for fast UI feedback

**Durations:**
- `--dur-fast`: 120ms (hover, focus rings)
- `--dur-mid`: 240ms (tab switches, expansion)
- `--dur-slow`: 400ms (page-level transitions)

## Layout
- 4px grid base for spacing rhythm
- Cards: 1px border, no drop shadow (military, not consumer)
- Square 2px corners — defense aesthetic
- Information density over whitespace

## States (mandatory coverage, design guide)
Every interactive surface must define:
- Default
- Hover
- Active / Pressed
- Focus (3px ring, accent color, 0.12 alpha)
- Loading (skeleton, sized to expected content)
- Empty (purposeful copy, not just "No data")
- Error (red-bg subtle, not alarming)
- Disabled (0.5 opacity)

## Iconography
- Stroke icons only (Feather/Lucide style), 1.5–2px stroke width
- 14–16px in UI chrome, 20px+ in feature blocks
- No emoji — replaced via the `ICO` map in dashboard.js

## Anti-patterns specific to this project (and how we resolved them)
- ~~Side-stripe `border-left:2px solid accent` on active nav~~ → background tint + tiny indicator dot
- ~~AI Correlation row showing 5 zeros~~ → graceful "AWAITING TELEMETRY" empty state
- ~~Unlabeled bottom nav icons (mobile)~~ → 9px label below each icon
- ~~Hero metric template (5 equal cards in stats strip)~~ → broken into primary count + 4 secondaries with weight contrast
