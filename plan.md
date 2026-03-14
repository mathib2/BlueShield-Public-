# BlueShield v4.0 — Professional RF Intelligence Dashboard Upgrade

## Overview
Massive upgrade adding 2,800+ lines across 10 files. Transforms BlueShield into a professional wireless threat intelligence platform.

## What Gets Built

### Backend (4 files modified, 2 new files)

**NEW: `scanner/tracker_detector.py`** (~180 lines)
- AirTag / SmartTag / Tile signature database
- "Following pattern" detection (stable RSSI over extended time)
- Confidence scoring per suspect

**NEW: `scanner/risk_engine.py`** (~200 lines)
- Per-device risk score 0-100 → LOW / MEDIUM / HIGH / CRITICAL
- Factors: MAC rotation rate, RSSI approaching trend, unknown manufacturer, duration, tracker patterns
- RSSI trend calculation (approaching / leaving / stationary)

**MODIFY: `scanner/fingerprint.py`** (~120 lines added)
- New fields: confidence_score, risk_score, risk_level, risk_factors, rssi_trend, tracker_suspect, ecosystem, movement_indicator
- Enhanced similarity scoring: advertisement interval matching, name similarity, payload pattern, improved temporal correlation
- Cluster confidence calculation (0.0-1.0)
- Ecosystem classification (Apple, Samsung, Google, etc.)
- Rolling RSSI history per fingerprint (last 60 readings for charts)
- Raise MIN_SIMILARITY_SCORE from 5→6 to reduce false positives

**MODIFY: `scanner/bt_scanner.py`** (~50 lines added)
- Capture raw manufacturer data bytes (not just length)
- Store raw_adv_data dict per device (manufacturer hex, service_data, flags, tx_power)
- Enhanced simulated scanner with fake tracker, approaching device, MAC rotators

**MODIFY: `logs/logger.py`** (~80 lines added)
- AnalyticsTracker class: daily counts, peak, returning vs new devices
- Persist to analytics.json

**MODIFY: `dashboard/app.py`** (~200 lines added)
- 7 new API endpoints:
  - `POST /api/ghost` — Emergency shutdown (Linux/RPi only)
  - `GET /api/analytics` — Historical device statistics
  - `GET /api/device/<id>/rssi-history` — Per-device RSSI time series
  - `GET /api/device/<id>/packets` — Raw BLE advertisement data
  - `GET /api/trackers` — Suspected tracker list
  - `GET/POST /api/alerts/rules` — Configurable alert rules
  - `POST /api/alerts/watch` — Watch for device re-appearance
- Integrate risk engine + tracker detector into scan loop
- Configurable alert rules engine

### Frontend (3 files modified)

**MODIFY: `index.html`** (~250 lines added)
- 3 new tabs: Radar, Analytics, Trackers
- Ghost Mode button in top bar (emergency shutdown)
- Environment statistics widget (Nearby / Peak / New / Trusted / Clusters)
- Enhanced device detail panel with RSSI chart, packet inspector, risk meter, quick actions
- Alert rules config UI

**MODIFY: `style.css`** (~350 lines added)
- Risk badges (color-coded LOW→CRITICAL)
- Movement indicators (approaching/leaving/stationary arrows)
- Radar container + legend
- Tracker cards (high/medium confidence borders)
- Analytics grid + cards
- Packet inspector (monospace)
- Ecosystem badges
- Follow-suspect pulse animation
- Ghost mode button styling
- RSSI mini chart
- Quick action buttons
- Risk meter bar

**MODIFY: `dashboard.js`** (~1,400 lines added)
- **Radar/Proximity View**: Canvas-based radar with animated sweep, RSSI-based device placement, category icons, risk-colored dots
- **RSSI Signal Graphs**: SVG line charts per device in detail panel
- **Device Risk Display**: Risk column in table, risk meter in detail panel, factor list
- **Movement Indicators**: Approaching/Leaving/Stationary per device
- **Tracker Detection Panel**: Grid of suspected trackers with confidence, type, duration
- **Packet Inspector**: Raw BLE advertisement data viewer in detail panel
- **Ecosystem Graph**: SVG node-link diagram grouping devices by manufacturer ecosystem
- **Analytics Dashboard**: Mini bar charts for daily/weekly device counts
- **Ghost Mode**: Double-confirm → POST /api/ghost
- **Trust/Untrust Toggle**: Fix trust button to allow revoking trust
- **Quick Actions**: Track, Ignore, Alert if Returns, Export Packets per device
- **Follow Mode**: Highlight devices present >30min with stable RSSI
- **Alert Rules UI**: Toggle alert rules from Config tab
- **Environment Stats**: Live widget above device table

## Implementation Order
1. Backend engines (tracker_detector.py, risk_engine.py)
2. Fingerprint.py + bt_scanner.py enhancements
3. Logger analytics + app.py new endpoints
4. HTML structure (new tabs, widgets, panels)
5. CSS styling (all new components)
6. JavaScript (all rendering, radar, charts, handlers)
7. Test with preview server
