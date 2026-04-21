/* ===================================================================
   BlueShield Easter Egg — Traditional Chinese Dragon
   Realistic ink-brush blue dragon: thick serpentine body, prominent
   fish scales, belly plates, bold mane, large detailed head with
   deer antlers, eagle claws, flaming pearl, ruyi clouds.
   Dark mode only. Activated by typing "dragon".
   =================================================================== */
(() => {
"use strict";

const canvas = document.getElementById("dragon-canvas");
if (!canvas) return;
const ctx = canvas.getContext("2d");

/* -- Palette -------------------------------------------------------- */
const C1 = [25, 120, 200];   // deep blue (body core)
const C2 = [34, 211, 238];   // cyan (highlights)
const C3 = [15, 60, 140];    // dark navy (bold outlines)
const C4 = [70, 190, 240];   // light blue (shimmer)
const C5 = [40, 160, 220];   // mid blue (scales)
const CW = [200, 230, 255];  // near-white (teeth, claws)

const rgb = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;

/* -- State ---------------------------------------------------------- */
let active = false, konamiBuffer = "";
const TRIGGER = "dragon";
let W, H, t = 0, mouseX = -1, mouseY = -1;
const SEG = 200;
const segments = [];
const clouds = [];

/* -- Resize --------------------------------------------------------- */
function resize() {
    const dpr = window.devicePixelRatio || 1;
    W = window.innerWidth; H = window.innerHeight;
    canvas.width = W * dpr; canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
window.addEventListener("resize", resize);

/* -- Activation ----------------------------------------------------- */
document.addEventListener("keydown", e => {
    if (e.key.length !== 1) return;
    konamiBuffer += e.key.toLowerCase();
    if (konamiBuffer.length > 20) konamiBuffer = konamiBuffer.slice(-20);
    if (konamiBuffer.endsWith(TRIGGER) && !active) activate();
});
document.addEventListener("mousemove", e => { mouseX = e.clientX; mouseY = e.clientY; });

/* == Serpentine path ================================================= */
function dragonX(i, time) {
    const r = i / SEG;
    const phase = r * Math.PI * 4.5;
    const drift = time * 0.35;
    const amp = W * 0.24 * (1 - r * 0.12);
    return W * 0.48 + Math.sin(phase + drift) * amp
         + Math.sin(phase * 2.3 + time * 0.6) * 14
         + (mouseX > 0 ? (mouseX - W/2) * 0.018 * Math.exp(-r*2.5) : 0);
}
function dragonY(i, time) {
    const r = i / SEG;
    const phase = r * Math.PI * 3.5;
    const drift = time * 0.3;
    return H * 0.28 + r * H * 0.42
         + Math.sin(phase + drift + 0.8) * H * 0.13 * (1 - r * 0.25)
         + Math.cos(phase * 1.5 + time * 0.45) * 12
         + (mouseY > 0 ? (mouseY - H/2) * 0.012 * Math.exp(-r*2.5) : 0);
}

/* Body width: big head, thick body, elegant taper */
function bodyW(i) {
    const r = i / SEG;
    if (r < 0.015) return 6 + r/0.015 * 20;          // snout tip
    if (r < 0.04)  return 26 + (r-0.015)/0.025 * 10;  // snout widen
    if (r < 0.08)  return 36;                           // head (big!)
    if (r < 0.12)  return 36 - (r-0.08)/0.04 * 6;     // neck narrows
    if (r < 0.20)  return 30 + (r-0.12)/0.08 * 4;     // chest swells
    if (r < 0.65)  return 34 - (r-0.20) * 22;          // long taper
    return Math.max(2, 24 * (1 - (r-0.65)/0.35));      // thin tail
}

/* -- Helpers -------------------------------------------------------- */
function segN(i) {
    const a = segments[Math.max(0,i-1)], b = segments[Math.min(SEG-1,i+1)];
    const dx = b.x-a.x, dy = b.y-a.y, len = Math.hypot(dx,dy)||1;
    return { nx:-dy/len, ny:dx/len, dx:dx/len, dy:dy/len };
}
function segA(i) { const n = segN(i); return Math.atan2(n.dy, n.dx); }
function updateSegs(time) {
    for (let i = 0; i < SEG; i++)
        segments[i] = { x: dragonX(i,time), y: dragonY(i,time), w: bodyW(i) };
}

/* == DRAWING ======================================================== */

/* -- Body: multi-layer fill with depth gradient --------------------- */
function drawBody() {
    // Outer atmospheric glow
    buildBodyPath(14);
    ctx.fillStyle = rgb(C2, 0.04);
    ctx.fill();

    // Main body fill with per-segment gradient for 3D depth
    for (let i = 0; i < SEG - 1; i++) {
        const s = segments[i], s2 = segments[i+1];
        const n = segN(i), n2 = segN(i+1);
        const w = s.w/2, w2 = s2.w/2;

        ctx.beginPath();
        ctx.moveTo(s.x + n.nx*w, s.y + n.ny*w);
        ctx.lineTo(s2.x + n2.nx*w2, s2.y + n2.ny*w2);
        ctx.lineTo(s2.x - n2.nx*w2, s2.y - n2.ny*w2);
        ctx.lineTo(s.x - n.nx*w, s.y - n.ny*w);
        ctx.closePath();

        // Cross-body gradient: dark edge → light center → dark edge
        const gx1 = s.x + n.nx*w, gy1 = s.y + n.ny*w;
        const gx2 = s.x - n.nx*w, gy2 = s.y - n.ny*w;
        const grad = ctx.createLinearGradient(gx1,gy1,gx2,gy2);
        grad.addColorStop(0, rgb(C3, 0.12));
        grad.addColorStop(0.3, rgb(C1, 0.16));
        grad.addColorStop(0.5, rgb(C5, 0.18));
        grad.addColorStop(0.7, rgb(C1, 0.14));
        grad.addColorStop(1, rgb(C3, 0.10));
        ctx.fillStyle = grad;
        ctx.fill();
    }

    // Belly center highlight
    ctx.beginPath();
    for (let i = 0; i < SEG; i++) {
        const s = segments[i], n = segN(i), off = s.w * 0.12;
        const px = s.x - n.nx*off, py = s.y - n.ny*off;
        i === 0 ? ctx.moveTo(px,py) : ctx.lineTo(px,py);
    }
    ctx.strokeStyle = rgb(C4, 0.1);
    ctx.lineWidth = 4;
    ctx.lineCap = "round";
    ctx.stroke();
}

function buildBodyPath(expand) {
    ctx.beginPath();
    for (let i = 0; i < SEG; i++) {
        const s = segments[i], n = segN(i), w = (s.w+expand)/2;
        i === 0 ? ctx.moveTo(s.x+n.nx*w, s.y+n.ny*w) : ctx.lineTo(s.x+n.nx*w, s.y+n.ny*w);
    }
    for (let i = SEG-1; i >= 0; i--) {
        const s = segments[i], n = segN(i), w = (s.w+expand)/2;
        ctx.lineTo(s.x-n.nx*w, s.y-n.ny*w);
    }
    ctx.closePath();
}

/* -- Body outline: calligraphic brush strokes ----------------------- */
function drawOutline() {
    const top = [], bot = [];
    for (let i = 0; i < SEG; i++) {
        const s = segments[i], n = segN(i), w = s.w/2;
        top.push({x:s.x+n.nx*w, y:s.y+n.ny*w});
        bot.push({x:s.x-n.nx*w, y:s.y-n.ny*w});
    }
    ctx.lineCap = "round"; ctx.lineJoin = "round";
    for (const edge of [top, bot]) {
        for (let i = 0; i < edge.length - 1; i++) {
            const r = i / edge.length;
            const dx = edge[Math.min(i+3,edge.length-1)].x - edge[Math.max(0,i-1)].x;
            const dy = edge[Math.min(i+3,edge.length-1)].y - edge[Math.max(0,i-1)].y;
            const prev = i > 0 ? Math.atan2(edge[i].y-edge[i-1].y, edge[i].x-edge[i-1].x) : 0;
            const curv = Math.abs(Math.atan2(dy,dx) - prev);
            const pressure = 1.5 + curv * 4;
            ctx.lineWidth = Math.min(3.5, pressure) * (1 - r*0.35);
            ctx.strokeStyle = rgb(C3, 0.25 + curv * 0.15);
            ctx.beginPath();
            ctx.moveTo(edge[i].x, edge[i].y);
            ctx.lineTo(edge[i+1].x, edge[i+1].y);
            ctx.stroke();
        }
    }
}

/* -- Fish scales: bold overlapping crescents ------------------------ */
function drawScales(time) {
    const start = Math.floor(SEG * 0.09), end = Math.floor(SEG * 0.92);
    for (let i = start; i < end; i += 2) {
        const s = segments[i];
        if (s.w < 5) continue;
        const n = segN(i), a = segA(i);
        const shimmer = 0.12 + Math.sin(i*0.25 + time*0.7) * 0.04;

        const cols = Math.max(1, Math.floor(s.w / 4.5));
        for (let c = 0; c < cols; c++) {
            const frac = (c+0.5)/cols - 0.5;
            const cx = s.x + n.nx*s.w*frac*0.44;
            const cy = s.y + n.ny*s.w*frac*0.44;
            const r = 3 + (s.w/20)*2.5;

            // Outer scale arc
            ctx.beginPath();
            ctx.arc(cx, cy, r, a - Math.PI*0.5, a + Math.PI*0.5, false);
            ctx.strokeStyle = rgb(C2, shimmer);
            ctx.lineWidth = 0.9;
            ctx.stroke();

            // Inner shading arc
            ctx.beginPath();
            ctx.arc(cx, cy, r*0.55, a - Math.PI*0.3, a + Math.PI*0.3, false);
            ctx.strokeStyle = rgb(C4, shimmer*0.6);
            ctx.lineWidth = 0.4;
            ctx.stroke();
        }
    }
}

/* -- Belly plates: horizontal segmented bands ----------------------- */
function drawBellyPlates() {
    const start = Math.floor(SEG * 0.1), end = Math.floor(SEG * 0.88);
    ctx.lineWidth = 0.6;
    for (let i = start; i < end; i += 3) {
        const s = segments[i];
        if (s.w < 6) continue;
        const n = segN(i);
        const bw = s.w * 0.3;
        // Horizontal band across belly
        ctx.beginPath();
        ctx.moveTo(s.x - n.nx*bw*0.5, s.y - n.ny*bw*0.5);
        ctx.lineTo(s.x + n.nx*bw*0.5, s.y + n.ny*bw*0.5);
        ctx.strokeStyle = rgb(C5, 0.06);
        ctx.stroke();
    }
}

/* -- Dorsal mane: thick flowing hair along spine -------------------- */
function drawMane(time) {
    const start = Math.floor(SEG * 0.04), end = Math.floor(SEG * 0.7);
    for (let i = start; i < end; i += 2) {
        const s = segments[i], n = segN(i);
        const progress = (i-start) / (end-start);
        const baseLen = (28 + Math.sin(i*0.12)*10) * (1 - progress*0.55);
        const w1 = Math.sin(time*1.3 + i*0.1) * 10;
        const w2 = Math.cos(time*0.8 + i*0.15) * 7;

        for (let h = 0; h < 3; h++) {
            const off = (h-1) * 3;
            const sx = s.x + n.nx*(s.w*0.5 + off);
            const sy = s.y + n.ny*(s.w*0.5 + off);
            const len = baseLen + h*6;
            const wf1 = w1 * (1 + h*0.25), wf2 = w2 * (1 + h*0.2);

            ctx.beginPath();
            ctx.moveTo(sx, sy);
            ctx.bezierCurveTo(
                sx + n.nx*len*0.35 + wf1, sy + n.ny*len*0.35 + wf2,
                sx + n.nx*len*0.65 + wf1*1.2, sy + n.ny*len*0.65 + wf2*0.7,
                sx + n.nx*len + wf1*0.8, sy + n.ny*len + wf2*1.1
            );
            const alpha = 0.09 - progress*0.04 - h*0.015;
            ctx.strokeStyle = rgb(C2, Math.max(0.02, alpha));
            ctx.lineWidth = 1.4 - progress*0.6 - h*0.2;
            ctx.lineCap = "round";
            ctx.stroke();
        }
    }
}

/* -- Legs with muscular form and eagle talons ----------------------- */
function drawLegs(time) {
    const positions = [
        { seg: Math.floor(SEG*0.17), side: 1 },
        { seg: Math.floor(SEG*0.17), side: -1 },
        { seg: Math.floor(SEG*0.50), side: 1 },
        { seg: Math.floor(SEG*0.50), side: -1 },
    ];
    positions.forEach((leg, li) => {
        const s = segments[leg.seg], n = segN(leg.seg), a = segA(leg.seg);
        const walk = Math.sin(time*1.5 + li*Math.PI*0.5) * 0.35;
        const bx = s.x - n.nx*s.w*0.44*leg.side;
        const by = s.y - n.ny*s.w*0.44*leg.side;

        // Upper leg (thigh)
        const uA = a + Math.PI*0.5*(-leg.side) + walk;
        const uL = 24;
        const kx = bx + Math.cos(uA)*uL, ky = by + Math.sin(uA)*uL;

        // Lower leg (shin)
        const lA = uA + 0.55 + Math.sin(time*1.5 + li*1.2 + 0.5)*0.25;
        const lL = 22;
        const fx = kx + Math.cos(lA)*lL, fy = ky + Math.sin(lA)*lL;

        // Muscular leg with varying thickness
        ctx.lineCap = "round"; ctx.lineJoin = "round";
        // Thigh
        ctx.beginPath(); ctx.moveTo(bx, by); ctx.lineTo(kx, ky);
        ctx.strokeStyle = rgb(C3, 0.22); ctx.lineWidth = 3; ctx.stroke();
        // Shin
        ctx.beginPath(); ctx.moveTo(kx, ky); ctx.lineTo(fx, fy);
        ctx.strokeStyle = rgb(C3, 0.2); ctx.lineWidth = 2.5; ctx.stroke();

        // Knee joint
        ctx.beginPath(); ctx.arc(kx, ky, 3, 0, Math.PI*2);
        ctx.fillStyle = rgb(C1, 0.15); ctx.fill();

        // Eagle claws: 5 toes (imperial dragon)
        for (let c = 0; c < 5; c++) {
            const spread = (c - 2) * 0.24;
            const ca = lA + spread;
            const cLen = 10;
            const tx = fx + Math.cos(ca)*cLen;
            const ty = fy + Math.sin(ca)*cLen;
            const hookA = ca + 0.7*(c < 2.5 ? 1 : -1);
            const hx = tx + Math.cos(hookA)*4;
            const hy = ty + Math.sin(hookA)*4;

            ctx.beginPath();
            ctx.moveTo(fx, fy);
            ctx.quadraticCurveTo(tx, ty, hx, hy);
            ctx.strokeStyle = rgb(CW, 0.18);
            ctx.lineWidth = 1.5 - Math.abs(c-2)*0.2;
            ctx.stroke();
        }
    });
}

/* -- HEAD: large, detailed, traditional ----------------------------- */
function drawHead(time) {
    const head = segments[0], neck = segments[8];
    const angle = Math.atan2(neck.y-head.y, neck.x-head.x) + Math.PI;
    ctx.save();
    ctx.translate(head.x, head.y);
    ctx.rotate(angle);

    const sc = 1.5; // head scale factor for prominence
    ctx.scale(sc, sc);

    const jaw = 4 + Math.sin(time*0.55) * 2.5;

    /* Upper jaw — elongated camel snout */
    ctx.beginPath();
    ctx.moveTo(-6, -12);
    ctx.bezierCurveTo(6, -18, 24, -16, 40, -7);
    ctx.quadraticCurveTo(45, -3, 42, 0);
    ctx.strokeStyle = rgb(C3, 0.35);
    ctx.lineWidth = 2.5; ctx.lineCap = "round"; ctx.stroke();

    /* Lower jaw */
    ctx.beginPath();
    ctx.moveTo(-6, 12);
    ctx.bezierCurveTo(6, 18+jaw, 24, 16+jaw, 38, 7+jaw);
    ctx.quadraticCurveTo(43, 3+jaw*0.5, 42, 0);
    ctx.strokeStyle = rgb(C3, 0.33); ctx.lineWidth = 2.2; ctx.stroke();

    /* Head fill */
    ctx.beginPath();
    ctx.moveTo(-6, -12);
    ctx.bezierCurveTo(6, -18, 24, -16, 40, -7);
    ctx.quadraticCurveTo(45, -3, 42, 0);
    ctx.quadraticCurveTo(43, 3+jaw*0.5, 38, 7+jaw);
    ctx.bezierCurveTo(24, 16+jaw, 6, 18+jaw, -6, 12);
    ctx.quadraticCurveTo(-14, 6, -14, 0);
    ctx.quadraticCurveTo(-14, -6, -6, -12);
    ctx.closePath();
    const hg = ctx.createLinearGradient(-14, -18, -14, 18);
    hg.addColorStop(0, rgb(C3, 0.15));
    hg.addColorStop(0.5, rgb(C1, 0.2));
    hg.addColorStop(1, rgb(C3, 0.12));
    ctx.fillStyle = hg;
    ctx.fill();

    /* Snout ridges */
    for (let r = 0; r < 4; r++) {
        ctx.beginPath();
        const ry = -9 + r*3;
        ctx.moveTo(14+r*2, ry);
        ctx.quadraticCurveTo(26, ry-2+r*0.8, 36, ry+1);
        ctx.strokeStyle = rgb(C2, 0.12);
        ctx.lineWidth = 0.6; ctx.stroke();
    }

    /* Eyes: large, fierce, glowing */
    for (const side of [-1, 1]) {
        const ey = side * 10;
        // Socket
        ctx.beginPath();
        ctx.ellipse(14, ey, 7, 5, side*0.2, 0, Math.PI*2);
        ctx.fillStyle = rgb(C1, 0.18);
        ctx.fill();
        ctx.strokeStyle = rgb(C3, 0.3);
        ctx.lineWidth = 1.5; ctx.stroke();

        // Iris
        ctx.beginPath();
        ctx.ellipse(15, ey, 4, 4.5, 0, 0, Math.PI*2);
        ctx.fillStyle = rgb(C2, 0.45);
        ctx.fill();

        // Slit pupil
        ctx.beginPath();
        ctx.ellipse(15.5, ey, 1.2, 4, 0.1, 0, Math.PI*2);
        ctx.fillStyle = rgb(C3, 0.6);
        ctx.fill();

        // Bright eye glow
        const eg = ctx.createRadialGradient(15, ey, 0, 15, ey, 14);
        eg.addColorStop(0, rgb(C2, 0.3));
        eg.addColorStop(0.5, rgb(C2, 0.08));
        eg.addColorStop(1, rgb(C2, 0));
        ctx.beginPath(); ctx.arc(15, ey, 14, 0, Math.PI*2);
        ctx.fillStyle = eg; ctx.fill();

        // Fierce brow ridge
        ctx.beginPath();
        ctx.moveTo(6, ey - side*6);
        ctx.quadraticCurveTo(14, ey - side*9, 24, ey - side*5);
        ctx.strokeStyle = rgb(C3, 0.25);
        ctx.lineWidth = 2; ctx.stroke();
    }

    /* Nostrils */
    for (const side of [-1, 1]) {
        ctx.beginPath();
        ctx.ellipse(36, side*3.5, 2.5, 1.5, side*0.4, 0, Math.PI*2);
        ctx.fillStyle = rgb(C3, 0.2); ctx.fill();
        // Smoke wisps
        const sw = Math.sin(time*2.2+side)*5;
        ctx.beginPath();
        ctx.moveTo(38, side*3.5);
        ctx.bezierCurveTo(44, side*2+sw, 50, side*5+sw, 48, side*8+sw);
        ctx.strokeStyle = rgb(C2, 0.06); ctx.lineWidth = 0.6; ctx.stroke();
    }

    /* Teeth — prominent fangs */
    for (let tt = 0; tt < 6; tt++) {
        const tx = 18 + tt*3.5;
        const sz = 5 - tt*0.5;
        // Upper
        ctx.beginPath();
        ctx.moveTo(tx-1.5, -5);
        ctx.lineTo(tx, -5 + sz + jaw*0.12);
        ctx.lineTo(tx+1.5, -5);
        ctx.strokeStyle = rgb(CW, 0.2);
        ctx.lineWidth = 0.8; ctx.stroke();
        ctx.fillStyle = rgb(CW, 0.06); ctx.fill();
        // Lower
        ctx.beginPath();
        ctx.moveTo(tx-1.5, 5+jaw*0.3);
        ctx.lineTo(tx, 5+jaw*0.3 - sz - jaw*0.08);
        ctx.lineTo(tx+1.5, 5+jaw*0.3);
        ctx.stroke(); ctx.fill();
    }

    /* Deer antlers — bold, branching */
    const hw = Math.sin(time*0.35) * 2.5;
    for (const side of [-1, 1]) {
        const ay = side * 13;
        // Main beam
        ctx.beginPath();
        ctx.moveTo(2, ay);
        ctx.bezierCurveTo(-6, ay+side*(-22+hw), -14, ay+side*(-34+hw), -20, ay+side*(-44+hw));
        ctx.strokeStyle = rgb(C3, 0.28); ctx.lineWidth = 2.8; ctx.lineCap = "round"; ctx.stroke();
        // Tine 1
        ctx.beginPath();
        ctx.moveTo(-8, ay+side*(-18+hw*0.5));
        ctx.bezierCurveTo(-16, ay+side*(-24+hw), -22, ay+side*(-20+hw), -24, ay+side*(-15+hw));
        ctx.lineWidth = 2; ctx.strokeStyle = rgb(C3, 0.2); ctx.stroke();
        // Tine 2
        ctx.beginPath();
        ctx.moveTo(-14, ay+side*(-30+hw));
        ctx.quadraticCurveTo(-8, ay+side*(-40+hw), -3, ay+side*(-44+hw));
        ctx.lineWidth = 1.5; ctx.strokeStyle = rgb(C3, 0.16); ctx.stroke();
        // Tine 3
        ctx.beginPath();
        ctx.moveTo(-18, ay+side*(-38+hw));
        ctx.quadraticCurveTo(-26, ay+side*(-44+hw), -28, ay+side*(-38+hw));
        ctx.lineWidth = 1; ctx.strokeStyle = rgb(C3, 0.12); ctx.stroke();
    }

    /* Whiskers — long, elegant, flowing */
    const ww = Math.sin(time*0.45) * 12;
    const ww2 = Math.cos(time*0.35) * 9;
    for (const side of [-1, 1]) {
        ctx.beginPath();
        ctx.moveTo(36, side*5);
        ctx.bezierCurveTo(54, side*12+ww, 76, side*8+ww*1.3, 100, side*16+ww*0.7);
        ctx.strokeStyle = rgb(C2, 0.16); ctx.lineWidth = 1.3; ctx.lineCap = "round"; ctx.stroke();

        ctx.beginPath();
        ctx.moveTo(34, side*6);
        ctx.bezierCurveTo(50, side*20+ww2, 66, side*26+ww2, 82, side*22+ww2*1.1);
        ctx.strokeStyle = rgb(C2, 0.1); ctx.lineWidth = 0.9; ctx.stroke();
    }

    /* Beard — flowing tendrils */
    for (let b = 0; b < 7; b++) {
        const bf = b/7;
        const bx = 0 + bf*16;
        const by = 14 + jaw*0.4;
        const wave = Math.sin(time*0.9 + b*0.6) * 7;
        const bLen = 26 + b*5;

        ctx.beginPath();
        ctx.moveTo(bx, by);
        ctx.bezierCurveTo(
            bx-5+wave, by+bLen*0.3,
            bx-10+wave*1.2, by+bLen*0.6,
            bx-7+wave*0.8, by+bLen
        );
        ctx.strokeStyle = rgb(C2, 0.08 + bf*0.025);
        ctx.lineWidth = 1.2 - bf*0.35;
        ctx.lineCap = "round"; ctx.stroke();
    }

    ctx.restore();
}

/* -- Tail: elegant curl with flame tuft ----------------------------- */
function drawTail(time) {
    const tip = segments[SEG-1], pre = segments[SEG-5];
    const tA = Math.atan2(tip.y-pre.y, tip.x-pre.x);

    // Spiral curl at tip
    const pts = [];
    for (let c = 0; c < 16; c++) {
        const cf = c/16;
        const ca = tA + cf*Math.PI*2 + Math.sin(time*1.1)*0.35;
        const cr = 14*(1-cf*0.55);
        pts.push({ x: tip.x+Math.cos(ca)*cr*cf*2.5, y: tip.y+Math.sin(ca)*cr*cf*2.5 });
    }
    ctx.lineCap = "round";
    for (let i = 0; i < pts.length-1; i++) {
        const r = i/(pts.length-1);
        ctx.beginPath(); ctx.moveTo(pts[i].x, pts[i].y); ctx.lineTo(pts[i+1].x, pts[i+1].y);
        ctx.strokeStyle = rgb(C2, 0.15*(1-r*0.6));
        ctx.lineWidth = 2.5*(1-r*0.7); ctx.stroke();
    }

    // Flame wisps
    for (let f = 0; f < 7; f++) {
        const spread = (f/7-0.5)*1.6;
        const fA = tA + spread;
        const fLen = 16 + Math.sin(time*2.5+f*1.1)*8;
        const wave = Math.sin(time*3+f*0.8)*4;
        ctx.beginPath();
        ctx.moveTo(tip.x, tip.y);
        ctx.quadraticCurveTo(
            tip.x+Math.cos(fA)*fLen*0.5+wave, tip.y+Math.sin(fA)*fLen*0.5+wave,
            tip.x+Math.cos(fA+wave*0.02)*fLen, tip.y+Math.sin(fA+wave*0.02)*fLen
        );
        ctx.strokeStyle = rgb(C2, 0.1+f*0.01);
        ctx.lineWidth = 1.8-f*0.2; ctx.lineCap = "round"; ctx.stroke();
    }

    // Glow
    const tg = ctx.createRadialGradient(tip.x,tip.y,0, tip.x,tip.y,26);
    tg.addColorStop(0, rgb(C2, 0.12)); tg.addColorStop(1, rgb(C2, 0));
    ctx.beginPath(); ctx.arc(tip.x,tip.y,26,0,Math.PI*2);
    ctx.fillStyle = tg; ctx.fill();
}

/* -- Flaming pearl -------------------------------------------------- */
function drawPearl(time) {
    const head = segments[0], neck = segments[8];
    const a = Math.atan2(neck.y-head.y, neck.x-head.x) + Math.PI;
    const dist = 80 + Math.sin(time*0.7)*10;
    const px = head.x + Math.cos(a)*dist;
    const py = head.y + Math.sin(a)*dist + Math.sin(time*1.1)*8;

    // Fire ring
    for (let f = 0; f < 10; f++) {
        const fa = (f/10)*Math.PI*2 + time*1.4;
        const fr = 18 + Math.sin(time*2.8+f*1.1)*5;
        ctx.beginPath();
        ctx.moveTo(px+Math.cos(fa)*10, py+Math.sin(fa)*10);
        ctx.quadraticCurveTo(px+Math.cos(fa+0.3)*(fr+5), py+Math.sin(fa+0.3)*(fr+5),
                             px+Math.cos(fa)*fr, py+Math.sin(fa)*fr);
        ctx.strokeStyle = rgb(C2, 0.08); ctx.lineWidth = 1; ctx.stroke();
    }

    // Pearl glow
    const pg = ctx.createRadialGradient(px,py,0, px,py,16);
    pg.addColorStop(0, rgb(C2, 0.28));
    pg.addColorStop(0.4, rgb(C1, 0.14));
    pg.addColorStop(1, rgb(C2, 0));
    ctx.beginPath(); ctx.arc(px,py,16,0,Math.PI*2); ctx.fillStyle = pg; ctx.fill();

    // Pearl solid core
    ctx.beginPath(); ctx.arc(px,py,6,0,Math.PI*2);
    ctx.fillStyle = rgb(C2, 0.3); ctx.fill();
    ctx.strokeStyle = rgb(C4, 0.35); ctx.lineWidth = 1.2; ctx.stroke();

    // Yin-yang swirl inside pearl
    ctx.beginPath();
    ctx.arc(px, py, 3.5, time*2, time*2+Math.PI*1.3);
    ctx.strokeStyle = rgb(CW, 0.2); ctx.lineWidth = 0.7; ctx.stroke();
}

/* -- Ruyi clouds ---------------------------------------------------- */
function initClouds() {
    for (let i = 0; i < 16; i++) {
        clouds.push({
            offset: Math.random(),
            drift: Math.random()*Math.PI*2,
            size: 22+Math.random()*35,
            speed: 0.08+Math.random()*0.18,
            amp: 35+Math.random()*50,
            lobes: 3+Math.floor(Math.random()*3)
        });
    }
}

function drawClouds(time) {
    clouds.forEach(c => {
        const si = Math.floor(c.offset*(SEG-1));
        const s = segments[si];
        const cx = s.x + Math.sin(time*c.speed+c.drift)*c.amp;
        const cy = s.y + Math.cos(time*c.speed*0.7+c.drift+1)*c.amp*0.6;
        const r = c.size + Math.sin(time*0.25+c.drift)*6;

        // Multi-lobe cloud
        for (let l = 0; l < c.lobes; l++) {
            const la = (l/c.lobes)*Math.PI + Math.PI*0.5;
            const lx = cx+Math.cos(la)*r*0.4;
            const ly = cy+Math.sin(la)*r*0.25;
            const lr = r*(0.38 + (l === Math.floor(c.lobes/2) ? 0.12 : 0));

            const lg = ctx.createRadialGradient(lx,ly,0, lx,ly,lr);
            lg.addColorStop(0, rgb(C2, 0.025));
            lg.addColorStop(0.6, rgb(C1, 0.012));
            lg.addColorStop(1, rgb(C2, 0));
            ctx.beginPath(); ctx.arc(lx,ly,lr,0,Math.PI*2);
            ctx.fillStyle = lg; ctx.fill();

            // Swirl outline
            ctx.beginPath();
            ctx.arc(lx,ly,lr, Math.PI*0.7, Math.PI*2.3);
            ctx.strokeStyle = rgb(C2, 0.04);
            ctx.lineWidth = 0.6; ctx.stroke();
        }
    });
}

/* == Main =========================================================== */
function draw(time) {
    updateSegs(time);
    drawClouds(time);
    drawBody();
    drawScales(time);
    drawBellyPlates();
    drawMane(time);
    drawOutline();
    drawLegs(time);
    drawTail(time);
    drawHead(time);
    drawPearl(time);
}

/* -- Loop ----------------------------------------------------------- */
let animFrame = null, lastTime = 0;
function animate(ts) {
    if (!active) return;
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    canvas.style.opacity = isDark ? "1" : "0";
    if (!isDark) { animFrame = requestAnimationFrame(animate); return; }
    const dt = lastTime ? (ts-lastTime)/1000 : 0.016;
    lastTime = ts; t += dt;
    ctx.clearRect(0,0,W,H);
    draw(t);
    animFrame = requestAnimationFrame(animate);
}

function activate() {
    if (active) return;
    active = true;
    resize();
    for (let i = 0; i < SEG; i++) segments.push({x:dragonX(i,0),y:dragonY(i,0),w:bodyW(i)});
    initClouds();
    canvas.style.opacity = "1";
    animFrame = requestAnimationFrame(animate);
    console.log("%c\uD83D\uDC09 The dragon awakens\u2026","color:#22D3EE;font-size:14px;font-weight:bold");
}

const observer = new MutationObserver(() => {
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    if (active) canvas.style.opacity = isDark ? "1" : "0";
});
observer.observe(document.documentElement, {attributes:true, attributeFilter:["data-theme"]});

})();
