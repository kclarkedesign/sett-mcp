// Builds the animated logo SVGs in assets/ from the same motion model as the
// "Sett Reveal" study: an S of eight stones settles into the five-stone tile.
//
//   node scripts/build_motion.mjs
//
// Output is plain SVG with SMIL <animate> tags, so it plays inside a README <img>,
// keeps a transparent background, and stays sharp at any size.
//   sett-reveal.svg / sett-reveal-white.svg  "Settle" timing with the wordmark, plays once
//   sett-loading.svg / sett-loading-white.svg  "Snap" timing, no wordmark, loops

import { readFileSync, writeFileSync } from "node:fs";

const ASSETS = new URL("../assets/", import.meta.url);
const WORD_D = readFileSync(new URL("sett-logo.svg", ASSETS), "utf8").match(/<path d="([^"]+)"/)[1];
const INK = "#1D2A24", PAPER = "#EEF0EC", ACCENT = "#6E9B5A";

// The S: eight stones on a 100-unit grid (x, y, w, h). The tile's five stones add rx.
const S = [[26,7,38,14],[68,7,14,14],[18,25,20,14],[22,43,24,14],[50,43,28,14],[62,61,20,14],[18,79,14,14],[36,79,38,14]];
const T = [[18,24,36,24,8],[58,25,24,23,9],[18,52,14,25,7],[36,52,30,25,9],[70,52,12,24,6]];
const TARGET = [0,1,0,2,3,4,2,4];   // which tile stone each S stone travels to
const MERGES = new Set([2,6,7]);    // second arrivals fade as they overlap
const GREEN = 4;

const ease = {
  inOutCubic: t => t < .5 ? 4*t*t*t : 1 - Math.pow(-2*t + 2, 3) / 2,
  outCubic: t => 1 - Math.pow(1 - t, 3),
  outBack: t => { const c1 = 1.35, c3 = c1 + 1; return 1 + c3*Math.pow(t - 1, 3) + c1*Math.pow(t - 1, 2); },
  outExpo: t => t === 1 ? 1 : 1 - Math.pow(2, -10*t),
};
const VARIANTS = {
  settle: { dur: 1000, stagger: 60, curve: ease.outBack, lift: 0.06 },
  snap:   { dur: 480,  stagger: 22, curve: ease.outExpo, lift: 0 },
};

const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
const lerp = (a, b, t) => a + (b - a) * t;
const mix = (c1, c2, t) => {
  const p = c => [1,3,5].map(i => parseInt(c.slice(i, i + 2), 16));
  const [a, b] = [p(c1), p(c2)];
  return "#" + a.map((v, i) => Math.round(lerp(v, b[i], t)).toString(16).padStart(2, "0")).join("");
};

function timeline(name, withWord) {
  const v = VARIANTS[name];
  const moveAt = 620, moveEnd = moveAt + 7 * v.stagger + v.dur;
  const tileAt = moveAt + v.dur * 0.5, tileEnd = tileAt + 450;
  const wordAt = Math.max(moveEnd, tileEnd) + 120, wordEnd = wordAt + 600;
  return { v, moveAt, tileAt, tileEnd, wordAt, wordEnd, end: withWord ? wordEnd : Math.max(moveEnd, tileEnd) };
}

// The state of every shape at time t (ms). `dark` means drawn for a dark page.
function frame(t, name, word, dark) {
  const tl = timeline(name, word), v = tl.v;
  const stoneFrom = dark ? PAPER : INK, stoneTo = dark ? INK : PAPER;
  const tileP = ease.outCubic(clamp((t - tl.tileAt) / (tl.tileEnd - tl.tileAt)));
  const stones = S.map((s, i) => {
    const intro = ease.outCubic(clamp((t - i * 30) / 260));
    const raw = clamp((t - tl.moveAt - i * v.stagger) / v.dur);
    const p = v.curve(raw);
    const tg = T[TARGET[i]];
    let [x, y, w, h] = [lerp(s[0], tg[0], p), lerp(s[1], tg[1], p), lerp(s[2], tg[2], p), lerp(s[3], tg[3], p)];
    const rx = lerp(7, tg[4], clamp(p));
    const lift = 1 + v.lift * Math.sin(Math.PI * clamp(raw * 1.6)) * (raw < 0.62 ? 1 : 0);
    const sc = (0.85 + 0.15 * intro) * lift;
    const cx = x + w / 2, cy = y + h / 2;
    w *= sc; h *= sc; x = cx - w / 2; y = cy - h / 2;
    const fade = MERGES.has(i) ? 1 - clamp((raw - 0.8) / 0.2) : 1;
    return {
      x, y, width: Math.max(w, 0), height: Math.max(h, 0), rx: Math.min(rx, h / 2),
      fill: i === GREEN ? ACCENT : mix(stoneFrom, stoneTo, tileP), opacity: intro * fade,
    };
  });
  const wordP = word ? ease.inOutCubic(clamp((t - tl.wordAt) / (tl.wordEnd - tl.wordAt))) : 0;
  const ts = lerp(0.72, 1, tileP);
  return {
    shift: word ? lerp(120, 9, wordP) : 0,
    tile: { x: 50 - 50 * ts, y: 50 - 50 * ts, width: 100 * ts, height: 100 * ts, rx: 24 * ts, opacity: tileP },
    stones,
    word: { opacity: wordP, dx: 6 + lerp(14, 0, wordP) },
  };
}

const num = v => (Math.abs(v) < 5e-4 ? 0 : +v.toFixed(2));

function build({ name, word, dark, loop, holdMs, fps = 30 }) {
  const tl = timeline(name, word);
  const dur = tl.end + holdMs;
  const times = [];
  for (let t = 0; t < tl.end; t += 1000 / fps) times.push(t);
  times.push(tl.end);
  if (holdMs > 0) times.push(dur);
  const frames = times.map(t => frame(Math.min(t, tl.end), name, word, dark));
  const keyTimes = times.map(t => +(t / dur).toFixed(4)).join(";");
  const timing = `dur="${(dur / 1000).toFixed(3)}s" keyTimes="${keyTimes}" ` +
    (loop ? 'repeatCount="indefinite"' : 'fill="freeze"');

  // One <animate> per attribute; attributes that never change become plain attributes.
  const animated = (pick, attrs, fmt = num) => {
    const parts = [], fixed = [];
    for (const a of attrs) {
      const vals = frames.map(f => fmt(pick(f)[a]));
      if (vals.every(v => v === vals[0])) fixed.push(`${a}="${vals[0]}"`);
      else parts.push(`<animate attributeName="${a}" ${timing} values="${vals.join(";")}"/>`);
    }
    return { fixed: fixed.join(" "), parts: parts.join("") };
  };
  const shape = (tag, pick, attrs, extra = "") => {
    const a = animated(pick, attrs, v => (typeof v === "string" ? v : num(v)));
    return `<${tag} ${a.fixed}${extra}>${a.parts}</${tag}>`;
  };

  const first = frames[0], last = frames.at(-1);
  const tileFill = dark ? PAPER : INK;
  const shifts = frames.map(f => `${num(f.shift)} 0`);
  const wordShifts = frames.map(f => `${num(f.word.dx)} 0`);
  const translate = (vals, initial) =>
    `transform="translate(${initial})"><animateTransform attributeName="transform" type="translate" ${timing} values="${vals.join(";")}"/>`;

  const stones = S.map((_, i) => shape("rect", f => f.stones[i], ["x", "y", "width", "height", "rx", "fill", "opacity"])).join("\n    ");
  const tile = shape("rect", f => f.tile, ["x", "y", "width", "height", "rx", "opacity"], ` fill="${tileFill}"`);
  const wordEl = word
    ? `<g ${translate(wordShifts, wordShifts[0])}${shape("path", f => f.word, ["opacity"], ` fill="${tileFill}" d="${WORD_D}"`)}</g>`
    : "";

  // Word: the full lockup, with the canvas centered on where it comes to rest (x 9 to 329)
  // and wide enough that the wordmark never clips while it slides in. Loading: the tile.
  const viewBox = word ? "-111 -6 560 112" : "-6 -6 112 112";
  const size = word ? 'width="560" height="112"' : 'width="112" height="112"';
  const label = word ? "Sett" : "Loading";
  const group = word ? `<g ${translate(shifts, shifts[0])}` : "<g>";
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${viewBox}" ${size} role="img" aria-label="${label}">
  <!-- Generated by scripts/build_motion.mjs. ${name} timing, ${loop ? "loops" : "plays once"}. -->
  ${group}
    ${tile}
    ${stones}
    ${wordEl}
  </g>
</svg>
`;
}

const outputs = {
  "sett-reveal.svg": { name: "settle", word: true, dark: false, loop: false, holdMs: 0 },
  "sett-reveal-white.svg": { name: "settle", word: true, dark: true, loop: false, holdMs: 0 },
  "sett-loading.svg": { name: "snap", word: false, dark: false, loop: true, holdMs: 700 },
  "sett-loading-white.svg": { name: "snap", word: false, dark: true, loop: true, holdMs: 700 },
};
for (const [file, opts] of Object.entries(outputs)) {
  const svg = build(opts);
  writeFileSync(new URL(file, ASSETS), svg);
  console.log(`${file}: ${(svg.length / 1024).toFixed(1)} KB`);
}
