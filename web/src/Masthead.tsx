import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { api } from "./api";
import { formatBytes } from "./util";

/* The dashboard's masthead, on a green phosphor CRT: "NASSCAN" decodes out of falling hash
 * digits, a read head sweeps down the screen every few seconds (glitching what it passes),
 * and a hex dump of "the file being read" scrolls under a typed status line. Drawn as
 * characters on a canvas, after Atelier ASCII's Terminal theme (#03110A under a #147A3D,
 * #33FF8A, #C8FFE0 ramp, with glow, scanlines and vignette; the last two are CSS). */

const ROWS = 14;
const LINE = 13; // px per row
const PAD = 6; // px above and below the grid
const FONT = '600 12px ui-monospace, "Cascadia Mono", Consolas, monospace';
const WORD_TOP = 1;
const TAGLINE = 8;
const RULE = 9; // the line between the screen and the hex dump
const FPS = 30;

// Atelier ASCII's Terminal theme.
const BG = "#03110a";
const DIM = [20, 122, 61]; // #147A3D
const MID = [51, 255, 138]; // #33FF8A
const HI = [200, 255, 224]; // #C8FFE0
const SHADOW = "#0b3d20";

function rgba([r, g, b]: number[], a: number) {
  return `rgba(${r},${g},${b},${a})`;
}

const SCRAMBLE = "!<>-_\\/[]{}=+*^?#%01ABCDEF";
const HEX = "0123456789abcdef";

// 5x5 letters; the masthead shears them into italics.
const LETTERS: Record<string, string[]> = {
  N: ["X...X", "XX..X", "X.X.X", "X..XX", "X...X"],
  A: [".XXX.", "X...X", "XXXXX", "X...X", "X...X"],
  S: [".XXXX", "X....", ".XXX.", "....X", "XXXX."],
  C: [".XXXX", "X....", "X....", "X....", ".XXXX"],
};
const WORD = "NASSCAN";

// Every 7 s from 2.5 s in, the read head sweeps top to bottom in 1.6 s.
const SWEEP_FIRST = 2.5;
const SWEEP_EVERY = 7;
const SWEEP_TAKES = 1.6;

const pick = (chars: string) => chars[Math.floor(Math.random() * chars.length)];

interface Drop {
  col: number;
  y: number; // head row, fractional
  speed: number; // rows a second
  len: number;
  chars: string[];
}

/** What depends on the canvas width: the grid, the wordmark's cells, the rain, the dump. */
interface Scene {
  width: number;
  cw: number; // px per column
  cols: number;
  word: Int8Array; // per cell: 0 empty, 1 letter, 2 its extruded shadow
  letterRow: Int8Array;
  lockAt: Float32Array; // when each letter cell stops scrambling
  drops: Drop[];
  dump: string[]; // hex dump lines, oldest first
  offset: number; // the next dump line's address
  dumpClock: number;
}

function newDrop(cols: number, top: boolean): Drop {
  const len = 3 + Math.floor(Math.random() * 6);
  return {
    col: Math.floor(Math.random() * cols),
    y: top ? -Math.random() * 10 : Math.random() * TAGLINE,
    speed: 4 + Math.random() * 9,
    len,
    chars: Array.from({ length: len }, () => pick(HEX)),
  };
}

// Bytes that look like the inside of real files: headers, text, padding.
const SNIPPETS = ["MZ\x90\x00", "PK\x03\x04", "%PDF-1.7", "\x7fELF", "ftypisom", "<?xml ", "#!/bin/sh", "\x00\x00\x00\x00"];

function dumpLine(offset: number, cols: number): string {
  const bytes: number[] = [];
  const width = cols >= 78 ? 16 : 8;
  if (Math.random() < 0.3) {
    for (const ch of SNIPPETS[Math.floor(Math.random() * SNIPPETS.length)]) bytes.push(ch.charCodeAt(0) & 255);
  }
  while (bytes.length < width) bytes.push(Math.random() < 0.25 ? 0 : Math.floor(Math.random() * 256));
  const hex = bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ");
  const text = bytes.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
  return `${offset.toString(16).padStart(8, "0")}  ${hex}  ${text}`;
}

function buildScene(width: number, cw: number): Scene {
  const cols = Math.max(1, Math.floor(width / cw));
  const word = new Int8Array(cols * ROWS);
  const letterRow = new Int8Array(cols * ROWS);
  const lockAt = new Float32Array(cols * ROWS);
  const scale = cols >= 100 ? 2 : 1;
  const gap = cols >= 48 ? scale + 1 : 1;
  const shear = (r: number) => Math.floor(((4 - r) * scale) / 2);
  const wide = WORD.length * 5 * scale + (WORD.length - 1) * gap + shear(0);
  const x0 = Math.floor((cols - wide) / 2);
  [...WORD].forEach((ch, li) => {
    LETTERS[ch].forEach((line, r) => {
      [...line].forEach((px, k) => {
        if (px !== "X") return;
        for (let sx = 0; sx < scale; sx++) {
          const c = x0 + li * (5 * scale + gap) + k * scale + sx + shear(r);
          if (c < 0 || c >= cols) continue;
          const i = (WORD_TOP + r) * cols + c;
          word[i] = 1;
          letterRow[i] = r;
          lockAt[i] = 0.3 + Math.random() * 0.9 + ((c - x0) / wide) * 0.5;
        }
      });
    });
  });
  // Extrude down and to the right.
  for (let i = word.length - cols - 2; i >= 0; i--) {
    const j = i + cols + 1;
    if (word[i] === 1 && word[j] === 0 && j % cols !== 0) word[j] = 2;
  }
  const drops = Array.from({ length: Math.ceil(cols / 7) }, () => newDrop(cols, false));
  let offset = 0x3a000 + Math.floor(Math.random() * 0x1000) * 16;
  const dump: string[] = [];
  for (let i = 0; i < ROWS - RULE - 1; i++) {
    dump.push(dumpLine(offset, cols));
    offset += cols >= 78 ? 16 : 8;
  }
  return { width, cw, cols, word, letterRow, lockAt, drops, dump, offset, dumpClock: 0 };
}

interface Status {
  files?: number;
  threats?: number;
  scanning?: { seen: number; read: number };
}

function tagline(s: Status): string {
  if (s.scanning) {
    return `> SCANNING ▸ ${s.scanning.seen.toLocaleString()} FILES ▸ ${formatBytes(s.scanning.read).toUpperCase()} READ`;
  }
  if (s.files === undefined) return "> MOUNTING /scan READ-ONLY";
  const clock = new Date().toLocaleTimeString([], { hour12: false });
  const threats = s.threats ? `${s.threats} OPEN THREAT${s.threats === 1 ? "" : "S"}` : "ALL CLEAR";
  return `> ${s.files.toLocaleString()} FILES WATCHED ▸ ${threats} ▸ ${clock}`;
}

/** One frame at t seconds. Glyphs go on `glyphs` (transparent), which is then laid on the
 * background twice: sharp, and blurred for the glow. */
function draw(
  out: CanvasRenderingContext2D,
  glyphs: CanvasRenderingContext2D,
  s: Scene,
  t: number,
  text: string,
  alarm: boolean,
) {
  const { cw, cols, word } = s;
  const g = glyphs;
  const at = (ch: string, c: number, r: number, color: string, dx = 0) => {
    g.fillStyle = color;
    g.fillText(ch, c * cw + dx, PAD + r * LINE);
  };
  g.clearRect(0, 0, g.canvas.width, g.canvas.height);
  g.font = FONT;
  g.textBaseline = "top";

  // The read head: a row position sweeping down, off screen between sweeps.
  const phase = t >= SWEEP_FIRST ? (t - SWEEP_FIRST) % SWEEP_EVERY : Infinity;
  const head = phase < SWEEP_TAKES ? (phase / SWEEP_TAKES) * (ROWS + 4) - 2 : -99;
  const near = (r: number) => Math.max(0, 1 - Math.abs(r - head) / 1.6);

  const typed = Math.max(0, Math.floor((t - 1.6) * 30));
  const shown = text.slice(0, typed) + (Math.floor(t * 2) % 2 ? " " : "█");
  const tx = Math.max(0, Math.floor((cols - text.length - 1) / 2));

  // Hash rain above the rule, behind the letters and the tagline.
  const free = (c: number, r: number) =>
    word[r * cols + c] === 0 && !(r === TAGLINE && c >= tx - 1 && c <= tx + text.length + 1);
  for (const d of s.drops) {
    for (let i = 0; i < d.len; i++) {
      const r = Math.floor(d.y) - i;
      if (r < 0 || r >= RULE || !free(d.col, r)) continue;
      const lit = near(r);
      const color = i === 0 ? rgba(HI, 0.9) : rgba(lit ? MID : DIM, Math.min(1, (1 - i / d.len) * 0.6 + lit * 0.4));
      at(d.chars[(r + d.len) % d.len], d.col, r, color);
    }
  }

  // The rule, and the hex dump of whatever's being "read" below it.
  for (let c = 0; c < cols; c++) at("─", c, RULE, rgba(DIM, 0.9));
  const label = " READING ";
  at(label, 2, RULE, rgba(MID, 0.9));
  s.dump.forEach((line, k) => {
    const r = RULE + 1 + k;
    const newest = k === s.dump.length - 1;
    const alpha = 0.25 + (k / s.dump.length) * 0.45 + near(r) * 0.3;
    const x = Math.max(0, Math.floor((cols - line.length) / 2));
    for (let i = 0; i < line.length && x + i < cols; i++) {
      if (line[i] !== " ") at(line[i], x + i, r, newest && i < 8 ? rgba(MID, 0.9) : rgba(DIM.map((v, j) => v + (MID[j] - v) * alpha), Math.min(1, alpha + 0.2)));
    }
  });

  // The wordmark: shadow, then letters decoding, shimmering, and glitched by the read head.
  for (let i = 0; i < word.length; i++) {
    if (!word[i]) continue;
    const c = i % cols;
    const r = Math.floor(i / cols);
    if (word[i] === 2) {
      if (t >= s.lockAt[i - cols - 1]) at("▒", c, r, SHADOW);
      continue;
    }
    const lock = s.lockAt[i];
    if (t < lock - 0.7) continue;
    if (t < lock || Math.abs(r - head) < 0.6) {
      at(pick(SCRAMBLE), c, r, t < lock ? rgba(MID, 0.8) : rgba(HI, 1));
      continue;
    }
    const top = s.letterRow[i] === 0;
    const ch = Math.sin(c * 0.25 - t * 2.5 + r * 0.6) > 0.92 ? "▓" : "█";
    if (near(r) > 0) {
      g.globalCompositeOperation = "lighter";
      at(ch, c, r, rgba(HI, 0.5 * near(r)), -1);
      at(ch, c, r, rgba(DIM, 0.6 * near(r)), 1);
      g.globalCompositeOperation = "source-over";
    }
    at(ch, c, r, top ? rgba(HI, 0.95) : rgba(MID, 1));
  }

  // The read head itself: a faint bright band.
  if (head > -2 && head < ROWS + 1) {
    g.fillStyle = rgba(HI, 0.07);
    g.fillRect(0, PAD + (head - 0.5) * LINE, g.canvas.width, LINE);
  }

  // The status line; open threats blink.
  const blinkOff = alarm && Math.floor(t * 2.5) % 2 === 0;
  at(shown.slice(0, 1), tx, TAGLINE, rgba(HI, 1));
  for (let k = 1; k < shown.length; k++) {
    const inAlarm = alarm && /\d+ OPEN THREAT/.test(text) && k >= text.indexOf("▸") + 2 && k < text.lastIndexOf("▸") - 1;
    const color = k === shown.length - 1 && shown[k] === "█" ? rgba(HI, 1) : inAlarm ? rgba(HI, blinkOff ? 0.35 : 1) : rgba(MID, 0.95);
    at(shown[k], tx + k, TAGLINE, color);
  }

  // Composite: background, sharp glyphs, then a blurred copy added for the glow.
  const w = out.canvas.width;
  const h = out.canvas.height;
  const bg = out.createLinearGradient(0, 0, 0, h);
  bg.addColorStop(0, "#04160d");
  bg.addColorStop(0.6, BG);
  bg.addColorStop(1, "#010805");
  out.setTransform(1, 0, 0, 1, 0, 0);
  out.fillStyle = bg;
  out.fillRect(0, 0, w, h);
  out.drawImage(g.canvas, 0, 0);
  out.globalCompositeOperation = "lighter";
  out.globalAlpha = 0.6;
  out.filter = `blur(${Math.round((w / s.width) * 4)}px)`;
  out.drawImage(g.canvas, 0, 0);
  out.filter = "none";
  out.globalAlpha = 1;
  out.globalCompositeOperation = "source-over";
}

function advance(s: Scene, dt: number) {
  for (const d of s.drops) {
    d.y += d.speed * dt;
    if (Math.random() < dt * 4) d.chars[Math.floor(Math.random() * d.len)] = pick(HEX);
    if (d.y - d.len > RULE) Object.assign(d, newDrop(s.cols, true));
  }
  // A new dump line about four times a second.
  s.dumpClock += dt;
  while (s.dumpClock > 0.25) {
    s.dumpClock -= 0.25;
    s.dump.shift();
    s.dump.push(dumpLine(s.offset, s.cols));
    s.offset += s.cols >= 78 ? 16 : 8;
  }
}

export function Masthead() {
  const stats = useQuery({ queryKey: ["file-stats"], queryFn: api.fileStats, refetchInterval: 60_000 });
  const summary = useQuery({ queryKey: ["finding-summary"], queryFn: api.findingSummary });
  const runs = useQuery({ queryKey: ["runs", 20], queryFn: () => api.runs(20) });
  const wrap = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const status = useRef<Status>({});
  const redrawStill = useRef<() => void>(() => {});

  const active = runs.data?.find((r) => r.status === "running");
  const threats = (summary.data?.counts.open?.malicious ?? 0) + (summary.data?.counts.open?.suspicious ?? 0);
  const files = stats.data?.files;
  const seen = active?.files_seen;
  const read = active?.bytes_hashed;

  useEffect(() => {
    const box = wrap.current;
    const out = canvas.current?.getContext("2d");
    const glyphs = document.createElement("canvas").getContext("2d");
    if (!box || !out || !glyphs) return;
    const still = window.matchMedia("(prefers-reduced-motion: reduce)");
    let scene: Scene | null = null;
    let frame = 0;
    let visible = true;
    let last = 0;
    const start = performance.now();

    const render = (t: number) => {
      if (!scene) return;
      const dpr = window.devicePixelRatio || 1;
      glyphs.setTransform(dpr, 0, 0, dpr, 0, 0);
      const st = status.current;
      draw(out, glyphs, scene, t, tagline(st), !!st.threats && !st.scanning);
    };
    // Reduced motion: one settled frame (after the decode, between sweeps).
    const renderStill = () => render(6);
    redrawStill.current = () => still.matches && renderStill();

    const resize = () => {
      const dpr = window.devicePixelRatio || 1;
      const width = box.clientWidth;
      const height = ROWS * LINE + PAD * 2;
      for (const c of [out.canvas, glyphs.canvas]) {
        c.width = Math.round(width * dpr);
        c.height = Math.round(height * dpr);
      }
      glyphs.font = FONT;
      scene = buildScene(width, glyphs.measureText("M").width);
      if (still.matches) renderStill();
    };

    const tick = (now: number) => {
      frame = 0;
      if (!visible || still.matches) return;
      frame = requestAnimationFrame(tick);
      if (now - last < 1000 / FPS || !scene) return;
      advance(scene, Math.min(0.1, (now - last) / 1000));
      last = now;
      render((now - start) / 1000);
    };
    const play = () => {
      if (still.matches) renderStill();
      else if (visible && !frame) frame = requestAnimationFrame(tick);
    };

    const sized = new ResizeObserver(resize);
    sized.observe(box);
    const seenObs = new IntersectionObserver(([e]) => {
      visible = e.isIntersecting;
      play();
    });
    seenObs.observe(box);
    still.addEventListener("change", play);
    resize();
    play();
    return () => {
      cancelAnimationFrame(frame);
      sized.disconnect();
      seenObs.disconnect();
      still.removeEventListener("change", play);
    };
  }, []);

  // With reduced motion the still frame waits for the figures.
  useEffect(() => {
    status.current = {
      files,
      threats,
      scanning: seen !== undefined ? { seen, read: read ?? 0 } : undefined,
    };
    redrawStill.current();
  }, [files, threats, seen, read]);

  const label =
    files === undefined
      ? "NAS Scanner"
      : `NAS Scanner: ${files.toLocaleString()} files watched, ${threats ? `${threats} open threats` : "all clear"}`;
  return (
    <div ref={wrap} className="masthead" role="img" aria-label={label}>
      <canvas ref={canvas} />
    </div>
  );
}
