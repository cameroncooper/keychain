const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const context = vm.createContext({});
vm.runInContext(fs.readFileSync(`${__dirname}/../shared/forms/menu.js`, "utf8"), context);
const place = context.KeychainFormMenu.placement;
const viewport = { left: 0, top: 0, width: 800, height: 600 };
const field = (top, bottom, left = 100, right = 380) => ({ top, bottom, left, right });
test("menu uses its measured height and stays below when it fits", () => {
  const p = place(field(400, 432), viewport, 70);
  assert.equal(p.side, "below");
  assert.equal(p.top, 436);
  assert.equal(p.height, 70);
});
test("menu flips above a low field and clamps horizontally", () => {
  const p = place(field(540, 572, 700, 790), viewport, 200);
  assert.equal(p.side, "above");
  assert.equal(p.top + p.height, 536);
  assert.equal(p.left + p.width, 792);
});
test("menu scrolls on the roomier side without crossing the input", () => {
  const p = place(field(280, 312), viewport, 800);
  assert.equal(p.side, "below");
  assert.equal(p.height, 276);
  assert.equal(p.top, 316);
});
test("visual viewport offsets and narrow widths are honored", () => {
  const p = place(field(350, 382, 80, 240), {left: 50, top: 300, width: 220, height: 300}, 120);
  assert.equal(p.width, 204);
  assert.equal(p.left, 58);
  assert.equal(p.top, 386);
});
test("unusable space, offscreen anchors and invalid dimensions hide the menu", () => {
  assert.equal(place(field(20, 580), viewport, 200), null);
  assert.equal(place(field(650, 682), viewport, 200), null);
  assert.equal(place(field(20, 52), viewport, NaN), null);
  assert.equal(place(field(20, 52), {...viewport, width: 10}, 200), null);
});
test("placement invariants hold throughout the viewport", () => {
  for (const width of [180, 360, 800]) for (const height of [180, 400, 800]) {
    const bounds = {...viewport, width, height};
    for (let top = 8; top < height - 40; top += 19) for (const natural of [48, 180, 900]) {
      const anchor = field(top, top + 32, width - 100, width - 8);
      const p = place(anchor, bounds, natural);
      if (!p) continue;
      assert.ok(p.left >= 8 && p.left + p.width <= width - 8);
      assert.ok(p.top >= 8 && p.top + p.height <= height - 8);
      assert.ok(p.top >= anchor.bottom + 4 || p.top + p.height <= anchor.top - 4);
      assert.ok(p.height <= 320);
    }
  }
});
