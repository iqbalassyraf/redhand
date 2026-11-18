import assert from "node:assert/strict";
import test from "node:test";

import { areaPath, bandPath, donutArcs, flowLayout, linePath, niceMax, scaleLinear, stack } from "../src/lib/chartGeometry.ts";

test("a linear scale maps the ends and the middle, and a flat domain does not divide by zero", () => {
  const s = scaleLinear([0, 10], [100, 0]);
  assert.equal(s(0), 100); assert.equal(s(10), 0); assert.equal(s(5), 50);
  assert.equal(scaleLinear([3, 3], [7, 9])(3), 7);
});

test("axes end on a round number: 1, 2 or 5 times a power of ten", () => {
  assert.equal(niceMax(0), 1); assert.equal(niceMax(-4), 1); assert.equal(niceMax(NaN), 1);
  assert.equal(niceMax(3), 5); assert.equal(niceMax(7), 10); assert.equal(niceMax(11250), 20000); assert.equal(niceMax(100), 100); assert.equal(niceMax(0.3), 0.5);
});

test("line and area paths are closed correctly and empty input gives an empty path", () => {
  assert.equal(linePath([{ x: 0, y: 1 }, { x: 2, y: 3 }]), "M0,1 L2,3");
  assert.equal(areaPath([{ x: 0, y: 1 }, { x: 2, y: 3 }], 10), "M0,1 L2,3 L2,10 L0,10 Z");
  assert.equal(areaPath([], 10), ""); assert.equal(linePath([]), "");
});

test("stacking adds layers on top of each other and the top layer equals the column sums", () => {
  const layers = stack([[1, 2, 3], [4, 0, 1], [0, 5, 0]]);
  assert.deepEqual(layers[0], { lower: [0, 0, 0], upper: [1, 2, 3] });
  assert.deepEqual(layers[1], { lower: [1, 2, 3], upper: [5, 2, 4] });
  assert.deepEqual(layers[2].upper, [5, 7, 4]);
  assert.deepEqual(stack([]), []);
});

test("a band path goes along the upper edge then back along the lower edge", () => {
  assert.equal(bandPath([0, 10], [0, 0], [5, 5], (v) => 100 - v), "M0,95 L10,95 L10,100 L0,100 Z");
  assert.equal(bandPath([], [], [], (v) => v), "");
});

test("donut arcs cover the full circle in order, ignore negatives, and a zero total gives none", () => {
  const arcs = donutArcs([50, 25, 25], 50, 50, 40, 25);
  assert.equal(arcs.length, 3);
  assert.ok(Math.abs(arcs[2].end - Math.PI * 2) < 1e-9);
  assert.deepEqual(arcs.map((a) => a.fraction), [0.5, 0.25, 0.25]);
  assert.ok(arcs.every((a) => !a.path.includes("NaN")));
  assert.deepEqual(donutArcs([0, 0, 0], 50, 50, 40, 25), []);
  assert.deepEqual(donutArcs([-5, 10], 50, 50, 40, 25).map((a) => a.fraction), [0, 1]);
});

test("a single full segment is drawn as a closed ring, a zero segment as nothing", () => {
  const [only, none] = donutArcs([10, 0], 50, 50, 40, 25);
  assert.ok(only.path.length > 0 && !only.path.includes("NaN"));
  assert.equal(none.path, "");
});

const SIZE = { width: 600, height: 200, nodeWidth: 10, gap: 6, minHeight: 4 };

test("flow layout: empty or all-zero input is an empty layout", () => {
  assert.deepEqual(flowLayout([], SIZE).nodes, []);
  assert.deepEqual(flowLayout([{ agent: "a", server: "s", outcome: "ALLOW", count: 0 }], SIZE).links, []);
});

test("flow layout: node totals, link widths and the three columns", () => {
  const rows = [
    { agent: "a1", server: "xero", outcome: "Allowed", count: 6 },
    { agent: "a1", server: "xero", outcome: "Refused", count: 2 },
    { agent: "a2", server: "github", outcome: "Allowed", count: 2 },
  ];
  const { nodes, links } = flowLayout(rows, SIZE);
  const node = (id) => nodes.find((n) => n.id === id);
  assert.equal(node("0:a1").value, 8); assert.equal(node("1:xero").value, 8); assert.equal(node("2:Allowed").value, 8); assert.equal(node("2:Refused").value, 2);
  assert.equal(links.length, 5); // two agent->server and three server->outcome
  assert.ok(nodes.every((n) => n.y >= 0 && n.y + n.height <= SIZE.height + 1e-6 && Number.isFinite(n.height)));
  assert.ok(links.every((l) => l.width >= 1 && !l.path.includes("NaN")));
});

test("flow layout: links leaving one node never overlap at their start", () => {
  const rows = [
    { agent: "a1", server: "x", outcome: "Allowed", count: 5 }, { agent: "a1", server: "y", outcome: "Allowed", count: 3 }, { agent: "a1", server: "z", outcome: "Refused", count: 2 },
  ];
  const { links } = flowLayout(rows, SIZE);
  const leaving = links.filter((l) => l.source === "0:a1").sort((a, b) => a.sy - b.sy);
  for (let i = 1; i < leaving.length; i += 1) assert.ok(leaving[i].sy - leaving[i].width / 2 >= leaving[i - 1].sy + leaving[i - 1].width / 2 - 1e-6);
});

test("a tiny node keeps its minimum height so it stays visible", () => {
  const { nodes } = flowLayout([{ agent: "big", server: "s", outcome: "Allowed", count: 1000 }, { agent: "tiny", server: "s", outcome: "Allowed", count: 1 }], SIZE);
  assert.ok(nodes.find((n) => n.id === "0:tiny").height >= SIZE.minHeight);
});
