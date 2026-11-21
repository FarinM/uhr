// uhr runs this with the Bun it records, to learn where that build keeps
// what uhr reads: it holds functions, strings and promises uhr knows, says
// where they are, and waits in frames uhr knows for uhr to read its stack.
// At each place it waits, it writes a line of JSON and reads a byte.
import { describe } from "bun:jsc";
import { readSync, writeSync } from "node:fs";
import vm from "node:vm";

const address = (value) => describe(value).match(/0x[0-9a-f]+/)[0];
const kept = [];
let said = {};

function uhrInner(marker, second, third) {
  const where = { inner: address(uhrInner), outer: address(uhrOuter), marker: address(marker) };
  writeSync(1, JSON.stringify({ ...said, ...where }) + "\n");
  readSync(0, Buffer.alloc(1));
  return [marker, second, third];
}

function uhrOuter(marker) {
  const result = uhrInner(marker, 2, 3);
  // Not a tail call, which would take this frame's place.
  kept.push(result);
  return result;
}

// Names of each length, of one byte a character and of two.
function uhrA() {}
function uhrBb() {}
function uhrCcc() {}
function uhrDddd() {}
function uhrEeeee() {}
function uhrFffffff() {}
function uhr一() {}
function uhr一二() {}
function uhr一二三() {}
function uhr一二三四() {}
function uhr一二三四五() {}
function uhr一二三四五六() {}
const uhrAssigned = function uhrOwnName() {};
// Named only for the constant they are, which some builds keep apart from
// the name a function gives itself.
const uhrConstant = function () {};
const uhrArrow = () => {};
// Written out, as reading a function's name gives it data uhr does not
// read through.
const names = [
  [uhrA, "uhrA"],
  [uhrBb, "uhrBb"],
  [uhrCcc, "uhrCcc"],
  [uhrDddd, "uhrDddd"],
  [uhrEeeee, "uhrEeeee"],
  [uhrFffffff, "uhrFffffff"],
  [uhrInner, "uhrInner"],
  [uhrOuter, "uhrOuter"],
  [uhrAssigned, "uhrOwnName"],
  [uhrConstant, "uhrConstant"],
  [uhrArrow, "uhrArrow"],
  [uhr一, "uhr一"],
  [uhr一二, "uhr一二"],
  [uhr一二三, "uhr一二三"],
  [uhr一二三四, "uhr一二三四"],
  [uhr一二三四五, "uhr一二三四五"],
  [uhr一二三四五六, "uhr一二三四五六"],
].map(([f, name]) => [address(f), name]);

// Promises in each state the frames that wait for one are found by.
const pending = () => new Promise(() => {});
const resolvedWithPending = () => (async () => pending())();
async function uhrWaits(promise) {
  await promise;
}
const promises = { pending: pending(), fulfilled: Promise.resolve(1), awaited: [], groups: {} };
for (const promise of [pending(), resolvedWithPending()]) {
  uhrWaits(promise);
  promises.awaited.push(promise);
}
for (const group of ["all", "allSettled", "any"]) {
  const members = [pending(), resolvedWithPending()];
  promises.groups[group] = { members, of: Promise[group](members) };
}
kept.push(promises);
const promiseAddresses = {
  pending: address(promises.pending),
  fulfilled: address(promises.fulfilled),
  awaited: promises.awaited.map(address),
  groups: Object.fromEntries(
    Object.entries(promises.groups).map(([group, { members, of }]) => [
      group,
      { members: members.map(address), of: address(of) },
    ]),
  ),
};

// Resumed once the module's code is done, with its state.
async function uhrAwaited(marker) {
  await null;
  uhrOuter(marker);
}
async function uhrAwaiter(promise) {
  await promise;
}
const marker = { uhr: true };
const awaited = uhrAwaited(marker);
const awaiter = uhrAwaiter(awaited);
kept.push(awaited, awaiter);

said = {
  phase: "module",
  version: Bun.version,
  path: import.meta.path,
  url: import.meta.url,
  names,
  promises: promiseAddresses,
};
uhrOuter(marker);

globalThis.uhrOuter = uhrOuter;
globalThis.uhrMarker = marker;
said = { phase: "program" };
vm.runInThisContext("uhrOuter(uhrMarker)", { filename: "uhr-probe-program" });

said = { phase: "eval" };
(0, eval)("uhrOuter(uhrMarker)");

said = { phase: "async", awaited: address(awaited), awaiter: address(awaiter) };
