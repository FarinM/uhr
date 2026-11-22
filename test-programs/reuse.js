// JavaScript test program of functions that take one another's place: it
// makes gen_0() to gen_7() one at a time, and has each collected before it
// makes the next, so the runtime can keep the code of one where it kept
// that of another. Each runs as long as the others, so each should get an
// eighth of their time.
//
// Usage: node reuse.js [milliseconds]   (how long each function runs, 50)

const FUNCTIONS = 8;

function collector() {
  if (typeof Bun !== "undefined") return () => Bun.gc(true);
  require("v8").setFlagsFromString("--expose-gc");
  return require("vm").runInNewContext("gc");
}

function make(name) {
  return new Function(
    `return function ${name}(ms) {
       const end = Date.now() + ms;
       let total = 0;
       while (Date.now() < end) {
         for (let i = 0; i < 10000; i++) total += Math.sqrt(i ^ total);
       }
       return total;
     }`,
  )();
}

const collect = collector();
const ms = Number(process.argv[2] ?? 50);
for (let i = 0; i < FUNCTIONS; i++) {
  let made = make(`gen_${i}`);
  made(ms);
  made = null;
  collect();
  collect();
}
