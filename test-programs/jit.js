// JavaScript test program with a known split: work() calls hot(), which does
// four times the work of warm(), so hot() should get about 80% of the CPU
// time and warm() about 20%, all under work(). V8 can compile them into
// work()'s code, and then their time counts for work().
//
// Usage: node jit.js [rounds]   (each round takes about 10 ms)

function hot(n) {
  let total = 0;
  for (let i = 0; i < n; i++) total += i * i;
  return total;
}

function warm(n) {
  let total = 0;
  for (let i = 0; i < n; i++) total += i * i;
  return total;
}

function work(rounds) {
  let sum = 0;
  for (let r = 0; r < rounds; r++) sum += hot(16000000) + warm(4000000);
  return sum;
}

console.log(work(Number(process.argv[2] ?? 50)));
