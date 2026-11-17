// JavaScript test program of async functions that wait for one another:
// outer() for middle(), and middle() for inner(), which works only once it
// was resumed. None of the others is on the stack then, but all of work()'s
// time is theirs too.
//
// Usage: node await.js [rounds]   (each round takes about 20 ms)

function work(ms) {
  const end = Date.now() + ms;
  let total = 0;
  while (Date.now() < end) total += Math.sqrt(total + 1);
  return total;
}

async function inner() {
  await null;
  return work(20);
}

async function middle() {
  return await inner();
}

async function outer() {
  return await middle();
}

async function main(rounds) {
  let sum = 0;
  for (let r = 0; r < rounds; r++) sum += await outer();
  console.log(sum);
}

main(Number(process.argv[2] ?? 50));
