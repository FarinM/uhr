// Zooms into a block on click and highlights the blocks a search matches.
// Each block's group holds its start and width in the graph's time units,
// to place it again at any zoom, and the index of the block it is on, which
// says what is inside what. Times can be past what a number holds exactly,
// so they only place blocks.
"use strict";

let blocks, parents, children, details, matched, resetButton, searchButton;
let search = null;

function init() {
  blocks = Array.from(document.querySelectorAll("#blocks > g"));
  parents = blocks.map((block) => (block.dataset.p === undefined ? -1 : Number(block.dataset.p)));
  children = blocks.map(() => []);
  parents.forEach((parent, at) => {
    if (parent >= 0) {
      children[parent].push(at);
    }
  });
  details = document.getElementById("details");
  matched = document.getElementById("matched");
  resetButton = document.getElementById("reset");
  searchButton = document.getElementById("search");
  blocks.forEach((block, at) => {
    block.addEventListener("mouseover", () => {
      details.textContent = block.querySelector("title").textContent;
    });
    block.addEventListener("mouseout", () => {
      details.textContent = "";
    });
    block.addEventListener("click", () => zoom(at));
  });
  resetButton.addEventListener("click", () => zoom(null));
  searchButton.addEventListener("click", () => {
    if (search === null) {
      ask();
    } else {
      highlight(null);
    }
  });
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === "f") {
      event.preventDefault();
      ask();
    } else if (event.key === "Escape") {
      highlight(null);
    }
  });
}

function number(block, key) {
  return Number(block.dataset[key]);
}

// Places a block at `x`, `width` pixels wide, and fits its label in.
function place(block, x, width) {
  const rect = block.querySelector("rect");
  const text = block.querySelector("text");
  rect.setAttribute("x", x.toFixed(2));
  rect.setAttribute("width", Math.max(width - GAP, 0).toFixed(2));
  text.setAttribute("x", (x + PADDING).toFixed(2));
  text.textContent = fit(block.dataset.name, width);
}

// As much of `name` as fits, by its characters, as the SVG was drawn.
function fit(name, width) {
  const chars = Array.from(name);
  const room = Math.floor((width - 2 * PADDING) / CHAR_WIDTH);
  if (chars.length <= room) {
    return name;
  }
  return room >= 3 ? chars.slice(0, room - 2).join("") + ".." : "";
}

// Shows the block at `target` across the whole width with what it called
// above it, and what called it below, dimmed. `null` shows everything
// again.
function zoom(target) {
  const root = target ?? 0;
  const start = number(blocks[root], "x");
  const scale = WIDTH / number(blocks[root], "w");
  for (const block of blocks) {
    block.style.display = "none";
    block.classList.remove("caller");
  }
  const inside = [root];
  while (inside.length > 0) {
    const at = inside.pop();
    const block = blocks[at];
    block.style.display = "";
    place(block, MARGIN + (number(block, "x") - start) * scale, number(block, "w") * scale);
    inside.push(...children[at]);
  }
  for (let at = parents[root]; at >= 0; at = parents[at]) {
    blocks[at].style.display = "";
    blocks[at].classList.add("caller");
    place(blocks[at], MARGIN, WIDTH);
  }
  resetButton.style.display = target === null ? "none" : "";
}

function ask() {
  const term = prompt("Search for functions matching (a regular expression)", search ?? "");
  if (term === null || term === "") {
    return;
  }
  try {
    highlight(new RegExp(term));
    search = term;
  } catch (error) {
    alert(`Not a regular expression: ${error.message}`);
  }
}

// Marks the functions whose name matches, and says what share of the time
// they cover, counting a match inside another once. The block under all
// others is no function's.
function highlight(pattern) {
  const hits = blocks.map(
    (block, at) => pattern !== null && parents[at] >= 0 && pattern.test(block.dataset.name),
  );
  const under = blocks.map(() => false);
  let covered = 0;
  // Each block comes after the one it is on.
  blocks.forEach((block, at) => {
    const parent = parents[at];
    under[at] = parent >= 0 && (hits[parent] || under[parent]);
    block.classList.toggle("match", hits[at]);
    if (hits[at] && !under[at]) {
      covered += number(block, "w");
    }
  });
  if (pattern === null) {
    search = null;
    matched.textContent = "";
    searchButton.textContent = "Search";
    return;
  }
  const total = number(blocks[0], "w");
  matched.textContent = `Matched: ${((100 * covered) / total).toFixed(1)}%`;
  searchButton.textContent = "Clear search";
}
