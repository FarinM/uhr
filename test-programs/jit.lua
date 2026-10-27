-- Lua test program with a known split: work() calls hot(), which does four
-- times the work of warm(), so hot() should get about 80% of the CPU time and
-- warm() about 20%, all under work().
--
-- Usage: lua jit.lua [rounds]   (each round takes about 10 ms)

local function hot(n)
  local total = 0
  for i = 1, n do
    total = total + i * i
  end
  return total
end

local function warm(n)
  local total = 0
  for i = 1, n do
    total = total + i * i
  end
  return total
end

local function work(rounds)
  local sum = 0
  for _ = 1, rounds do
    sum = sum + hot(2400000) + warm(600000)
  end
  return sum
end

print(work(tonumber(arg[1]) or 50))
