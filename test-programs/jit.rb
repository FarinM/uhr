# Ruby test program with a known split: work() calls hot(), which does four
# times the work of warm(), so hot() should get about 80% of the CPU time and
# warm() about 20%, all under work().
#
# Usage: ruby jit.rb [rounds]   (each round takes about 10 ms)

def hot(n)
  total = 0
  i = 0
  while i < n
    total += i * i
    i += 1
  end
  total
end

def warm(n)
  total = 0
  i = 0
  while i < n
    total += i * i
    i += 1
  end
  total
end

def work(rounds)
  sum = 0
  rounds.times { sum += hot(640_000) + warm(160_000) }
  sum
end

puts work((ARGV[0] || 50).to_i)
