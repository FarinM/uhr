<?php
// PHP test program with a known split: work() calls hot(), which does four
// times the work of warm(), so hot() should get about 80% of the CPU time and
// warm() about 20%, all under work().
//
// Usage: php jit.php [rounds]   (each round takes about 10 ms)

function hot($n) {
    $total = 0;
    for ($i = 0; $i < $n; $i++) {
        $total += $i * $i;
    }
    return $total;
}

function warm($n) {
    $total = 0;
    for ($i = 0; $i < $n; $i++) {
        $total += $i * $i;
    }
    return $total;
}

function work($rounds) {
    $sum = 0;
    for ($r = 0; $r < $rounds; $r++) {
        $sum += hot(1600000) + warm(400000);
    }
    return $sum;
}

echo work((int) ($argv[1] ?? 50)), "\n";
