// Java test program with a known split: work() calls hot(), which does four
// times the work of warm(), so hot() should get about 80% of the CPU time and
// warm() about 20%, all under work(). Run with -Xint, its methods stay
// interpreted.
//
// Usage: java Jit [rounds]   (each round takes about 10 ms with -Xint)

public class Jit {
    static long hot(long n) {
        long total = 0;
        for (long i = 0; i < n; i++) {
            total += i * i;
        }
        return total;
    }

    static long warm(long n) {
        long total = 0;
        for (long i = 0; i < n; i++) {
            total += i * i;
        }
        return total;
    }

    static long work(int rounds) {
        long sum = 0;
        for (int r = 0; r < rounds; r++) {
            sum += hot(1_600_000) + warm(400_000);
        }
        return sum;
    }

    public static void main(String[] args) {
        System.out.println(work(args.length > 0 ? Integer.parseInt(args[0]) : 50));
    }
}
