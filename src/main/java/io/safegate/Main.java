package io.safegate;
import java.util.Scanner;
public class Main {
    public static void main(String[] args) {
        System.out.println("SafeGate — Check before you click. Type 'quit' to exit.");
        try (Scanner in = new Scanner(System.in)) {
            while (true) {
                System.out.print("\nURL> "); if (!in.hasNextLine()) break;
                String s = in.nextLine().trim(); if (s.equalsIgnoreCase("quit")) break;
                try {
                    var r = Analyzer.analyze(s);
                    System.out.printf("%n%s (heuristic score %d/100)%n%s%n", r.risk(), r.score(), r.url());
                    r.findings().forEach(f -> System.out.printf("- [%s] %s: %s%n", f.level(), f.title(), f.detail()));
                    System.out.println("This cannot guarantee safety; it does not open or crawl the site.");
                } catch (IllegalArgumentException e) { System.out.println("Input error: " + e.getMessage()); }
            }
        }
    }
}
