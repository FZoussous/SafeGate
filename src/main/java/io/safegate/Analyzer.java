package io.safegate;
import java.net.IDN;
import java.net.URI;
import java.util.*;

public final class Analyzer {
    private static final Set<String> SHORTENERS = Set.of("bit.ly","tinyurl.com","t.co","is.gd","rb.gy");
    public record Finding(String level, String title, String detail) {}
    public record Report(String url, String risk, int score, List<Finding> findings) {}
    private Analyzer() {}
    public static Report analyze(String input) {
        if (input == null || input.isBlank()) throw new IllegalArgumentException("Enter a URL.");
        String candidate = input.strip();
        if (!candidate.matches("(?i)^[a-z][a-z0-9+.-]*://.*")) {
            candidate = "https://" + candidate;
        }
        URI uri;
        try { uri = URI.create(candidate); } catch (Exception e) { throw new IllegalArgumentException("Invalid URL syntax."); }
        String scheme = Objects.toString(uri.getScheme(), "").toLowerCase(Locale.ROOT);
        String host = uri.getHost();
        if ((!scheme.equals("https") && !scheme.equals("http")) || host == null || host.isBlank())
            throw new IllegalArgumentException("Use an HTTP or HTTPS URL with a valid hostname.");
        host = host.toLowerCase(Locale.ROOT);
        String ascii;
        try { ascii = IDN.toASCII(host); } catch (Exception e) { ascii = host; }
        List<Finding> fs = new ArrayList<>(); int score = 0;
        if (scheme.equals("http")) { fs.add(new Finding("CAUTION","Unencrypted HTTP","The URL does not use HTTPS.")); score += 15; }
        else fs.add(new Finding("INFO","HTTPS scheme","HTTPS does not prove the site itself is trustworthy."));
        if (uri.getUserInfo() != null) { fs.add(new Finding("HIGH","Credentials-like URL syntax","Text before @ can disguise the destination host.")); score += 30; }
        if (SHORTENERS.contains(ascii)) { fs.add(new Finding("CAUTION","URL shortener","The destination is hidden behind a shortened URL.")); score += 15; }
        if (ascii.startsWith("xn--") || ascii.contains(".xn--")) { fs.add(new Finding("CAUTION","IDN hostname","Inspect internationalized hostnames for lookalike characters.")); score += 15; }
        if (ascii.matches("\\d{1,3}(\\.\\d{1,3}){3}")) { fs.add(new Finding("CAUTION","Raw IP host","A public site using a raw IP deserves extra scrutiny.")); score += 10; }
        if (ascii.split("\\.").length >= 5) { fs.add(new Finding("INFO","Deep subdomain","This hostname has many labels.")); score += 5; }
        if (fs.stream().noneMatch(f -> f.level().equals("HIGH") || f.level().equals("CAUTION")))
            fs.add(new Finding("INFO","No obvious heuristic flags","No strong URL-pattern warning was found; reputation and content were not checked."));
        String risk = score >= 30 ? "HIGH RISK SIGNALS" : score >= 15 ? "CAUTION" : "LOW SIGNALS FOUND";
        return new Report(uri.toASCIIString(), risk, Math.min(score,100), List.copyOf(fs));
    }
}
