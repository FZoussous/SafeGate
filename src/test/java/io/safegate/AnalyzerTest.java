package io.safegate;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class AnalyzerTest {
 @Test void addsHttps() { assertTrue(Analyzer.analyze("example.com").url().startsWith("https://")); }
 @Test void flagsHttp() { assertEquals("CAUTION", Analyzer.analyze("http://example.com").risk()); }
 @Test void rejectsFtp() { assertThrows(IllegalArgumentException.class, () -> Analyzer.analyze("ftp://example.com")); }
 @Test void flagsCredentialsSyntax() { assertTrue(Analyzer.analyze("https://trusted.example@evil.example").score() >= 30); }
}
