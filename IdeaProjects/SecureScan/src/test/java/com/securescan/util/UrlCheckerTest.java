package com.securescan.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class UrlCheckerTest {

    private UrlChecker urlChecker;

    @BeforeEach
    void setUp() {
        urlChecker = new UrlChecker();
    }

    // ── extractUrls() ──────────────────────────────────────────

    @Test
    void testExtractUrls_findsHttpsUrl() {
        String text = "Click here: https://evil.com/login";
        List<String> urls = urlChecker.extractUrls(text);
        assertFalse(urls.isEmpty());
        assertTrue(urls.get(0).contains("evil.com"));
    }

    @Test
    void testExtractUrls_emptyText_returnsEmpty() {
        List<String> urls = urlChecker.extractUrls("");
        assertTrue(urls.isEmpty());
    }

    @Test
    void testExtractUrls_multipleUrls() {
        String text = "Visit https://google.com and http://evil.ru/verify";
        List<String> urls = urlChecker.extractUrls(text);
        assertEquals(2, urls.size());
    }

    // ── checkUrls() ────────────────────────────────────────────

    @Test
    void testCheckUrls_rawIp_isMalicious() {
        List<String> urls = List.of("http://192.168.1.1/verify");
        Map<String, UrlChecker.UrlStatus> results = urlChecker.checkUrls(urls);
        UrlChecker.UrlStatus status = results.get("http://192.168.1.1/verify");
        assertEquals(UrlChecker.Threat.MALICIOUS, status.threat);
    }

    @Test
    void testCheckUrls_legitimateDomain_isClean() {
        List<String> urls = List.of("https://accounts.google.com/login");
        Map<String, UrlChecker.UrlStatus> results = urlChecker.checkUrls(urls);
        UrlChecker.UrlStatus status = results.get("https://accounts.google.com/login");
        assertEquals(UrlChecker.Threat.CLEAN, status.threat);
    }

    @Test
    void testCheckUrls_urlShortener_isSuspicious() {
        List<String> urls = List.of("https://bit.ly/abc123");
        Map<String, UrlChecker.UrlStatus> results = urlChecker.checkUrls(urls);
        UrlChecker.UrlStatus status = results.get("https://bit.ly/abc123");
        assertEquals(UrlChecker.Threat.SUSPICIOUS, status.threat);
    }

    @Test
    void testCheckUrls_openRedirect_isMalicious() {
        List<String> urls = List.of("https://safe.com/go?url=https://evil.com");
        Map<String, UrlChecker.UrlStatus> results = urlChecker.checkUrls(urls);
        UrlChecker.UrlStatus status = results.get("https://safe.com/go?url=https://evil.com");
        assertEquals(UrlChecker.Threat.MALICIOUS, status.threat);
    }

    @Test
    void testCheckUrls_freeHosting_isSuspicious() {
        List<String> urls = List.of("https://mysite.netlify.app/verify");
        Map<String, UrlChecker.UrlStatus> results = urlChecker.checkUrls(urls);
        UrlChecker.UrlStatus status = results.get("https://mysite.netlify.app/verify");
        assertEquals(UrlChecker.Threat.SUSPICIOUS, status.threat);
    }

    // ── isFlagged() ────────────────────────────────────────────

    @Test
    void testIsFlagged_cleanUrl_returnsFalse() {
        List<String> urls = List.of("https://accounts.google.com/login");
        Map<String, UrlChecker.UrlStatus> results = urlChecker.checkUrls(urls);
        assertFalse(results.get("https://accounts.google.com/login").isFlagged());
    }

    @Test
    void testIsFlagged_maliciousUrl_returnsTrue() {
        List<String> urls = List.of("http://192.168.1.1/verify");
        Map<String, UrlChecker.UrlStatus> results = urlChecker.checkUrls(urls);
        assertTrue(results.get("http://192.168.1.1/verify").isFlagged());
    }
}