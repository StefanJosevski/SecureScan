package com.securescan.util;

import java.net.URI;
import java.util.*;
import java.util.regex.*;

/**
 * UrlChecker v3 — Accurate URL Reputation
 * ----------------------------------------
 * FIXED: Previous version flagged every HTTPS URL containing "login", "verify"
 * etc. in the PATH — this caused massive false positives.
 *
 * Now: path keywords only flagged when COMBINED with other signals (not on
 * legitimate domains like accounts.google.com or login.microsoft.com).
 *
 * New checks:
 *  - Excessive subdomains (>3 dots in host only, not counting TLD)
 *  - Port number in URL (unusual for email links)
 *  - Unicode/IDN hostname (punycode — xn--) spoofing
 *  - Free hosting domains used for phishing
 *  - Redirect chains (/redirect?url=, /go?to=, etc.)
 */
public class UrlChecker {

    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?i)\\b((?:https?://|www\\.)[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])",
            Pattern.CASE_INSENSITIVE);

    // Exact shortener domains
    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly","tinyurl.com","ow.ly","t.co","goo.gl",
            "short.link","rebrand.ly","cutt.ly","is.gd","buff.ly",
            "tiny.cc","adf.ly","clck.ru","qr.ae");

    // Free hosting platforms frequently abused for phishing pages
    private static final Set<String> FREE_HOSTS = Set.of(
            "000webhostapp.com","weebly.com","wixsite.com","glitch.me",
            "netlify.app","vercel.app","web.app","firebaseapp.com",
            "pages.dev","github.io","replit.app","surge.sh");

    // Legitimate brand domains — don't flag these for path keywords
    private static final Set<String> LEGITIMATE_DOMAINS = Set.of(
            "google.com","microsoft.com","apple.com","amazon.com","paypal.com",
            "netflix.com","facebook.com","instagram.com","linkedin.com",
            "twitter.com","x.com","github.com","dropbox.com","ebay.com",
            "accounts.google.com","login.microsoft.com","signin.amazon.com",
            "id.apple.com","www.paypal.com","secure.paypal.com");

    // Redirect parameter patterns in URL
    private static final Pattern REDIRECT_PATTERN = Pattern.compile(
            "[?&](?:url|redirect|goto|next|target|return|redir)=https?://",
            Pattern.CASE_INSENSITIVE);

    // IP address pattern
    private static final Pattern IP_PATTERN = Pattern.compile(
            "^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$");

    // ─────────────────────────────────────────────────────────────────────

    public List<String> extractUrls(String text) {
        if (text == null || text.isBlank()) return List.of();
        List<String> urls = new ArrayList<>();
        Matcher m = URL_PATTERN.matcher(text);
        while (m.find()) {
            String url = m.group(1);
            if (!urls.contains(url)) urls.add(url);
        }
        return Collections.unmodifiableList(urls);
    }

    public Map<String, UrlStatus> checkUrls(List<String> urls) {
        Map<String, UrlStatus> results = new LinkedHashMap<>();
        for (String url : urls) results.put(url, check(url));
        return results;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  MAIN CHECK LOGIC
    // ─────────────────────────────────────────────────────────────────────

    private UrlStatus check(String url) {
        String lower = url.toLowerCase();
        try {
            String parseTarget = lower.startsWith("www.") ? "http://" + url : url;
            URI uri  = new URI(parseTarget);
            String host = uri.getHost();
            if (host == null) host = lower;
            host = host.toLowerCase().replaceFirst("^www\\.", "");

            // 1. MALICIOUS: IP address used as hostname
            if (IP_PATTERN.matcher(host).matches()) {
                return new UrlStatus(url, Threat.MALICIOUS,
                        "Raw IP address as hostname — legitimate sites use domain names");
            }

            // 2. MALICIOUS: IDN punycode (xn--) — Unicode domain spoofing
            if (host.contains("xn--")) {
                return new UrlStatus(url, Threat.MALICIOUS,
                        "Internationalised domain (IDN) — used for homograph spoofing attacks");
            }

            // 3. MALICIOUS: Open redirect in URL
            if (REDIRECT_PATTERN.matcher(url).find()) {
                return new UrlStatus(url, Threat.MALICIOUS,
                        "Open redirect detected — URL redirects to external site to evade detection");
            }

            // 4. SUSPICIOUS: Unencrypted HTTP
            if (lower.startsWith("http://")) {
                return new UrlStatus(url, Threat.SUSPICIOUS,
                        "Unencrypted HTTP — credentials and data sent in plain text");
            }

            // 5. SUSPICIOUS: Known URL shortener
            for (String s : SHORTENERS) {
                if (host.equals(s)) {
                    return new UrlStatus(url, Threat.SUSPICIOUS,
                            "URL shortener (" + s + ") — hides the true destination");
                }
            }

            // 6. SUSPICIOUS: Excessive subdomains (more than 4 dots in host, e.g. paypal.com.evil.ru)
            long dots = host.chars().filter(c -> c == '.').count();
            if (dots > 3) {
                return new UrlStatus(url, Threat.SUSPICIOUS,
                        "Excessive subdomains (" + dots + " levels) — likely subdomain spoofing");
            }

            // 7. SUSPICIOUS: Free hosting platform
            for (String fh : FREE_HOSTS) {
                if (host.endsWith(fh)) {
                    return new UrlStatus(url, Threat.SUSPICIOUS,
                            "Hosted on free platform (" + fh + ") — commonly abused for phishing pages");
                }
            }

            // 8. SUSPICIOUS: Non-standard port number (e.g. :8080, :3000)
            int port = uri.getPort();
            if (port != -1 && port != 80 && port != 443) {
                return new UrlStatus(url, Threat.SUSPICIOUS,
                        "Non-standard port :" + port + " — unusual for legitimate email links");
            }

            // 9. SUSPICIOUS: Brand name in subdomain of wrong TLD
            //    e.g. paypal.security-update.com — paypal is in subdomain, not the actual domain
            String[] parts = host.split("\\.");
            if (parts.length >= 3) {
                String actualDomain = parts[parts.length - 2] + "." + parts[parts.length - 1];
                String subdomainPart = host.replace("." + actualDomain, "");
                String[] brands = {"paypal","amazon","google","microsoft","apple","netflix","ebay","bank"};
                for (String brand : brands) {
                    if (subdomainPart.contains(brand) && !actualDomain.contains(brand)) {
                        return new UrlStatus(url, Threat.SUSPICIOUS,
                                "Brand '" + brand + "' appears in subdomain of '" + actualDomain + "' — spoofing technique");
                    }
                }
            }

            // 10. INFO: Path contains phishing keywords BUT only on non-legitimate domains
            if (!LEGITIMATE_DOMAINS.contains(host)) {
                String path = uri.getPath() != null ? uri.getPath().toLowerCase() : "";
                if (path.contains("verify") || path.contains("login") || path.contains("signin")
                        || path.contains("confirm") || path.contains("account") || path.contains("secure")
                        || path.contains("update-info") || path.contains("authenticate")) {
                    return new UrlStatus(url, Threat.SUSPICIOUS,
                            "Phishing-style path on non-official domain: " + path);
                }
            }

            return new UrlStatus(url, Threat.CLEAN, "No threats detected");

        } catch (Exception e) {
            return new UrlStatus(url, Threat.SUSPICIOUS, "URL could not be parsed — possibly malformed");
        }
    }

    // ─────────────────────────────────────────────────────────────────────

    public enum Threat { CLEAN, SUSPICIOUS, MALICIOUS }

    public static class UrlStatus {
        public final String url;
        public final Threat threat;
        public final String reason;

        public UrlStatus(String url, Threat threat, String reason) {
            this.url    = url;
            this.threat = threat;
            this.reason = reason;
        }

        public boolean isFlagged() { return threat != Threat.CLEAN; }
    }
}
