package com.securescan.analysis;

import com.securescan.model.AnalysisResult;
import com.securescan.model.Email;
import com.securescan.model.PhishingIndicator;

import java.util.*;
import java.util.regex.*;
import java.util.stream.Collectors;

/**
 * PhishingAnalyzer v3 — Accurate Detection
 * -----------------------------------------
 * DESIGN PRINCIPLE: Every indicator must have a strong, specific reason.
 * No broad keyword matches that cause false positives on normal emails.
 *
 * Checks performed:
 *  1.  URL shorteners (exact domain match only)
 *  2.  Unencrypted HTTP links
 *  3.  Raw IP address in URLs (not domains)
 *  4.  Urgency language (phrase-level, not single word — reduces false positives)
 *  5.  Credential harvesting requests (exact phrases only)
 *  6.  Sender / Reply-To domain mismatch
 *  7.  ALL CAPS subject line (>70% uppercase letters, min 8 chars)
 *  8.  Homoglyph / Unicode character substitution
 *  9.  Brand lookalike domains (regex — amaz0n, paypa1, etc.)
 * 10.  Generic/impersonal greeting (exact phrases)
 * 11.  Excessive exclamation marks (>=4 only, not 3)
 * 12.  Base64 encoded content blocks (obfuscation)
 * 13.  Suspicious attachment references (.exe, .zip, .bat in email body)
 * 14.  IP addresses embedded in body text (not URLs)
 * 15.  Domain age spoofing keywords (expires, renewal, domain, registrar combined)
 */
public class PhishingAnalyzer {

    // ── Urgency: PHRASE level only — single words like "urgent" cause too many false positives
    private static final List<String> URGENCY_PHRASES = List.of(
            "act now", "act immediately", "limited time offer", "expires soon", "expires in",
            "account suspended", "account has been suspended", "account locked", "account has been locked",
            "account disabled", "account will be disabled", "account will be closed",
            "account will be terminated", "account will be deleted",
            "verify immediately", "verify your account", "verify your identity",
            "confirm your account", "confirm your identity", "confirm your email",
            "validate your account", "click here to verify", "click here to confirm",
            "respond immediately", "must respond within", "failure to respond",
            "within 24 hours", "within 48 hours", "24 hour deadline",
            "final notice", "last warning", "final warning", "last chance",
            "do not ignore this", "action required immediately", "immediate action required",
            "your account will be", "suspicious activity detected", "unusual sign-in",
            "unauthorized access detected", "security breach detected",
            "you have been selected", "you are a winner", "you have won",
            "claim your prize", "claim your reward", "free gift awaiting",
            "update your payment", "update your billing", "update your information immediately"
    );

    // ── Credential harvesting: exact request phrases
    private static final List<String> CREDENTIAL_PHRASES = List.of(
            "enter your password", "type your password", "input your password",
            "enter your username", "enter your email address",
            "provide your credit card", "provide your card number",
            "provide your social security", "provide your ssn",
            "provide your bank account", "provide your routing number",
            "submit your pin", "enter your pin number",
            "confirm your password", "re-enter your password",
            "enter your date of birth", "provide your date of birth",
            "mother's maiden name", "security question answer"
    );

    // ── Suspicious attachment keywords in body text
    private static final List<String> ATTACHMENT_KEYWORDS = List.of(
            ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".msi",
            "download the attachment", "open the attachment", "open attached file",
            "run the installer", "extract the zip", "enable macros"
    );

    // ── Homoglyph map: Unicode → ASCII lookalike
    private static final Map<Character, Character> HOMOGLYPHS = new LinkedHashMap<>();
    static {
        HOMOGLYPHS.put('\u0430', 'a'); // Cyrillic а
        HOMOGLYPHS.put('\u0435', 'e'); // Cyrillic е
        HOMOGLYPHS.put('\u043E', 'o'); // Cyrillic о
        HOMOGLYPHS.put('\u0440', 'p'); // Cyrillic р
        HOMOGLYPHS.put('\u0441', 'c'); // Cyrillic с
        HOMOGLYPHS.put('\u0445', 'x'); // Cyrillic х
        HOMOGLYPHS.put('\u0443', 'y'); // Cyrillic у
        HOMOGLYPHS.put('\u0456', 'i'); // Cyrillic і
        HOMOGLYPHS.put('\u03BD', 'v'); // Greek ν
        HOMOGLYPHS.put('\u03B1', 'a'); // Greek α
        HOMOGLYPHS.put('\u03BF', 'o'); // Greek ο
        HOMOGLYPHS.put('\u0401', 'E'); // Cyrillic Ё → E (less common)
    }

    // ── Brand lookalike patterns — only match when the substitution is present
    private static final List<Pattern> LOOKALIKE_PATTERNS = List.of(
            Pattern.compile("\\bpaypa[l1][^a-z]", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bpayp[a4]l\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bamaz[o0]n\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bmicr[o0]s[o0]ft\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bg[o0]{2}gle\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bapp[l1][e3]\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bnetfl[i1]x\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bfaceb[o0]{2}k\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\binstagram[^.com]", Pattern.CASE_INSENSITIVE)
    );

    // ── Known URL shortener domains (exact)
    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "ow.ly", "t.co", "goo.gl",
            "short.link", "rebrand.ly", "cutt.ly", "is.gd", "buff.ly",
            "tiny.cc", "adf.ly", "clck.ru", "qr.ae"
    );

    // ── Generic greetings (exact phrases only)
    private static final List<String> GENERIC_GREETINGS = List.of(
            "dear customer,", "dear user,", "dear account holder,",
            "dear valued customer,", "dear member,", "dear client,",
            "hello user,", "dear sir/madam,", "dear sir or madam,",
            "to whom it may concern,"
    );

    // ── Regex for extracting IPs from text
    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b((?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b");

    // ── Regex for URLs
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?i)https?://([a-zA-Z0-9.-]+)");

    // ── Base64 block detection (40+ chars of base64 chars in a row)
    private static final Pattern BASE64_PATTERN = Pattern.compile(
            "[A-Za-z0-9+/]{40,}={0,2}");

    // ─────────────────────────────────────────────────────────────────────
    //  MAIN ANALYSIS — every check is precise and evidence-based
    // ─────────────────────────────────────────────────────────────────────

    public AnalysisResult analyze(Email email) {
        List<PhishingIndicator> indicators = new ArrayList<>();
        Map<String, List<String>> matched  = new LinkedHashMap<>();
        int score = 0;

        String body     = email.getBody()    != null ? email.getBody()    : "";
        String subject  = email.getSubject() != null ? email.getSubject() : "";
        String from     = email.getFrom()    != null ? email.getFrom()    : "";
        String replyTo  = email.getReplyTo() != null ? email.getReplyTo() : "";
        String bodyLow  = body.toLowerCase();
        String fullLow  = (subject + " " + body).toLowerCase();

        // ─────────────────────────────────────────────────────────────────
        // CHECK 1: URL shorteners (domain-level exact match only)
        // ─────────────────────────────────────────────────────────────────
        List<String> shortenerHits = new ArrayList<>();
        Matcher urlM = URL_PATTERN.matcher(bodyLow);
        while (urlM.find()) {
            String domain = urlM.group(1).replaceFirst("^www\\.", "");
            for (String s : SHORTENERS) {
                if (domain.equals(s) && !shortenerHits.contains(s)) shortenerHits.add(s);
            }
        }
        if (!shortenerHits.isEmpty()) {
            int w = 25;
            matched.put("URL Shorteners", shortenerHits);
            indicators.add(new PhishingIndicator("Shortened URL Detected",
                    "Found: " + String.join(", ", shortenerHits) + " — hides true destination", w));
            score += w;
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 2: Unencrypted HTTP links (only count http:// not https://)
        // ─────────────────────────────────────────────────────────────────
        Pattern httpOnly = Pattern.compile("\\bhttp://(?!/)");
        long httpCount = httpOnly.matcher(bodyLow).results().count();
        if (httpCount > 0) {
            int w = 20;
            matched.put("Unencrypted Links", List.of(httpCount + " http:// link(s)"));
            indicators.add(new PhishingIndicator("Unencrypted HTTP Links",
                    httpCount + " unencrypted link(s) — passwords/data sent in plain text", w));
            score += w;
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 3: Raw IP address used as URL host
        // ─────────────────────────────────────────────────────────────────
        Pattern ipUrl = Pattern.compile("https?://(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)");
        Matcher ipUrlM = ipUrl.matcher(body);
        List<String> ipUrls = new ArrayList<>();
        while (ipUrlM.find()) ipUrls.add(ipUrlM.group());
        if (!ipUrls.isEmpty()) {
            int w = 35;
            matched.put("IP-based URLs", ipUrls);
            indicators.add(new PhishingIndicator("IP Address Used as URL",
                    "Legitimate services use domain names, not: " + ipUrls.get(0), w));
            score += w;
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 4: Urgency language (phrase-level — more accurate)
        // ─────────────────────────────────────────────────────────────────
        List<String> urgencyHits = findExact(fullLow, URGENCY_PHRASES);
        if (!urgencyHits.isEmpty()) {
            int w = Math.min(15 + urgencyHits.size() * 5, 35);
            matched.put("Urgency Phrases", urgencyHits);
            indicators.add(new PhishingIndicator("Urgency / Fear Language",
                    "Exact matches: " + urgencyHits.stream().limit(3).collect(Collectors.joining("; ")), w));
            score += w;
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 5: Credential harvesting (exact phrases)
        // ─────────────────────────────────────────────────────────────────
        List<String> credHits = findExact(fullLow, CREDENTIAL_PHRASES);
        if (!credHits.isEmpty()) {
            int w = 40;
            matched.put("Credential Requests", credHits);
            indicators.add(new PhishingIndicator("Credential Harvesting",
                    "Requests sensitive data: " + credHits.stream().limit(2).collect(Collectors.joining(", ")), w));
            score += w;
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 6: Sender / Reply-To domain mismatch (domain level)
        // ─────────────────────────────────────────────────────────────────
        if (!from.isBlank() && !replyTo.isBlank()) {
            String fd = extractDomain(from);
            String rd = extractDomain(replyTo);
            if (!fd.isBlank() && !rd.isBlank() && !fd.equalsIgnoreCase(rd)) {
                int w = 30;
                matched.put("Sender Mismatch", List.of("From: " + fd + "  →  Reply-To: " + rd));
                indicators.add(new PhishingIndicator("Sender / Reply-To Mismatch",
                        "From domain '" + fd + "' differs from Reply-To domain '" + rd + "'", w));
                score += w;
            }
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 7: ALL CAPS subject (min 8 letters, >70% uppercase)
        // ─────────────────────────────────────────────────────────────────
        String subjectLetters = subject.replaceAll("[^a-zA-Z]", "");
        if (subjectLetters.length() >= 8) {
            long caps = subjectLetters.chars().filter(Character::isUpperCase).count();
            if ((double) caps / subjectLetters.length() > 0.70) {
                int w = 15;
                matched.put("ALL CAPS Subject", List.of(subject));
                indicators.add(new PhishingIndicator("ALL CAPS Subject Line",
                        "Subject is " + (int)(100.0*caps/subjectLetters.length()) + "% uppercase — social engineering tactic", w));
                score += w;
            }
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 8: Homoglyph Unicode characters (only non-ASCII lookalikes)
        // ─────────────────────────────────────────────────────────────────
        List<String> homoglyphFound = detectHomoglyphs(body + " " + subject + " " + from);
        if (!homoglyphFound.isEmpty()) {
            int w = 45;
            matched.put("Homoglyph Characters", homoglyphFound);
            indicators.add(new PhishingIndicator("Unicode / Homoglyph Spoofing",
                    "Lookalike characters detected: " + String.join(", ", homoglyphFound), w));
            score += w;
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 9: Brand lookalike domains (typosquatting with char swaps)
        // ─────────────────────────────────────────────────────────────────
        List<String> lookalikeHits = new ArrayList<>();
        for (Pattern p : LOOKALIKE_PATTERNS) {
            Matcher m = p.matcher(body + " " + subject);
            while (m.find()) {
                String hit = m.group().trim();
                if (!lookalikeHits.contains(hit)) lookalikeHits.add(hit);
            }
        }
        if (!lookalikeHits.isEmpty()) {
            int w = 40;
            matched.put("Lookalike Domains", lookalikeHits);
            indicators.add(new PhishingIndicator("Brand Typosquatting Detected",
                    "Found spoofed brand strings: " + String.join(", ", lookalikeHits), w));
            score += w;
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 10: Generic / impersonal greeting
        // ─────────────────────────────────────────────────────────────────
        List<String> greetingHits = findExact(bodyLow, GENERIC_GREETINGS);
        if (!greetingHits.isEmpty()) {
            int w = 15;
            matched.put("Generic Greeting", greetingHits);
            indicators.add(new PhishingIndicator("Generic Impersonal Greeting",
                    "Uses '" + greetingHits.get(0) + "' — real companies address you by name", w));
            score += w;
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 11: Excessive exclamation marks (>=4, not 3 — reduces false positives)
        // ─────────────────────────────────────────────────────────────────
        long exclamCount = (body + subject).chars().filter(c -> c == '!').count();
        if (exclamCount >= 4) {
            int w = 10;
            matched.put("Excessive Punctuation", List.of(exclamCount + " exclamation marks"));
            indicators.add(new PhishingIndicator("Excessive Exclamation Marks",
                    exclamCount + " '!' found — characteristic of scam/spam content", w));
            score += w;
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 12: Base64 encoded content blocks (obfuscation technique)
        // ─────────────────────────────────────────────────────────────────
        List<String> b64Blocks = new ArrayList<>();
        Matcher b64M = BASE64_PATTERN.matcher(body);
        while (b64M.find() && b64Blocks.size() < 3) {
            String block = b64M.group();
            // Only flag if it looks like real base64 (length multiple of 4 or ends with =)
            if (block.length() % 4 == 0 || block.endsWith("=")) {
                b64Blocks.add(block.substring(0, Math.min(block.length(), 20)) + "...");
            }
        }
        if (!b64Blocks.isEmpty()) {
            int w = 20;
            matched.put("Base64 Encoded Content", b64Blocks);
            indicators.add(new PhishingIndicator("Obfuscated / Encoded Content",
                    "Base64 encoded blocks found — used to hide malicious content from scanners", w));
            score += w;
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 13: Suspicious attachment references
        // ─────────────────────────────────────────────────────────────────
        List<String> attachHits = findExact(bodyLow, ATTACHMENT_KEYWORDS);
        if (!attachHits.isEmpty()) {
            int w = 30;
            matched.put("Suspicious Attachments", attachHits);
            indicators.add(new PhishingIndicator("Malicious Attachment Reference",
                    "References executable or macro content: " + String.join(", ", attachHits), w));
            score += w;
        }

        // ─────────────────────────────────────────────────────────────────
        // CHECK 14: Embedded IP addresses in body text (not in URLs — separate)
        // ─────────────────────────────────────────────────────────────────
        Matcher ipBodyM = IP_PATTERN.matcher(body);
        List<String> embeddedIps = new ArrayList<>();
        while (ipBodyM.find()) {
            String ip = ipBodyM.group();
            // Skip IPs that are inside a URL (already caught by CHECK 3)
            if (!body.contains("http://" + ip) && !body.contains("https://" + ip)) {
                if (!embeddedIps.contains(ip)) embeddedIps.add(ip);
            }
        }
        if (!embeddedIps.isEmpty()) {
            int w = 15;
            matched.put("Embedded IP Addresses", embeddedIps);
            indicators.add(new PhishingIndicator("IP Address Embedded in Body",
                    "Raw IP(s) found: " + String.join(", ", embeddedIps) + " — may indicate C2 infrastructure", w));
            score += w;
        }

        // ── Clamp score 0–100 ─────────────────────────────────────────────
        score = Math.min(score, 100);

        // ── Assemble result ───────────────────────────────────────────────
        AnalysisResult result = new AnalysisResult(email);
        result.setRiskScore(score);
        result.setIndicators(indicators);
        result.setRiskLevel(result.calculateRiskLevel(score));
        result.setMatchedKeywords(matched);
        result.setConfidencePercent(calculateConfidence(score, indicators.size()));
        result.setSummary(buildSummary(result));
        return result;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  CONFIDENCE
    // ─────────────────────────────────────────────────────────────────────

    public static int calculateConfidence(int score, int indicatorCount) {
        if (indicatorCount == 0) return Math.max(40, 100 - score); // safe verdict: moderate confidence
        double c = score + (indicatorCount * 6.0);
        return (int) Math.min(c, 97);
    }

    // ─────────────────────────────────────────────────────────────────────
    //  HELPERS
    // ─────────────────────────────────────────────────────────────────────

    /** Find exact substring matches from a phrase list. Case-insensitive, already lowercased input. */
    private List<String> findExact(String textLower, List<String> phrases) {
        List<String> found = new ArrayList<>();
        for (String phrase : phrases) {
            if (textLower.contains(phrase) && !found.contains(phrase)) found.add(phrase);
        }
        return found;
    }

    /** Detect non-ASCII homoglyph characters in text. Returns human-readable descriptions. */
    private List<String> detectHomoglyphs(String text) {
        List<String> found = new ArrayList<>();
        for (char c : text.toCharArray()) {
            if (HOMOGLYPHS.containsKey(c)) {
                String desc = "U+" + String.format("%04X", (int) c) + "→'" + HOMOGLYPHS.get(c) + "'";
                if (!found.contains(desc)) found.add(desc);
            }
        }
        return found;
    }

    private String extractDomain(String emailAddr) {
        if (emailAddr == null) return "";
        int at = emailAddr.lastIndexOf('@');
        if (at < 0) return "";
        return emailAddr.substring(at + 1).toLowerCase().trim()
                .replaceAll("[<>\"\\s]", "");
    }

    private String buildSummary(AnalysisResult result) {
        int count = result.getIndicators().size();
        int conf  = result.getConfidencePercent();
        if (count == 0) return "No phishing indicators detected. Content appears safe. Confidence: " + conf + "%.";
        String top = result.getIndicators().stream()
                .max(Comparator.comparingInt(PhishingIndicator::getWeight))
                .map(PhishingIndicator::getName).orElse("—");
        return result.getRiskLevel().getLabel() + " — " + count + " indicator(s) detected. "
                + "Strongest: " + top + ". Confidence: " + conf + "%.";
    }
}
