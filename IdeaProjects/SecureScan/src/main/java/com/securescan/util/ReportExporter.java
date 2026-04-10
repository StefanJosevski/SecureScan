package com.securescan.util;

import com.securescan.model.AnalysisResult;
import com.securescan.model.PhishingIndicator;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

import java.awt.Color;
import java.io.*;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * ReportExporter v3
 * -----------------
 * Fixed coordinate system — PDF Y=0 is BOTTOM of page, Y=842 is TOP.
 * All sections drawn top-to-bottom by decrementing Y correctly.
 * Content stream operations: fill first, then text on top — never reversed.
 */
public class ReportExporter {

    private static final DateTimeFormatter DT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // A4 in points (1 pt = 1/72 inch)
    private static final float PW = 595f;  // page width
    private static final float PH = 842f;  // page height
    private static final float ML = 45f;   // left margin
    private static final float MR = 45f;   // right margin
    private static final float CW = PW - ML - MR; // content width = 505

    // ── Palette ───────────────────────────────────────────────────────────
    private static final Color NAVY     = col(0x0F1B2D);
    private static final Color CYAN     = col(0x0EA5E9);
    private static final Color CYAN_DIM = col(0x075985);
    private static final Color WHITE    = Color.WHITE;
    private static final Color OFFWHITE = col(0xF8FAFC);
    private static final Color LTGRAY   = col(0xE2E8F0);
    private static final Color MIDGRAY  = col(0x64748B);
    private static final Color DKTEXT   = col(0x1E293B);
    private static final Color GREEN    = col(0x15803D);
    private static final Color GREENBG  = col(0xDCFCE7);
    private static final Color AMBER    = col(0x92400E);
    private static final Color AMBERBG  = col(0xFEF3C7);
    private static final Color RED      = col(0xDC2626);
    private static final Color REDBG    = col(0xFEE2E2);
    private static final Color ROWA     = col(0xF1F5F9);
    private static final Color ROWB     = col(0xFFFFFF);

    // ── Fonts (loaded once) ───────────────────────────────────────────────
    // Note: fonts must be created inside export() because they're tied to the document.

    // ─────────────────────────────────────────────────────────────────────
    //  ENTRY POINT
    // ─────────────────────────────────────────────────────────────────────

    public static void export(AnalysisResult result, File out) throws Exception {
        try (PDDocument doc = new PDDocument()) {
            PDType1Font B  = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
            PDType1Font R  = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
            PDType1Font OB = new PDType1Font(Standard14Fonts.FontName.HELVETICA_OBLIQUE);

            PDPage p1 = new PDPage(PDRectangle.A4);
            doc.addPage(p1);

            try (PDPageContentStream cs = new PDPageContentStream(doc, p1,
                    PDPageContentStream.AppendMode.OVERWRITE, true, true)) {

                // Y starts at top of page and walks DOWN
                float y = PH;

                y = header(cs, B, R, result, y);
                y = riskSummary(cs, B, R, result, y);
                y = emailDetails(cs, B, R, result, y);
                y = securityChecks(cs, B, R, result, y);
                y = indicators(cs, B, R, result, y);
                y = matchedKeywords(cs, B, R, result, y);
                headerAnalysis(cs, B, R, result, y);
            }

            // Page 2: footer only visible on page 1
            footer(doc, B, R, result);

            doc.save(out);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  HEADER  (navy banner, title, timestamp)
    // ─────────────────────────────────────────────────────────────────────

    private static float header(PDPageContentStream cs,
                                PDType1Font B, PDType1Font R, AnalysisResult result, float y) throws IOException {

        float bannerH = 72f;
        // Navy banner — from top of page down 72pt
        rect(cs, NAVY, 0, PH - bannerH, PW, bannerH);
        // Cyan accent stripe at bottom of banner
        rect(cs, CYAN, 0, PH - bannerH - 3, PW, 3);

        // Title
        txt(cs, B, 20, WHITE, ML, PH - 30, "SecureScan  --  Phishing & Threat Analysis Report");
        // Subtitle
        txt(cs, R, 9, CYAN, ML, PH - 48,
                "Generated: " + DT.format(result.getAnalysisDate())
                        + "    Subject: " + clip(result.getEmail().getSubject(), 52));
        // Version tag
        txt(cs, B, 8, CYAN_DIM, PW - MR - 88, PH - 64, "SECURESCAN  v3.0");

        return PH - bannerH - 3 - 10; // return Y below the banner+stripe+gap
    }

    // ─────────────────────────────────────────────────────────────────────
    //  RISK SUMMARY  (big verdict box + score bar)
    // ─────────────────────────────────────────────────────────────────────

    private static float riskSummary(PDPageContentStream cs,
                                     PDType1Font B, PDType1Font R, AnalysisResult result, float y) throws IOException {

        y -= 8;
        float boxH = 52f;

        Color bg  = rBg(result.getRiskLevel());
        Color fg  = rFg(result.getRiskLevel());
        Color bdr = rBdr(result.getRiskLevel());

        // Verdict box (left 220pt)
        rect(cs, bg,  ML, y - boxH, 220, boxH);
        border(cs, bdr, ML, y - boxH, 220, boxH, 1.5f);
        txt(cs, B, 16, fg, ML + 10, y - 22, rLabel(result.getRiskLevel()));
        txt(cs, R,  9, fg, ML + 10, y - 38, result.getConfidencePercent() + "% detection confidence  ("
                + result.getConfidenceLabel() + ")");
        txt(cs, R,  8, fg, ML + 10, y - 50, result.getIndicators().size() + " indicator(s) detected");

        // Score bar area (right side)
        float bx = ML + 232;
        float bw = CW - 232;

        txt(cs, B, 10, DKTEXT, bx, y - 12, "Risk Score: " + result.getRiskScore() + " / 100");

        // Bar background
        rect(cs, LTGRAY, bx, y - 32, bw, 13);
        // Bar fill
        float fill = bw * result.getRiskScore() / 100f;
        Color barC = result.getRiskScore() < 30 ? GREEN
                : result.getRiskScore() < 70 ? col(0xD97706) : RED;
        if (fill > 0) rect(cs, barC, bx, y - 32, fill, 13);

        txt(cs, R, 9, MIDGRAY, bx, y - 46,
                "0          Low          Medium          High          100");

        // Summary text
        txt(cs, R, 9, DKTEXT, bx, y - 52, clip(result.getSummary(), 72));

        return y - boxH - 12;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  EMAIL DETAILS TABLE
    // ─────────────────────────────────────────────────────────────────────

    private static float emailDetails(PDPageContentStream cs,
                                      PDType1Font B, PDType1Font R, AnalysisResult result, float y) throws IOException {

        y -= 4;
        y = sectionHead(cs, B, "EMAIL DETAILS", y);

        String[][] rows = {
                { "From",      ns(result.getEmail().getFrom())    },
                { "Reply-To",  ns(result.getEmail().getReplyTo()) },
                { "Subject",   ns(result.getEmail().getSubject()) },
                { "Scan Time", DT.format(result.getAnalysisDate()) }
        };

        for (int i = 0; i < rows.length; i++) {
            float rowH = 17f;
            Color bg = i % 2 == 0 ? ROWA : ROWB;
            rect(cs, bg, ML, y - rowH, CW, rowH);
            txt(cs, B, 9, col(0x1D4ED8), ML + 4,  y - 12, rows[i][0] + ":");
            txt(cs, R, 9, DKTEXT,        ML + 72,  y - 12, clip(rows[i][1], 90));
            y -= rowH;
        }

        return y - 8;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  SECURITY CHECKS SUMMARY TABLE
    // ─────────────────────────────────────────────────────────────────────

    private static float securityChecks(PDPageContentStream cs,
                                        PDType1Font B, PDType1Font R, AnalysisResult result, float y) throws IOException {

        y -= 4;
        y = sectionHead(cs, B, "SECURITY CHECKS", y);

        // Build check items from result data
        List<String[]> checks = new java.util.ArrayList<>();

        // SPF
        String spf = result.getHeaderSpf();
        if (!spf.isBlank()) {
            boolean pass = spf.equalsIgnoreCase("PASS");
            checks.add(new String[]{ "SPF Authentication", spf.toUpperCase(), pass ? "PASS" : "FAIL" });
        }
        // DKIM
        String dkim = result.getHeaderDkim();
        if (!dkim.isBlank()) {
            boolean present = !dkim.equals("Not present");
            checks.add(new String[]{ "DKIM Signature", present ? dkim : "Not present", present ? "PASS" : "FAIL" });
        }
        // URL check
        long flaggedUrls = result.getIndicators().stream()
                .filter(i -> i.getName().contains("URL") || i.getName().contains("Link")).count();
        checks.add(new String[]{ "URL Reputation", flaggedUrls > 0 ? flaggedUrls + " flagged" : "Clean", flaggedUrls > 0 ? "FAIL" : "PASS" });

        // Sender check
        boolean senderMismatch = result.getIndicators().stream()
                .anyMatch(i -> i.getName().contains("Mismatch") || i.getName().contains("Spoof"));
        checks.add(new String[]{ "Sender Identity", senderMismatch ? "Mismatch detected" : "Consistent", senderMismatch ? "FAIL" : "PASS" });

        // IP check
        String ip = result.getHeaderOriginatingIp();
        checks.add(new String[]{ "Originating IP", ip.isBlank() ? "Not found in headers" : ip, ip.isBlank() ? "N/A" : "INFO" });

        for (int i = 0; i < checks.size(); i++) {
            float rowH = 16f;
            Color bg = i % 2 == 0 ? ROWA : ROWB;
            rect(cs, bg, ML, y - rowH, CW, rowH);

            String status = checks.get(i)[2];
            Color statusColor = switch (status) {
                case "PASS" -> GREEN;
                case "FAIL" -> RED;
                default     -> MIDGRAY;
            };

            txt(cs, B, 9, DKTEXT,     ML + 4,       y - 11, checks.get(i)[0]);
            txt(cs, R, 9, MIDGRAY,    ML + 160,      y - 11, clip(checks.get(i)[1], 55));
            txt(cs, B, 8, statusColor, ML + CW - 38, y - 11, "[" + status + "]");
            y -= rowH;
        }

        return y - 8;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  INDICATORS TABLE
    // ─────────────────────────────────────────────────────────────────────

    private static float indicators(PDPageContentStream cs,
                                    PDType1Font B, PDType1Font R, AnalysisResult result, float y) throws IOException {

        List<PhishingIndicator> inds = result.getIndicators();
        y -= 4;
        y = sectionHead(cs, B, "PHISHING INDICATORS (" + inds.size() + " found)", y);

        if (inds.isEmpty()) {
            rect(cs, GREENBG, ML, y - 22, CW, 22);
            txt(cs, B, 10, GREEN, ML + 10, y - 15, "No phishing indicators detected — content appears safe.");
            return y - 30;
        }

        // Column header row
        float colH = 16f;
        rect(cs, NAVY, ML, y - colH, CW, colH);
        txt(cs, B, 8, WHITE, ML + 4,         y - 11, "INDICATOR");
        txt(cs, B, 8, WHITE, ML + 200,        y - 11, "DETAIL");
        txt(cs, B, 8, WHITE, ML + CW - 46,   y - 11, "WEIGHT");
        y -= colH;

        for (int i = 0; i < inds.size(); i++) {
            if (y < 80) break; // stop before footer
            PhishingIndicator ind = inds.get(i);
            boolean danger = ind.getWeight() >= 25;
            Color bg = danger ? REDBG : AMBERBG;
            Color fg = danger ? RED   : AMBER;
            float rh = 26f;

            rect(cs, bg, ML,     y - rh, CW, rh);
            rect(cs, fg, ML,     y - rh, 4,  rh); // left colour tab

            txt(cs, B, 9, fg,      ML + 8,      y - 10, clip(ind.getName(), 32));
            txt(cs, R, 8, MIDGRAY, ML + 8,      y - 20, clip(ind.getDescription(), 38));
            txt(cs, R, 8, DKTEXT,  ML + 200,    y - 15, clip(ind.getDescription(), 44));
            txt(cs, B, 9, fg,      ML + CW - 40, y - 15, "+" + ind.getWeight() + " pt");

            // divider
            line(cs, LTGRAY, ML, y - rh, ML + CW, y - rh, 0.4f);
            y -= rh;
        }

        return y - 8;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  MATCHED KEYWORDS
    // ─────────────────────────────────────────────────────────────────────

    private static float matchedKeywords(PDPageContentStream cs,
                                         PDType1Font B, PDType1Font R, AnalysisResult result, float y) throws IOException {

        Map<String, List<String>> kws = result.getMatchedKeywords();
        if (kws.isEmpty() || y < 100) return y;

        y -= 4;
        y = sectionHead(cs, B, "MATCHED THREAT KEYWORDS", y);

        for (Map.Entry<String, List<String>> entry : kws.entrySet()) {
            if (y < 80) break;
            float rh = 18f;
            rect(cs, ROWA, ML, y - rh, CW, rh);
            txt(cs, B, 9, col(0x1D4ED8), ML + 4,  y - 12, entry.getKey() + ":");
            String words = String.join(", ", entry.getValue()).substring(0,
                    Math.min(String.join(", ", entry.getValue()).length(), 88));
            txt(cs, R, 9, DKTEXT, ML + 120, y - 12, words);
            y -= rh;
        }

        return y - 8;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  HEADER ANALYSIS (if parsed)
    // ─────────────────────────────────────────────────────────────────────

    private static float headerAnalysis(PDPageContentStream cs,
                                        PDType1Font B, PDType1Font R, AnalysisResult result, float y) throws IOException {

        if (!result.isHeaderParsed() || y < 100) return y;

        y -= 4;
        y = sectionHead(cs, B, "EMAIL HEADER FORENSICS", y);

        String[][] rows = {
                { "Originating IP",  ns(result.getHeaderOriginatingIp()) },
                { "Received From",   ns(result.getHeaderReceivedFrom())  },
                { "DKIM",            ns(result.getHeaderDkim())          },
                { "SPF Result",      ns(result.getHeaderSpf())           },
                { "Return-Path",     ns(result.getHeaderReturnPath())    }
        };

        for (int i = 0; i < rows.length; i++) {
            if (y < 80) break;
            float rh = 16f;
            rect(cs, i % 2 == 0 ? ROWA : ROWB, ML, y - rh, CW, rh);
            txt(cs, B, 9, MIDGRAY, ML + 4,  y - 11, rows[i][0] + ":");
            txt(cs, R, 9, DKTEXT,  ML + 115, y - 11, clip(rows[i][1], 80));
            y -= rh;
        }

        return y - 8;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  FOOTER  (drawn at bottom of page 1 last, after all content)
    //  Uses a separate pass so it always lands at y=36 regardless of content
    // ─────────────────────────────────────────────────────────────────────

    private static void footer(PDDocument doc, PDType1Font B, PDType1Font R,
                               AnalysisResult result) throws IOException {
        // Re-open page 1 content stream to append footer
        PDPage page1 = doc.getPage(0);
        try (PDPageContentStream cs = new PDPageContentStream(doc, page1,
                PDPageContentStream.AppendMode.APPEND, true, true)) {

            rect(cs, NAVY, 0, 0, PW, 34);
            line(cs, CYAN, 0, 34, PW, 34, 1.5f);

            txt(cs, R, 8, CYAN, ML, 12,
                    "SecureScan Phishing Intelligence Platform  |  Confidential — For security review only");

            String verdict = result.getRiskLevel().getLabel().toUpperCase()
                    + "  |  Score: " + result.getRiskScore() + "/100"
                    + "  |  Confidence: " + result.getConfidencePercent() + "%";
            float vw = strWidth(R, 8, verdict);
            txt(cs, R, 8, CYAN, PW - MR - vw, 12, verdict);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  PRIMITIVES
    // ─────────────────────────────────────────────────────────────────────

    private static float sectionHead(PDPageContentStream cs,
                                     PDType1Font B, String title, float y) throws IOException {
        float h = 18f;
        rect(cs, NAVY, ML, y - h, CW, h);
        rect(cs, CYAN, ML, y - h, 3,  h);
        txt(cs, B, 9, WHITE, ML + 7, y - 12, title);
        return y - h - 2;
    }

    /** Draw filled rectangle. In PDF: x,y is BOTTOM-LEFT corner. */
    private static void rect(PDPageContentStream cs, Color c,
                             float x, float y, float w, float h) throws IOException {
        cs.setNonStrokingColor(c);
        cs.addRect(x, y, w, h);
        cs.fill();
    }

    /** Draw stroked rectangle border. */
    private static void border(PDPageContentStream cs, Color c,
                               float x, float y, float w, float h, float lw) throws IOException {
        cs.setStrokingColor(c);
        cs.setLineWidth(lw);
        cs.addRect(x, y, w, h);
        cs.stroke();
    }

    /** Draw a horizontal line. */
    private static void line(PDPageContentStream cs, Color c,
                             float x1, float y1, float x2, float y2, float lw) throws IOException {
        cs.setStrokingColor(c);
        cs.setLineWidth(lw);
        cs.moveTo(x1, y1);
        cs.lineTo(x2, y2);
        cs.stroke();
    }

    /**
     * Draw text. x,y is the BASELINE position (left edge, baseline).
     * In PDF this is straightforward — just call newLineAtOffset then showText.
     */
    private static void txt(PDPageContentStream cs, PDType1Font font,
                            int size, Color color, float x, float y, String text) throws IOException {
        if (text == null || text.isBlank()) return;
        cs.beginText();
        cs.setNonStrokingColor(color);
        cs.setFont(font, size);
        cs.newLineAtOffset(x, y);
        cs.showText(safe(text));
        cs.endText();
    }

    private static float strWidth(PDType1Font font, int size, String text) {
        try {
            return font.getStringWidth(safe(text)) / 1000f * size;
        } catch (Exception e) {
            return text.length() * size * 0.5f;
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  HELPERS
    // ─────────────────────────────────────────────────────────────────────

    private static Color col(int hex) {
        return new Color((hex >> 16) & 0xFF, (hex >> 8) & 0xFF, hex & 0xFF);
    }

    private static String safe(String s) {
        if (s == null) return "";
        // PDFBox Type1 fonts only support printable ASCII 0x20-0x7E
        return s.replaceAll("[^\\x20-\\x7E]", "?");
    }

    private static String clip(String s, int max) {
        if (s == null || s.isBlank()) return "--";
        String a = safe(s).trim();
        return a.length() > max ? a.substring(0, max - 2) + ".." : a;
    }

    private static String ns(String s) {
        return (s == null || s.isBlank()) ? "--" : s;
    }

    // Risk colour helpers
    private static Color rBg(AnalysisResult.RiskLevel l) {
        return switch (l) { case SAFE -> GREENBG; case SUSPICIOUS -> AMBERBG; case MALICIOUS -> REDBG; };
    }
    private static Color rFg(AnalysisResult.RiskLevel l) {
        return switch (l) { case SAFE -> GREEN; case SUSPICIOUS -> AMBER; case MALICIOUS -> RED; };
    }
    private static Color rBdr(AnalysisResult.RiskLevel l) {
        return switch (l) {
            case SAFE       -> col(0x86EFAC);
            case SUSPICIOUS -> col(0xFCD34D);
            case MALICIOUS  -> col(0xFCA5A5);
        };
    }
    private static String rLabel(AnalysisResult.RiskLevel l) {
        return switch (l) {
            case SAFE       -> "SAFE  --  No threats detected";
            case SUSPICIOUS -> "SUSPICIOUS  --  Review recommended";
            case MALICIOUS  -> "MALICIOUS  --  Do not interact";
        };
    }

    // ─────────────────────────────────────────────────────────────────────
    //  TXT FALLBACK
    // ─────────────────────────────────────────────────────────────────────

    public static void exportTxt(AnalysisResult result, File outputFile) throws IOException {
        String bar = "=".repeat(60);
        StringBuilder sb = new StringBuilder();
        sb.append("SECURESCAN  PHISHING ANALYSIS REPORT\n").append(bar).append("\n");
        sb.append("Date:      ").append(DT.format(result.getAnalysisDate())).append("\n");
        sb.append("Subject:   ").append(result.getEmail().getSubject()).append("\n");
        sb.append("From:      ").append(result.getEmail().getFrom()).append("\n");
        sb.append("Reply-To:  ").append(result.getEmail().getReplyTo()).append("\n");
        sb.append(bar).append("\n");
        sb.append("RISK LEVEL:  ").append(result.getRiskLevel().getLabel().toUpperCase()).append("\n");
        sb.append("RISK SCORE:  ").append(result.getRiskScore()).append(" / 100\n");
        sb.append("CONFIDENCE:  ").append(result.getConfidencePercent()).append("%\n");
        sb.append(bar).append("\n");
        sb.append("SUMMARY:\n").append(result.getSummary()).append("\n\n");
        sb.append("INDICATORS (").append(result.getIndicators().size()).append(" found):\n");
        for (PhishingIndicator ind : result.getIndicators()) {
            sb.append("  [+").append(ind.getWeight()).append("pt] ")
                    .append(ind.getName()).append(": ").append(ind.getDescription()).append("\n");
        }
        sb.append(bar).append("\nSecureScan Phishing Intelligence Platform\n");
        try (Writer w = new FileWriter(outputFile)) { w.write(sb.toString()); }
    }
}

