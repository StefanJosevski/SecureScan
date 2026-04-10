package com.securescan;

import com.securescan.analysis.PhishingAnalyzer;
import com.securescan.model.AnalysisResult;
import com.securescan.model.Email;
import com.securescan.model.PhishingIndicator;
import com.securescan.util.HeaderParser;
import com.securescan.util.ReportExporter;
import com.securescan.util.ScanSession;
import com.securescan.util.UrlChecker;
import com.securescan.util.UrlChecker.UrlStatus;
import javafx.animation.*;
import javafx.application.Application;
import javafx.concurrent.Task;
import javafx.geometry.*;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.*;
import javafx.scene.text.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.util.Duration;

import java.io.*;
import java.nio.file.Files;
import java.util.*;

public class SecureScanApp extends Application {

    // ── Core services ──────────────────────────────────────────────────────
    private final PhishingAnalyzer analyzer   = new PhishingAnalyzer();
    private final UrlChecker       urlChecker = new UrlChecker();
    private final ScanSession      session    = ScanSession.getInstance();

    // ── Theme ──────────────────────────────────────────────────────────────
    private boolean darkMode = true;
    private Scene   scene;

    // ── Result panel widgets ───────────────────────────────────────────────
    private Label       riskPill;
    private Label       scoreLabel;
    private Label       confidenceLabel;
    private Label       summaryLabel;
    private VBox        indicatorsBox;
    private ProgressBar riskBar;
    private ProgressBar confidenceBar;
    private VBox        urlResultsBox;
    private VBox        keywordChipsBox;
    private Button      exportButton;

    // ── Header panel ───────────────────────────────────────────────────────
    private Label headerIpLabel;
    private Label headerRecvLabel;
    private Label headerDkimLabel;
    private Label headerSpfLabel;
    private Label headerReturnLabel;
    private VBox  headerFlagsBox;

    // ── Trend chart ────────────────────────────────────────────────────────
    private VBox trendChartPane; // replaces Canvas — no GPU needed

    // ── Radar ──────────────────────────────────────────────────────────────
    private StackPane radarOverlay;
    private Timeline  radarTimeline; // kept for start/stop API compatibility

    // ── Root ───────────────────────────────────────────────────────────────
    private Stage     primaryStage;
    private StackPane rootStack;

    // ══════════════════════════════════════════════════════════════════════
    //  START
    // ══════════════════════════════════════════════════════════════════════
    @Override
    public void start(Stage stage) {
        this.primaryStage = stage;

        Label shieldIcon = new Label("🛡");
        shieldIcon.getStyleClass().add("shield-icon");

        Label title   = new Label("SecureScan");
        Label tagline = new Label("Phishing Intelligence Platform");
        title.getStyleClass().add("brand-title");
        tagline.getStyleClass().add("brand-tagline");

        VBox brandBox = new VBox(1, title, tagline);
        brandBox.setAlignment(Pos.CENTER_LEFT);

        Label statusPill = new Label("● SYSTEM ONLINE");
        statusPill.getStyleClass().add("status-pill");
        animatePulse(statusPill);

        Button themeBtn = new Button("☀  Light Mode");
        themeBtn.getStyleClass().add("btn-theme");
        themeBtn.setOnAction(e -> toggleTheme(themeBtn));

        Region topSpacer = new Region();
        HBox.setHgrow(topSpacer, Priority.ALWAYS);

        HBox topBar = new HBox(14, shieldIcon, brandBox, topSpacer, statusPill, themeBtn);
        topBar.getStyleClass().add("top-bar");
        topBar.setAlignment(Pos.CENTER_LEFT);

        // ── Tabs ──────────────────────────────────────────────────────────
        TabPane tabPane = new TabPane();
        tabPane.getStyleClass().add("custom-tabs");
        tabPane.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);

        Tab emailTab  = new Tab("  📧  Email / Text  ");
        Tab fileTab   = new Tab("  📎  File Upload  ");
        Tab headerTab = new Tab("  🔬  Header Analysis  ");
        Tab trendTab  = new Tab("  📊  Trend Chart  ");

        emailTab.setContent(buildEmailPane());
        fileTab.setContent(buildFilePane());
        headerTab.setContent(buildHeaderPane());
        trendTab.setContent(buildTrendPane());

        tabPane.getTabs().addAll(emailTab, fileTab, headerTab, trendTab);
        trendTab.setOnSelectionChanged(e -> { if (trendTab.isSelected()) drawTrendChart(); });

        // ── Right panel ───────────────────────────────────────────────────
        VBox resultPanel = buildResultPanel();

        radarOverlay = buildRadarOverlay();
        radarOverlay.setVisible(false);

        HBox mainContent = new HBox(16, tabPane, resultPanel);
        mainContent.setPadding(new Insets(18));
        HBox.setHgrow(tabPane, Priority.ALWAYS);
        resultPanel.setMinWidth(355);
        resultPanel.setMaxWidth(420);

        BorderPane root = new BorderPane();
        root.setTop(topBar);
        root.setCenter(mainContent);

        rootStack = new StackPane(root, radarOverlay);
        scene = new Scene(rootStack, 1320, 820);
        applyTheme();

        stage.setTitle("SecureScan — Phishing Intelligence");
        stage.setScene(scene);
        stage.show();

        root.setOpacity(0);
        FadeTransition fi = new FadeTransition(Duration.millis(600), root);
        fi.setToValue(1);
        fi.play();
    }

    // ══════════════════════════════════════════════════════════════════════
    //  EMAIL TAB
    // ══════════════════════════════════════════════════════════════════════
    private Pane buildEmailPane() {
        TextField fromField    = styledField("From:  e.g. support@paypal.com");
        TextField replyToField = styledField("Reply-To:  e.g. attacker@evil.ru");
        TextField subjectField = styledField("Subject:  e.g. URGENT: Verify your account now!!");

        TextArea bodyArea = new TextArea();
        bodyArea.setPromptText("Paste the full email body here, including any links…");
        bodyArea.setWrapText(true);
        bodyArea.setPrefRowCount(9);

        Label urlLabel = new Label("DETECTED URLs");
        urlLabel.getStyleClass().add("section-label");

        urlResultsBox = new VBox(5);
        ScrollPane urlScroll = new ScrollPane(urlResultsBox);
        urlScroll.setFitToWidth(true);
        urlScroll.setPrefHeight(110);
        urlScroll.getStyleClass().add("url-scroll");
        urlScroll.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);

        HBox chips = new HBox(8,
                chip("🔗 Links"), chip("⚡ Urgency"), chip("🎭 Spoofing"),
                chip("🔤 Homoglyphs"), chip("🌐 URL Rep"), chip("🔑 Credentials")
        );

        Button importBtn = new Button("⬆  Import .eml");
        importBtn.getStyleClass().add("btn-secondary");
        importBtn.setOnAction(e -> {
            FileChooser fc = new FileChooser();
            fc.setTitle("Open Email File");
            fc.getExtensionFilters().add(
                    new FileChooser.ExtensionFilter("Email files", "*.eml", "*.txt"));
            File f = fc.showOpenDialog(primaryStage);
            if (f != null) {
                try { bodyArea.setText(Files.readString(f.toPath())); }
                catch (IOException ex) { bodyArea.setText("Error: " + ex.getMessage()); }
            }
        });

        Button scanBtn = new Button("🔍  Scan Email");
        scanBtn.getStyleClass().add("btn-primary");
        scanBtn.setOnAction(e -> {
            Email email = new Email(
                    fromField.getText(), replyToField.getText(),
                    subjectField.getText(), bodyArea.getText()
            );
            startScan(email, bodyArea.getText());
        });

        Region btnSpacer = new Region();
        HBox.setHgrow(btnSpacer, Priority.ALWAYS);
        HBox btnRow = new HBox(10, btnSpacer, importBtn, scanBtn);
        btnRow.setAlignment(Pos.CENTER_RIGHT);

        GridPane grid = new GridPane();
        grid.setHgap(10); grid.setVgap(10);
        ColumnConstraints c0 = new ColumnConstraints(80);
        ColumnConstraints c1 = new ColumnConstraints();
        c1.setHgrow(Priority.ALWAYS);
        grid.getColumnConstraints().addAll(c0, c1);
        addRow(grid, 0, "From",     fromField);
        addRow(grid, 1, "Reply-To", replyToField);
        addRow(grid, 2, "Subject",  subjectField);

        Label bodyLabel = new Label("MESSAGE CONTENT");
        bodyLabel.getStyleClass().add("section-label");

        VBox card = new VBox(12,
                sectionTitle("Email Analysis", "Paste headers and message body"),
                grid, bodyLabel, bodyArea, chips, urlLabel, urlScroll, btnRow
        );
        card.getStyleClass().add("card");
        VBox.setVgrow(bodyArea, Priority.ALWAYS);

        VBox wrapper = new VBox(card);
        VBox.setVgrow(card, Priority.ALWAYS);
        return wrapper;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  FILE UPLOAD TAB
    // ══════════════════════════════════════════════════════════════════════
    private Pane buildFilePane() {
        VBox dropZone = new VBox(12);
        dropZone.getStyleClass().add("drop-zone");
        dropZone.setAlignment(Pos.CENTER);
        dropZone.setPrefHeight(160);

        Label dropIcon = new Label("📂");
        dropIcon.getStyleClass().add("drop-icon");
        Label dropText = new Label("Drag & drop a file here");
        dropText.getStyleClass().add("drop-text");
        Label dropSub  = new Label("PDF · DOCX · CSV · TXT · EML");
        dropSub.getStyleClass().add("drop-sub");
        Button browseBtn = new Button("Browse Files");
        browseBtn.getStyleClass().add("btn-secondary");
        dropZone.getChildren().addAll(dropIcon, dropText, dropSub, browseBtn);

        dropZone.setOnDragOver(ev -> {
            if (ev.getDragboard().hasFiles()) {
                ev.acceptTransferModes(javafx.scene.input.TransferMode.COPY);
                dropZone.getStyleClass().add("drop-zone-hover");
            }
            ev.consume();
        });
        dropZone.setOnDragExited(ev -> dropZone.getStyleClass().remove("drop-zone-hover"));

        TextArea previewArea = new TextArea();
        previewArea.setPromptText("Extracted file content will appear here…");
        previewArea.setWrapText(true);
        previewArea.setPrefRowCount(8);
        previewArea.setEditable(false);

        Label previewLabel = new Label("EXTRACTED CONTENT");
        previewLabel.getStyleClass().add("section-label");

        Button scanFileBtn = new Button("🔍  Scan File for Phishing");
        scanFileBtn.getStyleClass().add("btn-primary");
        scanFileBtn.setDisable(true);

        final String[] extracted = {""};

        browseBtn.setOnAction(ev -> {
            FileChooser fc = new FileChooser();
            fc.setTitle("Select File to Scan");
            fc.getExtensionFilters().addAll(
                    new FileChooser.ExtensionFilter("Supported Files",
                            "*.pdf","*.docx","*.csv","*.txt","*.eml"),
                    new FileChooser.ExtensionFilter("All Files","*.*")
            );
            File f = fc.showOpenDialog(primaryStage);
            if (f != null) {
                String content = processFile(f, dropText, dropSub);
                previewArea.setText(content);
                extracted[0] = content;
                scanFileBtn.setDisable(content.isBlank());
            }
        });

        dropZone.setOnDragDropped(ev -> {
            List<File> files = ev.getDragboard().getFiles();
            if (!files.isEmpty()) {
                String content = processFile(files.get(0), dropText, dropSub);
                previewArea.setText(content);
                extracted[0] = content;
                scanFileBtn.setDisable(content.isBlank());
            }
            ev.setDropCompleted(true);
            ev.consume();
        });

        scanFileBtn.setOnAction(ev -> {
            if (!extracted[0].isBlank()) {
                Email email = new Email("","","[File Scan]", extracted[0]);
                startScan(email, extracted[0]);
            }
        });

        HBox formatChips = new HBox(8,
                formatChip("PDF","#ef4444"), formatChip("DOCX","#3b82f6"),
                formatChip("CSV","#10b981"), formatChip("TXT","#8b5cf6"),
                formatChip("EML","#f59e0b")
        );

        Region btnSpacer = new Region();
        HBox.setHgrow(btnSpacer, Priority.ALWAYS);
        HBox btnRow = new HBox(10, btnSpacer, scanFileBtn);
        btnRow.setAlignment(Pos.CENTER_RIGHT);

        VBox card = new VBox(14,
                sectionTitle("File Scanner","Upload any document to scan for threats"),
                dropZone, formatChips, previewLabel, previewArea, btnRow
        );
        card.getStyleClass().add("card");
        VBox.setVgrow(previewArea, Priority.ALWAYS);

        VBox wrapper = new VBox(card);
        VBox.setVgrow(card, Priority.ALWAYS);
        return wrapper;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  HEADER ANALYSIS TAB  (Feature #5)
    // ══════════════════════════════════════════════════════════════════════
    private Pane buildHeaderPane() {
        TextArea headerInput = new TextArea();
        headerInput.setPromptText(
                "Paste the full raw email headers here.\n\n" +
                        "In Gmail: Open email → More (⋮) → Show original\n" +
                        "In Outlook: File → Properties → Internet headers\n\n" +
                        "Example fields parsed:\n" +
                        "  Received: from smtp.evil.ru ...\n" +
                        "  X-Originating-IP: 185.220.101.42\n" +
                        "  DKIM-Signature: v=1; a=rsa-sha256; d=legitimate.com ...\n" +
                        "  Authentication-Results: spf=fail ...\n" +
                        "  Return-Path: <attacker@evil.ru>"
        );
        headerInput.setWrapText(true);
        headerInput.setPrefRowCount(10);

        // ── Parsed fields display ─────────────────────────────────────────
        headerIpLabel     = headerVal("—");
        headerRecvLabel   = headerVal("—");
        headerDkimLabel   = headerVal("—");
        headerSpfLabel    = headerVal("—");
        headerReturnLabel = headerVal("—");

        GridPane fieldsGrid = new GridPane();
        fieldsGrid.setHgap(12);
        fieldsGrid.setVgap(8);
        ColumnConstraints lc = new ColumnConstraints(130);
        ColumnConstraints vc = new ColumnConstraints();
        vc.setHgrow(Priority.ALWAYS);
        fieldsGrid.getColumnConstraints().addAll(lc, vc);

        int gr = 0;
        fieldsGrid.add(headerKey("Originating IP"),  0, gr);   fieldsGrid.add(headerIpLabel,     1, gr++);
        fieldsGrid.add(headerKey("Received From"),   0, gr);   fieldsGrid.add(headerRecvLabel,   1, gr++);
        fieldsGrid.add(headerKey("DKIM Signature"),  0, gr);   fieldsGrid.add(headerDkimLabel,   1, gr++);
        fieldsGrid.add(headerKey("SPF Result"),      0, gr);   fieldsGrid.add(headerSpfLabel,    1, gr++);
        fieldsGrid.add(headerKey("Return-Path"),     0, gr);   fieldsGrid.add(headerReturnLabel, 1, gr++);

        Label fieldsTitle = new Label("PARSED FIELDS");
        fieldsTitle.getStyleClass().add("section-label");

        // ── Flags section ─────────────────────────────────────────────────
        Label flagsTitle = new Label("HEADER FLAGS");
        flagsTitle.getStyleClass().add("section-label");

        headerFlagsBox = new VBox(6);
        ScrollPane flagsScroll = new ScrollPane(headerFlagsBox);
        flagsScroll.setFitToWidth(true);
        flagsScroll.setPrefHeight(140);
        flagsScroll.getStyleClass().add("url-scroll");
        flagsScroll.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);

        // ── Buttons ───────────────────────────────────────────────────────
        Button parseBtn = new Button("🔬  Parse Headers");
        parseBtn.getStyleClass().add("btn-secondary");

        Button scanHeaderBtn = new Button("🔍  Scan + Parse");
        scanHeaderBtn.getStyleClass().add("btn-primary");

        parseBtn.setOnAction(e -> {
            String raw = headerInput.getText();
            if (raw.isBlank()) { showToast("Paste some header text first", "toast-warn"); return; }
            AnalysisResult dummy = new AnalysisResult(
                    new Email("","","[Header Parse]", raw));
            HeaderParser.parse(raw, dummy);
            updateHeaderFields(dummy);
            HeaderParser.SuspicionReport report = HeaderParser.evaluate(dummy, raw);
            updateHeaderFlags(report);
            showToast("Headers parsed — " + (report.hasFlags() ? report.getNames().size() + " flag(s) found" : "No flags"),
                    report.hasFlags() ? "toast-warn" : "toast-success");
        });

        scanHeaderBtn.setOnAction(e -> {
            String raw = headerInput.getText();
            if (raw.isBlank()) { showToast("Paste some header text first", "toast-warn"); return; }
            Email email = new Email("","","[Header Scan]", raw);
            startScanWithHeaders(email, raw);
        });

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        HBox btnRow = new HBox(10, spacer, parseBtn, scanHeaderBtn);
        btnRow.setAlignment(Pos.CENTER_RIGHT);

        Label inputLabel = new Label("RAW HEADERS INPUT");
        inputLabel.getStyleClass().add("section-label");

        Label tipLabel = new Label(
                "Tip: Paste the complete raw headers. " +
                        "SecureScan will extract routing info, check SPF/DKIM and flag suspicious patterns.");
        tipLabel.setWrapText(true);
        tipLabel.getStyleClass().add("indicator-desc");

        VBox card = new VBox(12,
                sectionTitle("Email Header Analysis", "Forensic inspection of email routing"),
                tipLabel, inputLabel, headerInput,
                fieldsTitle, fieldsGrid,
                flagsTitle, flagsScroll,
                btnRow
        );
        card.getStyleClass().add("card");
        VBox.setVgrow(headerInput, Priority.ALWAYS);

        VBox wrapper = new VBox(card);
        VBox.setVgrow(card, Priority.ALWAYS);
        return wrapper;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  TREND CHART TAB
    // ══════════════════════════════════════════════════════════════════════
    private Pane buildTrendPane() {
        trendChartPane = new VBox(8);
        trendChartPane.getStyleClass().add("chart-holder");
        trendChartPane.setPadding(new Insets(16));

        ScrollPane scroll = new ScrollPane(trendChartPane);
        scroll.setFitToWidth(true);
        scroll.setFitToHeight(true);
        scroll.getStyleClass().add("url-scroll");
        scroll.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);

        Button clearBtn = new Button("🗑  Clear Session Data");
        clearBtn.getStyleClass().add("btn-secondary");
        clearBtn.setOnAction(e -> { session.clear(); drawTrendChart(); });

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        HBox btnRow = new HBox(10, spacer, clearBtn);

        VBox card = new VBox(12,
                sectionTitle("Risk Score Trend", "Scores from this session"),
                scroll, btnRow
        );
        card.getStyleClass().add("card");
        VBox.setVgrow(scroll, Priority.ALWAYS);

        VBox wrapper = new VBox(card);
        VBox.setVgrow(card, Priority.ALWAYS);

        // Draw initial state
        javafx.application.Platform.runLater(this::drawTrendChart);
        return wrapper;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  RESULT PANEL
    // ══════════════════════════════════════════════════════════════════════
    private VBox buildResultPanel() {
        Label panelTitle = new Label("Threat Analysis");
        panelTitle.getStyleClass().add("panel-title");

        riskPill = new Label("— AWAITING SCAN —");
        riskPill.getStyleClass().addAll("risk-pill","risk-idle");
        riskPill.setMaxWidth(Double.MAX_VALUE);
        riskPill.setAlignment(Pos.CENTER);

        riskBar = new ProgressBar(0);
        riskBar.setMaxWidth(Double.MAX_VALUE);
        riskBar.getStyleClass().add("risk-bar");

        scoreLabel = new Label("Score: —");
        scoreLabel.getStyleClass().add("score-label");

        // ── Confidence meter ──────────────────────────────────────────────
        Label confTitle = new Label("DETECTION CONFIDENCE");
        confTitle.getStyleClass().add("section-label");

        confidenceBar = new ProgressBar(0);
        confidenceBar.setMaxWidth(Double.MAX_VALUE);
        confidenceBar.getStyleClass().add("confidence-bar");

        confidenceLabel = new Label("Confidence: —");
        confidenceLabel.getStyleClass().add("confidence-label");

        VBox confidenceBox = new VBox(4, confTitle, confidenceBar, confidenceLabel);

        summaryLabel = new Label("Run a scan to see the threat assessment.");
        summaryLabel.setWrapText(true);
        summaryLabel.getStyleClass().add("summary-text");

        // ── Keyword chips ─────────────────────────────────────────────────
        Label kwTitle = new Label("MATCHED KEYWORDS");
        kwTitle.getStyleClass().add("section-label");

        keywordChipsBox = new VBox(6);
        ScrollPane kwScroll = new ScrollPane(keywordChipsBox);
        kwScroll.setFitToWidth(true);
        kwScroll.setPrefHeight(100);
        kwScroll.getStyleClass().add("url-scroll");
        kwScroll.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);

        // ── Export button ─────────────────────────────────────────────────
        exportButton = new Button("📄  Export PDF Report");
        exportButton.getStyleClass().add("btn-export");
        exportButton.setMaxWidth(Double.MAX_VALUE);
        exportButton.setDisable(true);
        exportButton.setOnAction(e -> {
            AnalysisResult res = (AnalysisResult) exportButton.getUserData();
            if (res == null) return;
            FileChooser fc = new FileChooser();
            fc.setTitle("Save Report");
            fc.setInitialFileName("SecureScan_Report.pdf");
            fc.getExtensionFilters().add(
                    new FileChooser.ExtensionFilter("PDF Files","*.pdf"));
            File f = fc.showSaveDialog(primaryStage);
            if (f != null) {
                try {
                    ReportExporter.export(res, f);
                    showToast("✅  Report saved: " + f.getName(), "toast-success");
                } catch (Exception ex) {
                    showToast("⚠  " + ex.getMessage(), "toast-warn");
                }
            }
        });

        // ── Indicators ────────────────────────────────────────────────────
        Label indTitle = new Label("INDICATORS DETECTED");
        indTitle.getStyleClass().add("section-label");

        indicatorsBox = new VBox(8);
        ScrollPane indScroll = new ScrollPane(indicatorsBox);
        indScroll.setFitToWidth(true);
        indScroll.getStyleClass().add("indicator-scroll");
        indScroll.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        VBox.setVgrow(indScroll, Priority.ALWAYS);

        VBox panel = new VBox(10,
                panelTitle, separator(),
                riskPill, riskBar, scoreLabel,
                confidenceBox,
                summaryLabel,
                exportButton,
                separator(),
                kwTitle, kwScroll,
                separator(),
                indTitle, indScroll
        );
        panel.getStyleClass().add("result-panel");
        VBox.setVgrow(panel, Priority.ALWAYS);
        return panel;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  RADAR OVERLAY
    // ══════════════════════════════════════════════════════════════════════
    private StackPane buildRadarOverlay() {
        // Pure CSS spinner — NO Canvas, NO GPU texture, works on all hardware
        Label spinnerRing = new Label();
        spinnerRing.getStyleClass().add("spinner-ring");

        Label spinnerDot = new Label();
        spinnerDot.getStyleClass().add("spinner-dot");

        StackPane spinner = new StackPane(spinnerRing, spinnerDot);
        spinner.setPrefSize(80, 80);

        // Rotate the ring with a simple RotateTransition — CSS-only, no Canvas
        RotateTransition rotate = new RotateTransition(Duration.millis(1000), spinnerRing);
        rotate.setByAngle(360);
        rotate.setCycleCount(Animation.INDEFINITE);
        rotate.setInterpolator(Interpolator.LINEAR);

        Label scanningLabel = new Label("SCANNING…");
        scanningLabel.getStyleClass().add("radar-label");

        VBox box = new VBox(14, spinner, scanningLabel);
        box.setAlignment(Pos.CENTER);
        box.getStyleClass().add("radar-box");
        box.setMaxSize(220, 200);

        StackPane overlay = new StackPane(box);
        overlay.setStyle("-fx-background-color: rgba(0,0,0,0.70);");
        overlay.setVisible(false);

        // Store rotate so we can start/stop it
        radarTimeline = new Timeline(new KeyFrame(Duration.millis(16), e -> {}));
        radarTimeline.setCycleCount(Animation.INDEFINITE);

        // Use the overlay visible property to start/stop the spinner
        overlay.visibleProperty().addListener((obs, wasVisible, isVisible) -> {
            if (isVisible) rotate.play();
            else           rotate.stop();
        });

        return overlay;
    }

    // drawRadarFrame removed — replaced by CSS spinner, no Canvas needed
    private void drawRadarFrame(Object c) { /* no-op */ }

    // ══════════════════════════════════════════════════════════════════════
    //  SCAN ORCHESTRATION
    // ══════════════════════════════════════════════════════════════════════
    private void startScan(Email email, String rawText) {
        startScanInternal(email, rawText, false);
    }

    private void startScanWithHeaders(Email email, String rawText) {
        startScanInternal(email, rawText, true);
    }

    private void startScanInternal(Email email, String rawText, boolean parseHeaders) {
        radarOverlay.setVisible(true);
        radarTimeline.play();

        Task<ScanBundle> task = new Task<>() {
            @Override protected ScanBundle call() {
                AnalysisResult result = analyzer.analyze(email);

                // URL check
                List<String> urls = urlChecker.extractUrls(rawText);
                Map<String, UrlStatus> urlStatuses = urlChecker.checkUrls(urls);

                // Merge URL indicators
                List<PhishingIndicator> extra = new ArrayList<>();
                int extraScore = 0;
                for (UrlStatus us : urlStatuses.values()) {
                    if (us.isFlagged()) {
                        int w = us.threat == UrlChecker.Threat.MALICIOUS ? 40 : 20;
                        extra.add(new PhishingIndicator(
                                "Suspicious URL",
                                truncate(us.url, 55) + " — " + us.reason, w));
                        extraScore += w;
                    }
                }
                if (!extra.isEmpty()) {
                    List<PhishingIndicator> all = new ArrayList<>(result.getIndicators());
                    all.addAll(extra);
                    result.setIndicators(all);
                    int ns = Math.min(100, result.getRiskScore() + extraScore);
                    result.setRiskScore(ns);
                    result.setRiskLevel(result.calculateRiskLevel(ns));
                }

                // Header parsing
                if (parseHeaders) {
                    HeaderParser.parse(rawText, result);
                    HeaderParser.SuspicionReport hReport = HeaderParser.evaluate(result, rawText);
                    if (hReport.hasFlags()) {
                        List<PhishingIndicator> all = new ArrayList<>(result.getIndicators());
                        int hs = 0;
                        for (int i = 0; i < hReport.getNames().size(); i++) {
                            all.add(new PhishingIndicator(
                                    hReport.getNames().get(i),
                                    hReport.getReasons().get(i),
                                    hReport.getWeights().get(i)));
                            hs += hReport.getWeights().get(i);
                        }
                        result.setIndicators(all);
                        int ns = Math.min(100, result.getRiskScore() + hs);
                        result.setRiskScore(ns);
                        result.setRiskLevel(result.calculateRiskLevel(ns));
                    }
                }

                // Recalculate confidence after all indicators merged
                result.setConfidencePercent(
                        PhishingAnalyzer.calculateConfidence(
                                result.getRiskScore(), result.getIndicators().size()));

                return new ScanBundle(result, urlStatuses, parseHeaders);
            }
        };

        task.setOnSucceeded(e -> {
            radarTimeline.stop();
            radarOverlay.setVisible(false);
            ScanBundle bundle = task.getValue();
            displayResult(bundle.result);
            displayUrlResults(bundle.urlStatuses);
            if (bundle.headerParsed) {
                updateHeaderFields(bundle.result);
                HeaderParser.SuspicionReport rep =
                        HeaderParser.evaluate(bundle.result, rawText);
                updateHeaderFlags(rep);
            }
            session.record(bundle.result);
            showToast(toastMessage(bundle.result), toastStyle(bundle.result));
        });

        task.setOnFailed(e -> {
            radarTimeline.stop();
            radarOverlay.setVisible(false);
            showToast("❌ Scan error: " + task.getException().getMessage(), "toast-error");
        });

        Thread t = new Thread(task);
        t.setDaemon(true);
        t.start();
    }

    private record ScanBundle(
            AnalysisResult result,
            Map<String, UrlStatus> urlStatuses,
            boolean headerParsed) {}

    // ══════════════════════════════════════════════════════════════════════
    //  DISPLAY RESULT
    // ══════════════════════════════════════════════════════════════════════
    private void displayResult(AnalysisResult result) {
        // Risk pill
        riskPill.getStyleClass().removeAll("risk-idle","risk-safe","risk-suspicious","risk-malicious");
        switch (result.getRiskLevel()) {
            case SAFE       -> { riskPill.setText("✅  SAFE");       riskPill.getStyleClass().add("risk-safe"); }
            case SUSPICIOUS -> { riskPill.setText("⚠️  SUSPICIOUS"); riskPill.getStyleClass().add("risk-suspicious"); }
            case MALICIOUS  -> { riskPill.setText("🚨  MALICIOUS");  riskPill.getStyleClass().add("risk-malicious"); }
        }

        // Risk bar animation
        new Timeline(
                new KeyFrame(Duration.ZERO,
                        new KeyValue(riskBar.progressProperty(), riskBar.getProgress())),
                new KeyFrame(Duration.millis(800),
                        new KeyValue(riskBar.progressProperty(), result.getRiskScore()/100.0, Interpolator.EASE_OUT))
        ).play();
        scoreLabel.setText("Risk Score: " + result.getRiskScore() + " / 100");

        // ── Confidence bar (Feature #6) ────────────────────────────────────
        int conf = result.getConfidencePercent();
        new Timeline(
                new KeyFrame(Duration.ZERO,
                        new KeyValue(confidenceBar.progressProperty(), confidenceBar.getProgress())),
                new KeyFrame(Duration.millis(800),
                        new KeyValue(confidenceBar.progressProperty(), conf/100.0, Interpolator.EASE_OUT))
        ).play();

        // Colour the confidence bar by level
        confidenceBar.getStyleClass().removeAll("conf-low","conf-med","conf-high");
        if (conf >= 65) confidenceBar.getStyleClass().add("conf-high");
        else if (conf >= 40) confidenceBar.getStyleClass().add("conf-med");
        else confidenceBar.getStyleClass().add("conf-low");

        confidenceLabel.setText("Confidence: " + conf + "%  (" + result.getConfidenceLabel() + ")");

        summaryLabel.setText(result.getSummary());

        exportButton.setUserData(result);
        exportButton.setDisable(false);

        // ── Keyword chips (Feature #1) ─────────────────────────────────────
        keywordChipsBox.getChildren().clear();
        Map<String, List<String>> kws = result.getMatchedKeywords();
        if (kws.isEmpty()) {
            Label none = new Label("No keywords matched.");
            none.getStyleClass().add("url-none");
            keywordChipsBox.getChildren().add(none);
        } else {
            for (Map.Entry<String, List<String>> entry : kws.entrySet()) {
                Label catLabel = new Label(entry.getKey());
                catLabel.getStyleClass().add("kw-category");

                FlowPane chipsPane = new FlowPane(6, 4);
                for (String word : entry.getValue()) {
                    Label chip = new Label(word);
                    chip.getStyleClass().add("kw-chip");
                    chipsPane.getChildren().add(chip);
                }

                VBox row = new VBox(3, catLabel, chipsPane);
                keywordChipsBox.getChildren().add(row);
            }
        }

        // ── Indicators ────────────────────────────────────────────────────
        indicatorsBox.getChildren().clear();
        if (result.getIndicators().isEmpty()) {
            Label none = new Label("No phishing indicators detected.");
            none.getStyleClass().add("indicator-none");
            indicatorsBox.getChildren().add(none);
        } else {
            int i = 0;
            for (PhishingIndicator ind : result.getIndicators()) {
                VBox card = buildIndicatorCard(ind);
                card.setOpacity(0);
                int delay = i++ * 60;
                PauseTransition pause = new PauseTransition(Duration.millis(delay));
                pause.setOnFinished(ev -> {
                    FadeTransition ft = new FadeTransition(Duration.millis(200), card);
                    ft.setToValue(1); ft.play();
                });
                pause.play();
                indicatorsBox.getChildren().add(card);
            }
        }

        FadeTransition flash = new FadeTransition(Duration.millis(200), riskPill);
        flash.setFromValue(0.2); flash.setToValue(1); flash.play();
    }

    // ── URL results ───────────────────────────────────────────────────────
    private void displayUrlResults(Map<String, UrlStatus> statuses) {
        if (urlResultsBox == null) return;
        urlResultsBox.getChildren().clear();
        if (statuses.isEmpty()) {
            Label none = new Label("No URLs found in this content.");
            none.getStyleClass().add("url-none");
            urlResultsBox.getChildren().add(none);
            return;
        }
        for (UrlStatus us : statuses.values()) {
            urlResultsBox.getChildren().add(buildUrlRow(us));
        }
    }

    // ── Header fields update (Feature #5) ────────────────────────────────
    private void updateHeaderFields(AnalysisResult result) {
        headerIpLabel.setText(blank(result.getHeaderOriginatingIp()));
        headerRecvLabel.setText(blank(result.getHeaderReceivedFrom()));

        String dkim = result.getHeaderDkim();
        headerDkimLabel.setText(blank(dkim));
        headerDkimLabel.getStyleClass().removeAll("hdr-ok","hdr-bad","hdr-neutral");
        if ("Not present".equals(dkim)) headerDkimLabel.getStyleClass().add("hdr-bad");
        else headerDkimLabel.getStyleClass().add("hdr-ok");

        String spf = result.getHeaderSpf();
        headerSpfLabel.setText(blank(spf));
        headerSpfLabel.getStyleClass().removeAll("hdr-ok","hdr-bad","hdr-neutral");
        if ("FAIL".equalsIgnoreCase(spf) || "SOFTFAIL".equalsIgnoreCase(spf))
            headerSpfLabel.getStyleClass().add("hdr-bad");
        else if ("PASS".equalsIgnoreCase(spf))
            headerSpfLabel.getStyleClass().add("hdr-ok");
        else headerSpfLabel.getStyleClass().add("hdr-neutral");

        headerReturnLabel.setText(blank(result.getHeaderReturnPath()));
    }

    private void updateHeaderFlags(HeaderParser.SuspicionReport report) {
        headerFlagsBox.getChildren().clear();
        if (!report.hasFlags()) {
            Label ok = new Label("✅  No suspicious header patterns detected");
            ok.getStyleClass().add("indicator-none");
            headerFlagsBox.getChildren().add(ok);
            return;
        }
        for (int i = 0; i < report.getNames().size(); i++) {
            Label name = new Label("⚠  " + report.getNames().get(i)
                    + "  (+" + report.getWeights().get(i) + "pt)");
            name.getStyleClass().add("indicator-name");
            Label reason = new Label(report.getReasons().get(i));
            reason.getStyleClass().add("indicator-desc");
            reason.setWrapText(true);
            VBox row = new VBox(3, name, reason);
            row.getStyleClass().addAll("indicator-card","indicator-warning");
            headerFlagsBox.getChildren().add(row);
        }
    }

    // ── Indicator card ────────────────────────────────────────────────────
    private VBox buildIndicatorCard(PhishingIndicator ind) {
        String icon = switch (ind.getName()) {
            case "Suspicious Link"           -> "🔗";
            case "Urgency Language"          -> "⚡";
            case "Sender / Reply-To Mismatch"-> "🎭";
            case "Credential Harvesting"     -> "🔑";
            case "ALL CAPS Subject Line"     -> "📢";
            case "Homoglyph / Unicode Spoofing"-> "🔤";
            case "Brand Lookalike Domain"    -> "🎯";
            case "Excessive Punctuation"     -> "❗";
            case "Generic / Impersonal Greeting" -> "👤";
            case "SPF FAIL", "SPF SOFTFAIL"  -> "🛡";
            case "No DKIM Signature"         -> "✍";
            case "Display Name Spoofing"     -> "🎭";
            default -> ind.getName().contains("URL") ? "🌐" : "⚠";
        };

        Label nameLbl   = new Label(icon + "  " + ind.getName());
        nameLbl.getStyleClass().add("indicator-name");

        Label weightLbl = new Label("+" + ind.getWeight() + "pt");
        weightLbl.getStyleClass().add("indicator-weight");

        Region r = new Region();
        HBox.setHgrow(r, Priority.ALWAYS);
        HBox header = new HBox(4, nameLbl, r, weightLbl);
        header.setAlignment(Pos.CENTER_LEFT);

        Label desc = new Label(ind.getDescription());
        desc.setWrapText(true);
        desc.getStyleClass().add("indicator-desc");

        VBox card = new VBox(5, header, desc);
        card.getStyleClass().add("indicator-card");
        card.getStyleClass().add(ind.getWeight() >= 25 ? "indicator-danger" : "indicator-warning");
        return card;
    }

    private HBox buildUrlRow(UrlStatus us) {
        String cls = switch (us.threat) {
            case CLEAN      -> "url-clean";
            case SUSPICIOUS -> "url-suspicious";
            case MALICIOUS  -> "url-malicious";
        };
        String icon = switch (us.threat) {
            case CLEAN -> "✅"; case SUSPICIOUS -> "⚠️"; case MALICIOUS -> "🚨";
        };
        Label iconLbl = new Label(icon);
        iconLbl.setMinWidth(22);
        Label urlLbl = new Label(truncate(us.url, 42));
        urlLbl.getStyleClass().addAll("url-text", cls);
        urlLbl.setTooltip(new Tooltip(us.url));
        Label reasonLbl = new Label(us.reason);
        reasonLbl.getStyleClass().add("url-reason");
        reasonLbl.setWrapText(true);
        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);
        HBox row = new HBox(8, iconLbl, urlLbl, sp, reasonLbl);
        row.getStyleClass().addAll("url-row", cls + "-row");
        row.setAlignment(Pos.CENTER_LEFT);
        return row;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  TREND CHART  — pure VBox/Region bars, zero Canvas/GPU
    // ══════════════════════════════════════════════════════════════════════
    private void drawTrendChart() {
        if (trendChartPane == null) return;
        trendChartPane.getChildren().clear();

        List<ScanSession.ScanEntry> entries = session.getEntries();

        // Title row
        Label title = new Label("RISK SCORE OVER TIME  ("
                + entries.size() + " scan" + (entries.size() == 1 ? "" : "s") + ")");
        title.getStyleClass().add("chart-title");
        trendChartPane.getChildren().add(title);

        if (entries.isEmpty()) {
            Label empty = new Label(
                    "No scan data yet — run some scans to see your trend here.");
            empty.getStyleClass().add("no-data-label");
            empty.setWrapText(true);
            trendChartPane.getChildren().add(empty);
            return;
        }

        // One bar row per scan entry
        for (int i = 0; i < entries.size(); i++) {
            ScanSession.ScanEntry entry = entries.get(i);
            int score = entry.getScore();

            // Label column — scan number + risk level
            String levelText = score < 30 ? "SAFE" : score < 70 ? "SUSPICIOUS" : "MALICIOUS";
            String barColor  = score < 30 ? "#4ade80" : score < 70 ? "#fbbf24" : "#f87171";

            Label scanNum = new Label(String.format("#%-2d", i + 1));
            scanNum.getStyleClass().add("chart-scan-num");
            scanNum.setMinWidth(32);

            // The bar itself — width proportional to score
            Region bar = new Region();
            bar.setPrefHeight(22);
            bar.setMinWidth(2);
            bar.setStyle("-fx-background-color:" + barColor
                    + "; -fx-background-radius:3;");

            // Animate bar width from 0 → target using a Timeline on prefWidth
            double targetPct = score / 100.0;
            bar.setPrefWidth(0);
            javafx.animation.KeyValue kv = new javafx.animation.KeyValue(
                    bar.prefWidthProperty(), 0);

            // Use a StackPane so the bar can fill relative to its parent
            StackPane barWrap = new StackPane(bar);
            barWrap.setAlignment(Pos.CENTER_LEFT);
            barWrap.setMaxWidth(Double.MAX_VALUE);
            HBox.setHgrow(barWrap, Priority.ALWAYS);

            // Animate after layout
            int finalI = i;
            barWrap.layoutBoundsProperty().addListener(new javafx.beans.value.ChangeListener<>() {
                boolean done = false;
                @Override public void changed(javafx.beans.value.ObservableValue<? extends javafx.geometry.Bounds> o,
                                              javafx.geometry.Bounds old, javafx.geometry.Bounds now) {
                    if (!done && now.getWidth() > 10) {
                        done = true;
                        Timeline anim = new Timeline(
                                new KeyFrame(Duration.ZERO,
                                        new KeyValue(bar.prefWidthProperty(), 0)),
                                new KeyFrame(Duration.millis(500 + finalI * 80),
                                        new KeyValue(bar.prefWidthProperty(),
                                                now.getWidth() * targetPct,
                                                Interpolator.EASE_OUT))
                        );
                        anim.play();
                    }
                }
            });

            Label scoreLbl = new Label(score + "/100");
            scoreLbl.setMinWidth(58);
            scoreLbl.setStyle("-fx-text-fill:" + barColor
                    + "; -fx-font-size:11px; -fx-font-weight:bold; -fx-font-family:'Consolas',monospace;");

            Label levelLbl = new Label(levelText);
            levelLbl.setMinWidth(88);
            levelLbl.setStyle("-fx-text-fill:" + barColor
                    + "; -fx-font-size:9px; -fx-font-family:'Consolas',monospace;");

            HBox row = new HBox(8, scanNum, barWrap, scoreLbl, levelLbl);
            row.setAlignment(Pos.CENTER_LEFT);
            row.setPadding(new Insets(2, 0, 2, 0));
            trendChartPane.getChildren().add(row);
        }
    }

    private String scoreColorCss(int score) {
        if (score < 30) return "#4ade80";
        if (score < 70) return "#fbbf24";
        return "#f87171";
    }

    // ══════════════════════════════════════════════════════════════════════
    //  TOAST
    // ══════════════════════════════════════════════════════════════════════
    private void showToast(String message, String styleClass) {
        Label toast = new Label(message);
        toast.getStyleClass().addAll("toast", styleClass);
        toast.setMaxWidth(460);
        StackPane.setAlignment(toast, Pos.BOTTOM_RIGHT);
        StackPane.setMargin(toast, new Insets(0, 24, 24, 0));
        rootStack.getChildren().add(toast);
        toast.setTranslateY(40);
        toast.setOpacity(0);
        FadeTransition fi = new FadeTransition(Duration.millis(300), toast);
        fi.setToValue(1);
        TranslateTransition su = new TranslateTransition(Duration.millis(300), toast);
        su.setToY(0);
        ParallelTransition show = new ParallelTransition(fi, su);
        show.setOnFinished(e -> {
            PauseTransition hold = new PauseTransition(Duration.millis(2800));
            hold.setOnFinished(ev -> {
                FadeTransition out = new FadeTransition(Duration.millis(400), toast);
                out.setToValue(0);
                out.setOnFinished(d -> rootStack.getChildren().remove(toast));
                out.play();
            });
            hold.play();
        });
        show.play();
    }

    private String toastMessage(AnalysisResult r) {
        return switch (r.getRiskLevel()) {
            case SAFE       -> "✅  No threats  (score: " + r.getRiskScore() + "/100, confidence: " + r.getConfidencePercent() + "%)";
            case SUSPICIOUS -> "⚠️  Suspicious  (score: " + r.getRiskScore() + "/100, confidence: " + r.getConfidencePercent() + "%)";
            case MALICIOUS  -> "🚨  MALICIOUS  (score: " + r.getRiskScore() + "/100, confidence: " + r.getConfidencePercent() + "%)";
        };
    }

    private String toastStyle(AnalysisResult r) {
        return switch (r.getRiskLevel()) {
            case SAFE -> "toast-success"; case SUSPICIOUS -> "toast-warn"; case MALICIOUS -> "toast-error";
        };
    }

    // ══════════════════════════════════════════════════════════════════════
    //  THEME
    // ══════════════════════════════════════════════════════════════════════
    private void toggleTheme(Button btn) {
        darkMode = !darkMode;
        btn.setText(darkMode ? "☀  Light Mode" : "🌙  Dark Mode");
        applyTheme();
        drawTrendChart();
    }

    private void applyTheme() {
        scene.getStylesheets().clear();
        String css = getClass().getResource(
                darkMode ? "/securescan.css" : "/securescan-light.css"
        ).toExternalForm();
        scene.getStylesheets().add(css);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  FILE EXTRACTION
    // ══════════════════════════════════════════════════════════════════════
    private String processFile(File file, Label dropText, Label dropSub) {
        String name = file.getName().toLowerCase();
        dropText.setText("📄  " + file.getName());
        try {
            if (name.endsWith(".txt")||name.endsWith(".eml")||name.endsWith(".csv")) {
                dropSub.setText("✅ Loaded");
                return Files.readString(file.toPath());
            } else if (name.endsWith(".pdf")) {
                dropSub.setText("✅ PDF loaded");
                return extractPdf(file);
            } else if (name.endsWith(".docx")) {
                dropSub.setText("✅ DOCX loaded");
                return extractDocx(file);
            } else {
                dropSub.setText("⚠ Plain read");
                return Files.readString(file.toPath());
            }
        } catch (Exception ex) {
            dropSub.setText("❌ Error: " + ex.getMessage());
            return "";
        }
    }

    private String extractPdf(File file) throws Exception {
        try {
            Class<?> loader   = Class.forName("org.apache.pdfbox.pdmodel.PDDocument");
            Class<?> stripper = Class.forName("org.apache.pdfbox.text.PDFTextStripper");
            Object doc  = loader.getMethod("load", File.class).invoke(null, file);
            Object s    = stripper.getDeclaredConstructor().newInstance();
            String text = (String) stripper.getMethod("getText", loader).invoke(s, doc);
            loader.getMethod("close").invoke(doc);
            return text;
        } catch (ClassNotFoundException e) {
            return "[PDFBox not found — add pdfbox 3.0.1 to pom.xml]";
        }
    }

    private String extractDocx(File file) throws Exception {
        try {
            Class<?> xwpf = Class.forName("org.apache.poi.xwpf.usermodel.XWPFDocument");
            Class<?> ext  = Class.forName("org.apache.poi.xwpf.extractor.XWPFWordExtractor");
            try (var is = new FileInputStream(file)) {
                Object doc    = xwpf.getConstructor(java.io.InputStream.class).newInstance(is);
                Object extObj = ext.getConstructor(xwpf).newInstance(doc);
                String text   = (String) ext.getMethod("getText").invoke(extObj);
                ext.getMethod("close").invoke(extObj);
                return text;
            }
        } catch (ClassNotFoundException e) {
            return "[Apache POI not found — add poi-ooxml 5.2.5 to pom.xml]";
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  UI HELPERS
    // ══════════════════════════════════════════════════════════════════════
    private TextField styledField(String prompt) {
        TextField tf = new TextField();
        tf.setPromptText(prompt);
        return tf;
    }

    private void addRow(GridPane g, int row, String labelText, TextField field) {
        Label l = new Label(labelText);
        l.getStyleClass().add("field-label");
        g.add(l, 0, row);
        g.add(field, 1, row);
    }

    private HBox sectionTitle(String title, String sub) {
        Label t = new Label(title); t.getStyleClass().add("card-title");
        Label s = new Label(sub);   s.getStyleClass().add("card-meta");
        Region r = new Region();    HBox.setHgrow(r, Priority.ALWAYS);
        HBox h = new HBox(10, t, r, s);
        h.setAlignment(Pos.CENTER_LEFT);
        return h;
    }

    private Label chip(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("chip");
        return l;
    }

    private Label formatChip(String text, String color) {
        Label l = new Label(text);
        l.getStyleClass().add("format-chip");
        l.setStyle("-fx-border-color:" + color + ";-fx-text-fill:" + color + ";");
        return l;
    }

    private Separator separator() {
        Separator s = new Separator();
        s.getStyleClass().add("section-sep");
        return s;
    }

    private Label headerKey(String text) {
        Label l = new Label(text + ":");
        l.getStyleClass().add("hdr-key");
        return l;
    }

    private Label headerVal(String text) {
        Label l = new Label(text);
        l.getStyleClass().add("hdr-val");
        l.setWrapText(true);
        return l;
    }

    private void animatePulse(Node node) {
        FadeTransition ft = new FadeTransition(Duration.millis(2400), node);
        ft.setFromValue(1.0); ft.setToValue(0.5);
        ft.setAutoReverse(true);
        ft.setCycleCount(Animation.INDEFINITE);
        ft.play();
    }

    private String truncate(String s, int max) {
        return s != null && s.length() > max ? s.substring(0, max-1) + "…" : s;
    }

    private String blank(String s) {
        return (s == null || s.isBlank()) ? "—" : s;
    }

    public static void main(String[] args) {
        // MUST be set before JavaFX initialises — setting inside start() is too late
        // Forces software renderer — fixes RTTexture NPE crash on ARM/Snapdragon
        System.setProperty("prism.order", "sw");
        System.setProperty("prism.verbose", "false");
        System.setProperty("javafx.animation.fullspeed", "false");
        launch(args);
    }
}

