# SecureScan Phishing Intelligence Platform

> A standalone desktop application for intelligent phishing detection and email security analysis.

---

## Overview

SecureScan is a Java-based desktop application built for CSI 3370 Software Engineering at Oakland University. It provides users with a fast, local, and reliable way to analyze emails, URLs, and file attachments for phishing threats — no internet connection or cloud service required.

The application evaluates content against **15 phishing indicators**, assigns a **risk score from 0–100**, and classifies results into three verdict levels: **SAFE**, **SUSPICIOUS**, and **MALICIOUS**.

---

## Team

| Name | Role |
|------|------|
| Stefan | Group Leader & System Architect |
| Sebastian Stanaj | Requirements Analysis & UML |
| Matheus Alsabbagh | UI/Frontend Design |
| Anthony Khemmoro | Implementation & Testing |

---

## Features

- **Email Text Scanning** — Paste raw email content for instant phishing analysis
- **EML File Import** — Import exported `.eml` files directly from your mail client
- **File Attachment Analysis** — Scan PDF and DOCX attachments for embedded threats
- **URL Checking** — Validate URLs against PhishTank, URLhaus, and Spamhaus threat feeds
- **Threat Risk Reports** — View detailed breakdowns of detected indicators and risk scores
- **Scan History** — Browse and manage past scan sessions across application restarts
- **Dark/Light Theme** — Toggle between custom CSS dark and light JavaFX themes
- **PDF Export** — Export threat reports using Apache PDFBox

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Java 17 |
| UI Framework | JavaFX 17 |
| PDF Parsing & Export | Apache PDFBox |
| Office File Parsing | Apache POI |
| Testing | JUnit 5 |
| Build System | Maven |
| IDE | IntelliJ IDEA |

---

## Threat Intelligence Feeds

- [PhishTank](https://www.phishtank.com/)
- [URLhaus](https://urlhaus.abuse.ch/)
- [Spamhaus](https://www.spamhaus.org/)

---

## Project Structure

```
SecureScan/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/securescan/
│   │   │       ├── analyzer/       # PhishingAnalyzer, UrlChecker, RiskScorer
│   │   │       ├── model/          # AnalysisResult, PhishingIndicator, ScanSession, RiskLevel
│   │   │       ├── parser/         # EmailParser, EmlParser, FileParser
│   │   │       ├── report/         # ReportExporter
│   │   │       ├── history/        # ScanHistoryManager
│   │   │       └── ui/             # JavaFX controllers and views
│   │   └── resources/
│   │       └── css/                # dark-theme.css, light-theme.css
│   └── test/
│       └── java/
│           └── com/securescan/
│               └── analyzer/       # UrlCheckerTest.java and other JUnit 5 tests
├── pom.xml
└── README.md
```

---

## Detection System

SecureScan evaluates content against **15 phishing indicators** and produces:

- A **risk score** between 0 and 100
- A **RiskLevel** verdict: `SAFE`, `SUSPICIOUS`, or `MALICIOUS`
- A detailed list of which indicators were triggered and why

---

## Testing

The project includes **38 passing JUnit 5 unit tests** covering core analyzer logic, URL checking, file parsing, and report generation.

To run tests:

```bash
mvn test
```

---

## Getting Started

### Prerequisites

- Java 17 or higher
- Maven 3.8+
- JavaFX 17 SDK (if not bundled via Maven)

### Build and Run

```bash
# Clone the repository
git clone https://github.com/StefanJosevski/SecureScan.git
cd SecureScan

# Build the project
mvn clean install

# Run the application
mvn javafx:run
```

---

## Process Model

This project was developed using **Scrum** across five structured sprint phases:

| Phase | Deliverable |
|-------|------------|
| Phase 1 | Problem statement, objectives, risks, requirements |
| Phase 2 | Use case diagram, fully dressed use cases, domain class diagram |
| Phase 3 | Design sequence diagrams, design class diagram |
| Phase 4 | Implementation, JUnit 5 testing |
| Phase 5 | Final presentation and report |

---

## References

- Larman, Craig. *Applying UML and Patterns.* 3rd Edition, Prentice Hall, 2004.
- Pressman, Roger. *Software Engineering: A Practitioner's Approach.* 8th Edition, McGraw Hill, 2014.
- Apache PDFBox Documentation — https://pdfbox.apache.org/
- Apache POI Documentation — https://poi.apache.org/
- JavaFX 17 Documentation — https://openjfx.io/javadoc/17/
- JUnit 5 User Guide — https://junit.org/junit5/docs/current/user-guide/
- CISA Phishing Resources — https://www.cisa.gov/phishing

---

## License

This project was developed for academic purposes as part of CSI 3370 Software Engineering at Oakland University.
