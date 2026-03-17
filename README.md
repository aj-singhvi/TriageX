# TriageX

**TriageX** is a USB-deployable Windows forensic tool for live RAM and process analysis, designed for rapid incident response without installation on the target machine. It uses a dual machine learning pipeline (Random Forest + Isolation Forest) trained on synthetic data to provide threat scoring, anomaly detection, and network connection mapping. TriageX generates signed PDF and HTML triage reports for secure evidence handling.

---

## Features

- **Portable**: Runs from USB, no installation required
- **Live RAM & Process Analysis**: Captures and analyzes volatile memory and running processes
- **Dual ML Pipeline**: Random Forest + Isolation Forest for robust threat and anomaly detection
- **Synthetic Data Training**: Models trained on augmented synthetic datasets
- **Comprehensive Reporting**: Digitally signed PDF and HTML reports with threat scoring, network mapping, and anomaly detection
- **Incident Response Ready**: Designed for field use by responders

---

## Quick Start

1. **Clone the repository**
   ```sh
   git clone https://github.com/yourusername/TriageX.git
   cd TriageX
   ```

2. **Install Python (3.8+)**
   - [Download Python](https://www.python.org/downloads/) and ensure it is in your PATH.

3. **Install dependencies**
   ```sh
   pip install -r requirements.txt
   ```
   If `requirements.txt` is missing, install:
   ```
   pip install psutil jinja2 xhtml2pdf matplotlib scikit-learn joblib pandas numpy requests cpuinfo
   ```

4. **Prepare ML Models**
   - To generate the synthetic dataset and train models:
     ```sh
     python Scripts/main_analysis.py --download-dataset synthetic
     python Scripts/main_analysis.py --train-model
     ```
   - This will create the required `.joblib` model files in `Scripts/toolkit/`.

5. **Run Analysis**
   - On the target machine:
     ```sh
     python Scripts/main_analysis.py
     ```
   - Reports will be generated in `Scripts/Reports/` (excluded from GitHub).

---

## Project Structure

```
TriageX/
├── RUN_ANALYSIS.bat
├── Scripts/
│   ├── main_analysis.py
│   ├── toolkit/
│   │   ├── [models, scaler, datasets]
│   └── Reports/
└── Tools/
    └── Python/  # (Not included in repo)
```

---

## Requirements

- Windows OS (tested on Windows 10/11)
- Python 3.8+
- See dependencies above

---

## Email Report Delivery (Optional)

To enable email delivery of reports, set the following environment variables before running the tool:

- `TRIAGE_SMTP_SENDER` — Sender email address
- `TRIAGE_SMTP_PASS` — App password for the sender email
- `TRIAGE_SMTP_RECEIVER` — Receiver email address

No credentials are stored in the code or repository.

---

## Security & Privacy

- All analysis is performed locally; no data is transmitted externally unless email delivery is configured.
- Reports are digitally signed for integrity.
- Do not upload or share generated reports publicly.

---

## Contributing

Contributions are welcome! Please open issues or submit pull requests for improvements, bug fixes, or new features.

---

## License

[MIT License](LICENSE.txt)

---

## Disclaimer

TriageX is intended for use by authorized personnel for forensic and incident response purposes. Use responsibly and in accordance with local laws and organizational policies.
