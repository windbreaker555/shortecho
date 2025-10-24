# ShortEcho 🔍

A web technology fingerprinting tool that identifies frameworks, libraries, servers, and technologies used by web applications. Detects 100+ technologies including CMS platforms, JavaScript frameworks, web servers, CDNs, and more through HTTP headers, HTML patterns, and JavaScript analysis.

## Installation

```bash
git clone https://github.com/windbreaker555/shortecho.git
cd shortecho
pip3 install requests
```

## Usage

**Basic scan:**
```bash
python3 shortecho.py https://example.com
```

**Active scan** (checks specific URLs):
```bash
python3 shortecho.py https://example.com --active
```

**Export to JSON:**
```bash
python3 shortecho.py https://example.com -o results.json
```

**Set confidence threshold:**
```bash
python3 shortecho.py https://example.com -m 50
```

**All options:**
```
-h, --help                Show help message
-a, --active              Perform active scanning
-o, --output FILE         Export results to JSON
-s, --signatures FILE     Custom signatures file
-m, --min-confidence NUM  Minimum confidence (default: 30)
--no-color                Disable colors
```

## Disclaimer

For authorized security testing only. Always obtain permission before scanning.
