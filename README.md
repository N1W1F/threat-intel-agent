# Securo

A local, multi-agent security dashboard. It reads a list of your installed
software, checks each item against the public **NVD** CVE database, writes a
report, and (via **winget**) can show and apply available updates. Everything
runs on your own machine — the UI is a local window bound to `127.0.0.1`.

Bilingual UI (العربية / English) with full RTL/LTR support.

**What this is not:** Securo only cross-references locally-installed software
names/versions against public vulnerability databases (NVD, CISA KEV) — the
same category of check as a software updater. It never scans network ports,
never probes other machines, and never attempts to exploit anything. It is a
personal patch-awareness tool, not a penetration-testing or exploitation tool.

**Privacy:** this program will not transfer any information to other
networked systems unless specifically requested by the user or the person
installing or operating it. No telemetry, no analytics, no data collection.

---

## بالعربية

تطبيق أمني محلي متعدد الوكلاء يقرأ قائمة برامجك، يفحصها مقابل قاعدة ثغرات NVD،
يكتب تقريراً، ويعرض التحديثات المتاحة عبر winget مع إمكانية تطبيقها. كل شيء يعمل
على جهازك — الواجهة نافذة محلية على `127.0.0.1` فقط، بدون أي اتصال خارجي عدا
موقع NVD الرسمي.

### التشغيل
1. ثبّت المتطلبات: `pip install -r requirements.txt`
2. انسخ `inventory.example.txt` إلى `inventory.txt` وعدّله ببرامجك (أو استخدم `winget list`).
3. شغّل: `python app/desktop_app.py`  — أو انقر اختصار سطح المكتب.

---

## Requirements

- Windows 10/11 (winget updates use the Windows Package Manager)
- Python 3.10+
- `pip install -r requirements.txt`

## Run

```bash
python app/desktop_app.py      # native desktop window
# or
python app/server.py           # then open http://127.0.0.1:8765 in a browser
```

Create your `inventory.txt` first (copy `inventory.example.txt`).

## What each agent does

| Agent | Role | Access |
|---|---|---|
| Orchestrator | Coordinates the run, sequences the others | — |
| Threat Hunter | Queries NVD for CVEs matching your assets | network only (NVD host) |
| Asset Auditor | Reads `inventory.txt` | read-only, sandboxed |
| Remediation | Writes `threat_intel_report.md` | write-only, fixed path |
| Package Manager | Scans/applies winget updates | fixed `winget` argv only |

## Security

See [SHARING.md](SHARING.md) for the full security posture and how to share
this app with others safely. In short: source-only (inspectable), localhost
only, CSRF-protected local API, strict input validation, no `shell=True`,
no telemetry.

## Project governance

Single-maintainer project. All roles below are currently held by the same
person ([N1W1F](https://github.com/N1W1F)):

- **Author / Committer**: trusted to modify source directly.
- **Reviewer**: reviews any externally-proposed change (pull request) before merge.
- **Approver**: approves what gets tagged as a release / signed build.

`main` is branch-protected — no change reaches it without the automated
126-test Golden Dataset security suite passing first (see
[.github/workflows/ci.yml](.github/workflows/ci.yml)).

## Code signing policy

Windows builds of this project are code-signed for free by
[SignPath.io](https://about.signpath.io/), certificate provided by
[SignPath Foundation](https://signpath.org/), once accepted into their
open-source program.
