
# Nightcheck

**A lightweight HTTP security header checker built with Node.js.**

Nightcheck is a command-line tool that checks selected HTTP security headers, displays basic recommendations, and exports scan reports as JSON.

Use Nightcheck only on websites you own or are explicitly authorized to assess.

## Features

- Checks six common HTTP security headers.
- Displays HTTP response status and request method.
- Follows HTTP redirects with a configurable maximum limit.
- Falls back from `HEAD` to `GET` when the server returns `405` or `501`.
- Provides basic recommendations for missing headers.
- Calculates a simple header-count-based risk indicator.
- Exports reports in JSON format.
- Includes automated tests using Node.js's built-in test runner.
- Validates destination IP addresses to block many private or special-use destinations by default.

## Security Headers Checked

| Header | Purpose |
| --- | --- |
| `Strict-Transport-Security` | Helps enforce HTTPS connections |
| `Content-Security-Policy` | Helps restrict permitted content sources |
| `X-Content-Type-Options` | Helps prevent MIME-type sniffing |
| `X-Frame-Options` | Helps control framing and reduce clickjacking risk |
| `Referrer-Policy` | Controls referrer information |
| `Permissions-Policy` | Controls access to selected browser features |

## Requirements

- Node.js with support for the built-in test runner.
- npm.

## Installation

Clone or download the repository, then open a terminal in the project directory.

Install dependencies:

```powershell
npm install
```

## Usage

Display help:

```powershell
node src/index.js --help
```

Check a website:

```powershell
node src/index.js https://example.com
```

Save the report as JSON:

```powershell
node src/index.js https://example.com --json
```

Reports are saved in the `reports/` directory. JSON report files are excluded from Git by default.

## Testing

Run the automated test suite:

```powershell
npm test
```

The tests cover URL validation, protocol validation, risk-level calculation, HTTP header checks, and redirect handling.

## Risk Indicator

Nightcheck uses a simple indicator based on the number of detected headers:

| Detected headers | Indicator |
| ---: | --- |
| 6 | `LOW` |
| 4–5 | `MEDIUM` |
| 2–3 | `HIGH` |
| 0–1 | `CRITICAL` |

This is only a basic indicator, not a comprehensive vulnerability assessment. A missing header does not automatically mean a website is vulnerable, and a detected header does not guarantee that it is configured correctly.

## Security Limitations

- Header presence is checked; header values are not comprehensively audited.
- IP validation is a basic safeguard and does not fully prevent DNS rebinding or all SSRF scenarios.
- Only the listed headers are inspected.
- Results should be reviewed in the context of the website's architecture and security requirements.

## Project Structure

```text
nightcheck/
├── src/
│   └── index.js
├── test/
│   └── nightcheck.test.js
├── reports/
├── .gitignore
├── package.json
├── package-lock.json
└── README.md
```

## License

No license has been specified yet. All rights are reserved unless the project owner states otherwise.
