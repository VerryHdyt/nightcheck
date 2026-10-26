@'
# Nightcheck

**A lightweight HTTP security header checker built with Node.js.**

Nightcheck inspects selected HTTP response headers and provides basic recommendations for websites you own or are authorized to assess.

## Features

- Checks six common HTTP security headers.
- Displays the HTTP response status and inspection method.
- Provides basic recommendations.
- Exports reports in JSON format.
- Includes automated tests using the built-in Node.js test runner.
- Requires no third-party dependencies.

## Requirements

Install a supported version of Node.js.

## Usage

Display help:

```powershell
node src/index.js --help