
const https = require("node:https");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const dns = require("node:dns").promises;
const net = require("node:net");
const ipaddr = require("ipaddr.js");

const VERSION = "0.3.0";
const TIMEOUT_MS = 10000;
const MAX_REDIRECTS = 5;

const SECURITY_HEADERS = [
  {
    name: "strict-transport-security",
    label: "Strict-Transport-Security",
    recommendation:
      "Aktifkan HSTS setelah HTTPS dikonfigurasi dengan benar."
  },
  {
    name: "content-security-policy",
    label: "Content-Security-Policy",
    recommendation:
      "Evaluasi CSP yang sesuai dengan kebutuhan aplikasi."
  },
  {
    name: "x-content-type-options",
    label: "X-Content-Type-Options",
    recommendation: "Pertimbangkan nilai nosniff."
  },
  {
    name: "x-frame-options",
    label: "X-Frame-Options",
    recommendation:
      "Evaluasi X-Frame-Options atau CSP frame-ancestors."
  },
  {
    name: "referrer-policy",
    label: "Referrer-Policy",
    recommendation:
      "Atur kebijakan referrer sesuai kebutuhan privasi."
  },
  {
    name: "permissions-policy",
    label: "Permissions-Policy",
    recommendation:
      "Batasi fitur browser yang tidak dibutuhkan."
  }
];

function isPrivateOrReservedAddress(address) {
  try {
    return ipaddr.process(address).range() !== "unicast";
  } catch {
    return true;
  }
}

async function validateDestination(url, allowPrivate = false) {
  let addresses;

  try {
    if (net.isIP(url.hostname)) {
      addresses = [{ address: url.hostname }];
    } else {
      addresses = await dns.lookup(url.hostname, {
        all: true,
        verbatim: true
      });
    }
  } catch {
    throw new Error("Hostname tidak dapat di-resolve.");
  }

  if (addresses.length === 0) {
    throw new Error("Hostname tidak memiliki alamat IP.");
  }

  if (
    !allowPrivate &&
    addresses.some(({ address }) =>
      isPrivateOrReservedAddress(address)
    )
  ) {
    throw new Error(
      "Tujuan mengarah ke alamat IP privat atau khusus; permintaan diblokir."
    );
  }
}

async function requestHeaders(
  url,
  method,
  redirects = 0,
  options = {}
) {
  const { allowPrivate = false } = options;

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Hanya URL HTTP dan HTTPS yang didukung.");
  }

  if (url.username || url.password) {
    throw new Error("URL tidak boleh berisi kredensial.");
  }

  await validateDestination(url, allowPrivate);

  return new Promise((resolve, reject) => {
    const client = url.protocol === "https:" ? https : http;

    const request = client.request(
      url,
      {
        method,
        timeout: TIMEOUT_MS,
        headers: {
          "User-Agent": `Nightcheck/${VERSION}`
        }
      },
      (response) => {
        const status = response.statusCode;
        const location = response.headers.location;

        if (
          [301, 302, 303, 307, 308].includes(status) &&
          location
        ) {
          response.resume();

          if (redirects >= MAX_REDIRECTS) {
            reject(
              new Error(
                `Terlalu banyak redirect (maksimal ${MAX_REDIRECTS}).`
              )
            );
            return;
          }

          let nextUrl;

          try {
            nextUrl = new URL(location, url);
          } catch {
            reject(new Error("URL redirect tidak valid."));
            return;
          }

          if (!["http:", "https:"].includes(nextUrl.protocol)) {
            reject(
              new Error(
                "Redirect ke protokol yang tidak didukung."
              )
            );
            return;
          }

          requestHeaders(
            nextUrl,
            method,
            redirects + 1,
            options
          )
            .then(resolve)
            .catch(reject);

          return;
        }

        const result = {
          statusCode: status,
          headers: response.headers,
          method,
          finalUrl: url.href
        };

        if (
          method === "HEAD" &&
          [405, 501].includes(status)
        ) {
          response.resume();

          resolve({
            retryWithGet: true,
            finalUrl: url.href
          });
          return;
        }

        if (method === "GET") {
          response.destroy();
        } else {
          response.resume();
        }

        resolve(result);
      }
    );

    request.setTimeout(TIMEOUT_MS, () => {
      request.destroy(
        new Error("Permintaan melewati batas 10 detik.")
      );
    });

    request.on("error", reject);
    request.end();
  });
}

function calculateRiskLevel(presentCount) {
  if (presentCount >= 6) return "LOW";
  if (presentCount >= 4) return "MEDIUM";
  if (presentCount >= 2) return "HIGH";
  return "CRITICAL";
}

async function checkHeaders(input, options = {}) {
  let url;

  try {
    url = new URL(input);
  } catch {
    throw new Error(
      "URL tidak valid. Sertakan https:// atau http://."
    );
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Hanya URL HTTP dan HTTPS yang didukung.");
  }

  if (url.username || url.password) {
    throw new Error("URL tidak boleh berisi kredensial.");
  }

  url.hash = "";

  let response = await requestHeaders(url, "HEAD", 0, options);

  if (response.retryWithGet) {
    const retryUrl = new URL(response.finalUrl ?? url.href);

    response = await requestHeaders(
      retryUrl,
      "GET",
      0,
      options
    );
  }

  const results = SECURITY_HEADERS.map((item) => {
    const value = response.headers[item.name];

    return {
      header: item.name,
      label: item.label,
      present: Boolean(value),
      value: value ?? null,
      recommendation: value ? null : item.recommendation
    };
  });

  const presentCount = results.filter(
    (item) => item.present
  ).length;

  const missingCount = results.length - presentCount;

  return {
    tool: "Nightcheck",
    version: VERSION,
    target: url.origin,
    finalUrl: response.finalUrl ?? url.href,
    checkedAt: new Date().toISOString(),
    httpStatus: response.statusCode,
    method: response.method,
    headers: results,
    summary: {
      total: results.length,
      present: presentCount,
      missing: missingCount,
      riskLevel: calculateRiskLevel(presentCount)
    }
  };
}

function saveReport(report) {
  const directory = path.join(__dirname, "..", "reports");

  fs.mkdirSync(directory, { recursive: true });

  const timestamp = new Date()
    .toISOString()
    .replace(/[:.]/g, "-");

  const filename = `nightcheck-${timestamp}.json`;
  const filepath = path.join(directory, filename);

  fs.writeFileSync(
    filepath,
    JSON.stringify(report, null, 2),
    "utf8"
  );

  return filepath;
}

function printHelp() {
  console.log(`
Nightcheck v${VERSION}
HTTP Security Header Checker

Usage:
  node src/index.js <URL> [--json]
  node src/index.js --help

Options:
  --json    Simpan hasil sebagai laporan JSON
  --help    Tampilkan bantuan

Examples:
  node src/index.js https://example.com
  node src/index.js https://example.com --json

Gunakan hanya pada website yang kamu miliki
atau yang kamu punya izin untuk periksa.
`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.length === 0) {
    printHelp();
    return;
  }

  const shouldExport = args.includes("--json");
  const target = args.find((arg) => !arg.startsWith("--"));

  if (!target) {
    printHelp();
    process.exitCode = 1;
    return;
  }

  try {
    const report = await checkHeaders(target);

    console.log("\n=== NIGHTCHECK SECURITY REPORT ===\n");
    console.log(`Version      : ${report.version}`);
    console.log(`Target       : ${report.target}`);
    console.log(`Final URL    : ${report.finalUrl}`);
    console.log(`HTTP status  : ${report.httpStatus}`);
    console.log(`Method       : ${report.method}`);
    console.log(`Checked at   : ${report.checkedAt}\n`);

    for (const item of report.headers) {
      console.log(
        `${item.present ? "[FOUND]" : "[MISSING]"} ${item.label}`
      );

      if (item.present) {
        console.log(`  Value: ${item.value}`);
      } else {
        console.log(`  Advice: ${item.recommendation}`);
      }

      console.log();
    }

    console.log("--- Summary ---");
    console.log(`Checked    : ${report.summary.total}`);
    console.log(`Found      : ${report.summary.present}`);
    console.log(`Missing    : ${report.summary.missing}`);
    console.log(`Risk level : ${report.summary.riskLevel}`);

    if (shouldExport) {
      console.log(
        `\nJSON report saved: ${saveReport(report)}`
      );
    }
  } catch (error) {
    console.error(`\nNightcheck error: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  checkHeaders,
  saveReport,
  requestHeaders,
  validateDestination,
  isPrivateOrReservedAddress,
  calculateRiskLevel
};
