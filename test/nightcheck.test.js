
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const {
  checkHeaders,
  calculateRiskLevel
} = require("../src/index");

test("menolak URL yang tidak valid", async () => {
  await assert.rejects(
    checkHeaders("ini-bukan-url"),
    /URL tidak valid/
  );
});

test("menolak protokol yang tidak didukung", async () => {
  await assert.rejects(
    checkHeaders("ftp://example.com"),
    /Hanya URL HTTP dan HTTPS/
  );
});

test("menghitung tingkat risiko berdasarkan jumlah header", () => {
  assert.equal(calculateRiskLevel(6), "LOW");
  assert.equal(calculateRiskLevel(5), "MEDIUM");
  assert.equal(calculateRiskLevel(4), "MEDIUM");
  assert.equal(calculateRiskLevel(3), "HIGH");
  assert.equal(calculateRiskLevel(2), "HIGH");
  assert.equal(calculateRiskLevel(1), "CRITICAL");
  assert.equal(calculateRiskLevel(0), "CRITICAL");
});

test("memeriksa security headers dari server lokal", async (t) => {
  const server = http.createServer((req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.statusCode = 200;
    res.end("OK");
  });

  await new Promise((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  t.after(() => {
    server.close();
  });

  const address = server.address();
  const url = `http://127.0.0.1:${address.port}`;

  const report = await checkHeaders(url, {
    allowPrivate: true
  });

  assert.equal(report.httpStatus, 200);
  assert.equal(report.summary.total, 6);
  assert.equal(report.summary.present, 2);
  assert.equal(report.summary.missing, 4);

  const header = report.headers.find(
    (item) => item.header === "x-content-type-options"
  );

  assert.equal(header.present, true);
  assert.equal(header.value, "nosniff");
});

test("mengikuti redirect dan memeriksa header URL tujuan", async (t) => {
  const destinationServer = http.createServer((req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.statusCode = 200;
    res.end("Destination");
  });

  await new Promise((resolve) => {
    destinationServer.listen(0, "127.0.0.1", resolve);
  });

  t.after(() => {
    destinationServer.close();
  });

  const destinationAddress = destinationServer.address();
  const destinationUrl =
    `http://127.0.0.1:${destinationAddress.port}/`;

  const redirectServer = http.createServer((req, res) => {
    res.statusCode = 302;
    res.setHeader("Location", destinationUrl);
    res.end();
  });

  await new Promise((resolve) => {
    redirectServer.listen(0, "127.0.0.1", resolve);
  });

  t.after(() => {
    redirectServer.close();
  });

  const redirectAddress = redirectServer.address();
  const redirectUrl =
    `http://127.0.0.1:${redirectAddress.port}/`;

  const report = await checkHeaders(redirectUrl, {
    allowPrivate: true
  });

  assert.equal(report.httpStatus, 200);
  assert.equal(report.finalUrl, destinationUrl);

  const header = report.headers.find(
    (item) => item.header === "x-content-type-options"
  );

  assert.equal(header.present, true);
  assert.equal(header.value, "nosniff");
});
