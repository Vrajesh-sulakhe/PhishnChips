const { chromium } = require('playwright-core');
const fs = require('fs');

const TARGET_URL = process.env.TARGET_URL;
const TIMEOUT_MS = parseInt(process.env.TIMEOUT_MS || '15000', 10);

if (!TARGET_URL) {
  console.error(JSON.stringify({ error: "TARGET_URL environment variable missing." }));
  process.exit(1);
}

(async () => {
  const result = {
    target: TARGET_URL,
    timestamp: new Date().toISOString(),
    redirects: [],
    networkRequests: [],
    domMetadata: {},
    error: null
  };

  let browser;
  try {
    browser = await chromium.launch({
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-zygote',
        '--single-process'
      ]
    });

    const context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
      viewport: { width: 1280, height: 720 },
      ignoreHTTPSErrors: true
    });

    const page = await context.newPage();

    // Log outbound network requests
    page.on('request', req => {
      result.networkRequests.push({
        url: req.url(),
        method: req.method(),
        resourceType: req.resourceType()
      });
    });

    // Track redirect chains
    page.on('response', res => {
      if (res.status() >= 300 && res.status() < 400) {
        result.redirects.push({ 
          from: res.url(), 
          status: res.status(), 
          location: res.headers()['location'] 
        });
      }
    });

    const response = await page.goto(TARGET_URL, {
      waitUntil: 'networkidle',
      timeout: TIMEOUT_MS
    });

    result.finalUrl = page.url();
    result.httpStatus = response ? response.status() : null;

    // Collect DOM evidence
    result.domMetadata = await page.evaluate(() => {
      const inputs = Array.from(document.querySelectorAll('input')).map(i => ({
        type: i.type,
        name: i.name,
        placeholder: i.placeholder,
        autocomplete: i.autocomplete
      }));
      return {
        title: document.title,
        hasPasswordInput: inputs.some(i => i.type === 'password'),
        inputCount: inputs.length,
        inputs: inputs,
        formsCount: document.querySelectorAll('form').length,
        externalScripts: Array.from(document.querySelectorAll('script[src]')).map(s => s.src)
      };
    });

    // Capture visual snapshot
    await page.screenshot({ path: '/output/screenshot.png', fullPage: true });

  } catch (err) {
    result.error = err.message;
  } finally {
    if (browser) await browser.close();
    fs.writeFileSync('/output/report.json', JSON.stringify(result, null, 2));
    console.log(JSON.stringify({ status: "completed", finalUrl: result.finalUrl, error: result.error }));
  }
})();
