// 14 · 受害浏览器：带 DVWA 会话 cookie 打开一个 URL，等待页面里的脚本执行
// 用法: NODE_PATH=<puppeteer-core 所在 node_modules> node visit.js <url> "<cookie header>" [waitMs]
const puppeteer = require('puppeteer-core');

const [, , url, cookieHeader, waitMs] = process.argv;
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

(async () => {
  const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new' });
  const page = await browser.newPage();
  const u = new URL(url);
  const cookies = cookieHeader.split(';')
    .map(kv => kv.trim())
    .filter(Boolean)
    .map(kv => {
      const i = kv.indexOf('=');
      return { name: kv.slice(0, i), value: kv.slice(i + 1), domain: u.hostname, path: '/' };
    });
  await page.setCookie(...cookies);
  await page.goto(url, { waitUntil: 'networkidle2', timeout: 20000 });
  await new Promise(r => setTimeout(r, Number(waitMs || 2000)));
  await browser.close();
  console.log('visited:', url);
})().catch(e => {
  console.error('visit error:', e.message);
  process.exit(1);
});
