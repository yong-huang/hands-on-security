// 15 · 受害浏览器：带 DVWA 会话 cookie 打开一个 URL（默认等 2 秒），报告最终落点
// 用法: NODE_PATH=<node_modules> node visit.js <url> "<cookie header>" [waitMs]
const puppeteer = require('puppeteer-core');

const [, , url, cookieHeader, waitMs] = process.argv;
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

(async () => {
  const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new' });
  const page = await browser.newPage();
  const domain = new URL(url).hostname;
  const cookies = cookieHeader.split(';')
    .map(kv => kv.trim())
    .filter(Boolean)
    .map(kv => {
      const i = kv.indexOf('=');
      return { name: kv.slice(0, i), value: kv.slice(i + 1), domain, path: '/' };
    });
  await page.setCookie(...cookies);
  await page.goto(url, { waitUntil: 'networkidle2', timeout: 20000 });
  await new Promise(r => setTimeout(r, Number(waitMs || 2000)));
  console.log('visited:', url);
  console.log('final:  ', page.url());
  console.log('changed:', (await page.content()).includes('Password Changed.'));
  await browser.close();
})().catch(e => {
  console.error('visit error:', e.message);
  process.exit(1);
});
