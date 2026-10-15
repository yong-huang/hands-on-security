#!/usr/bin/env node
// 29 · 管理员机器人（模拟「运营人员点开了你的留言」）：
//   带 admin_session cookie 打开留言页，页面里被注入的脚本会在浏览器中
//   执行并把 document.cookie 外带到平台的 /c4/exfil —— 真实 XSS 通路。
//   用法: node admin_bot.js <url> <cookie>
const puppeteer = require('puppeteer-core');

(async () => {
    const [url, cookie] = process.argv.slice(2);
    const [name, value] = cookie.split('=');
    const browser = await puppeteer.launch({
        executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        headless: 'new',
    });
    const page = await browser.newPage();
    await page.setCookie({ name, value, domain: '127.0.0.1' });
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 });
    await new Promise((r) => setTimeout(r, 1500)); // 等脚本外带完成
    await browser.close();
})().catch((e) => { console.error('bot error:', e.message); process.exit(1); });
