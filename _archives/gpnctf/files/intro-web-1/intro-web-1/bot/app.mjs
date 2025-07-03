import express from "express";
import puppeteer from "puppeteer";
import crypto from "crypto";

const app = express();

const browserPromise = puppeteer.launch({args: ['--no-sandbox']});

const baseUrl = process.env.CHALLENGE_SERVICE_URL || 'http://localhost:9222';
const password = process.env.ADMIN_PASSWORD;
const FLAG_STAGE_2 = process.env.FLAG_STAGE_2;
const FLAG_STAGE_3 = process.env.FLAG_STAGE_3;

async function initializeBot() {
    try {
        const browser = await browserPromise;

        await browser.setCookie({
            domain: baseUrl.replace('http://', '').replace('https://', ''),
            name: 'FLAG',
            value: FLAG_STAGE_3,
            httpOnly: false,

        })

        await browser.setCookie({
            domain: baseUrl.replace('http://', '').replace('https://', ''),
            name: 'ADMIN_PASSWORD',
            value: password,
            httpOnly: true,
        })

        const page = await browser.newPage();
        const randomUser = 'I_am_the_admin_' + crypto.randomBytes(32).toString('hex');

        await page.goto(`${baseUrl}/login`, {waitUntil: 'networkidle2'});
        await page.type('input[name="username"]', randomUser);
        await page.type('input[name="password"]', password);
        await page.click('button[type="submit"]');
        await page.waitForNavigation({waitUntil: 'networkidle2'});

        await page.goto(`${baseUrl}/note/new`, {waitUntil: 'networkidle2'});
        await page.type('input[name="title"]', 'My juicy note');
        await page.type('textarea[name="content"]', `Here you got some juicy flag: ${FLAG_STAGE_2}`);
        await page.click('button[type="submit"]');
        await page.waitForNavigation({waitUntil: 'networkidle2'});
        console.log(`Admin logged in as ${randomUser} with password ${password} and created initial note.`);
        await page.close();
    } catch (err) {
        console.error('Initialization failed:', err);
        throw err;
    }
}

await initializeBot()

app.use(express.json());

app.post('/bot', async (req, res) => {
    const url = req.body.url;
    if (!url) {
        res.status(400).send('Missing url parameter');
        return;
    }
    try {
        const browser = await browserPromise;
        const page = await browser.newPage();
        console.log(`Visiting URL: ''${url}''`);
        await page.goto(url, {timeout: 5000, waitUntil: 'networkidle0'});
        await new Promise(r => setTimeout(r, 5000));
        res.send(`Bot visited your url ${url}`);
        await page.close();
    } catch (err) {
        console.error('Error in /bot handler:', err);
        res.status(502).send(`Could not reach ${url}`);
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Bot running on port ${PORT}`);
});
