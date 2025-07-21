import { browserCtx } from "./setup";
import * as dotenv from "dotenv";

dotenv.config();

async function run() {
  const context = await browserCtx();
  const visited = new Set<string>();

  try {
    const page = await context.newPage();
    await page.goto(`${process.env.BASE_URL}/login`);
    await page.fill('input[name="username"]', "ilsya");
    await page.fill('input[name="password"]', process.env.PASS_ADMIN!);
    await page.click('button[type="submit"]');
    await page.waitForSelector(".toast-ilsya-msg");
    await page.goto(`${process.env.BASE_URL}/admin`);
    const links = await page.$$eval("a[href]", (as) =>
      as
        .map((a) => (a as HTMLAnchorElement).href)
        .filter((href) => href.includes("/admin"))
    );
    console.log(`Found ${links.length} /admin links.`);
    for (const url of links) {
      if (visited.has(url)) continue;
      visited.add(url);

      try {
        console.log(`Visiting: ${url}`);
        await page.goto(url, { waitUntil: "networkidle" });
        const title = await page.title();
        console.log(`  ✔️ ${url} - ${title}`);
      } catch (err) {
        console.error(`  ❌ Failed to visit ${url}:`, err);
      }
    }
  } catch (error) {
    console.error(error);
  } finally {
    await context.close();
  }
}


export { run };