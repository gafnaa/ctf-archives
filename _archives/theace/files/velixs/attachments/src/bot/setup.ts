/**
 * Copyright (c) 2025 replican
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import {  chromium, firefox } from 'playwright';
import type { LaunchOptions,Browser, BrowserContext } from 'playwright';
import fs from 'fs';
import path from 'path';

const browserType = process.env.PLAYWRIGHT_BROWSER_TYPE || 'chromium';
// const browserPath = process.env.PLAYWRIGHT_BROWSER_PATH || '/usr/bin/chromium';
const browserHeadless = !(process.env.PLAYWRIGHT_DISPLAY === undefined && fs.existsSync('/tmp/.X11-unix'));

console.info(`Using browser type: ${browserType}, headless: ${browserHeadless}`);
let sharedBrowser: Browser | null = null;


/**
 * Returns a comma-separated string of extension directories.
 */
function getBrowserExtension(): string {
  const extDir = path.join(__dirname, 'extensions');
  if (!fs.existsSync(extDir)) return '';
  const dirs = fs.readdirSync(extDir).filter((file) => {
    const fullPath = path.join(extDir, file);
    return fs.lstatSync(fullPath).isDirectory();
  });
  return dirs.map((dir) => path.join(extDir, dir)).join(',');
}

/**
 * Constructs launch options for the browser.
 * @param extension - Comma-separated list of extension directories.
 */
function getLaunchOptions(extension: string): LaunchOptions {
  const extensionArgs = extension
    ? [
        `--disable-extensions-except=${extension}`,
        `--load-extension=${extension}`,
      ]
    : [
        '--disable-extensions',
        '--no-gpu',
        '--disable-translate',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
    ];
  
  return {
    // executablePath: browserPath,
    headless: browserHeadless,
    args: extensionArgs,
  };
}

/**
 * Launches a browser based on the provided options.
 * Reuses a shared instance if no extensions are loaded.
 * @param options - Launch options for the browser.
 */
async function launchBrowser(options: LaunchOptions): Promise<Browser> {
  if (!getBrowserExtension() && sharedBrowser) {
    return sharedBrowser;
  }
  if (browserType === 'firefox') {
    return firefox.launch(options);
  } else {
    // Default to chromium
    return chromium.launch(options);
  }
}

/**
 * Initializes and returns a new browser context with HTTPS errors ignored.
 * Uses a shared browser instance when no extensions are present.
 */
export async function browserCtx(): Promise<BrowserContext> {
  const extension = getBrowserExtension();
  const launchOptions = getLaunchOptions(extension);
  
  let browser: Browser;
  if (!extension) {
    if (!sharedBrowser) {
      sharedBrowser = await launchBrowser(launchOptions);
    }
    browser = sharedBrowser;
  } else {
    // Launch a new browser instance if extensions are used.
    browser = await launchBrowser(launchOptions);
  }

// Usage: 

  
  return browser.newContext({ ignoreHTTPSErrors: true });
}