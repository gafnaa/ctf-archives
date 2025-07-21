/**
 * Copyright (c) 2025 replican
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { browserCtx } from '../setup';
import { port } from '../../index.js';

const baseUrl = `http://localhost:${port}`;
let context: Awaited<ReturnType<typeof browserCtx>>;

describe('Health Check Endpoint', () => {
  beforeAll(async () => {
    context = await browserCtx();
  });

  afterAll(async () => {
    await context.close();
  });

  it('should return basic health status when no includeDetails provided', async () => {
    const page = await context.newPage();
    try {
      const response = await page.goto(`${baseUrl}/api/health`, {
        waitUntil: 'load',
        timeout: 5000,
      });
      if (!response) {
        throw new Error('No response received from page.goto');
      }
      expect(response.status()).toBe(200);
      const data = await response.json();
      expect(data).toEqual({
        status: 'ok',
        message: 'Server is healthy',
      });
    } finally {
      await page.close();
    }
  });

  it('should handle multiple query parameters correctly', async () => {
    const page = await context.newPage();
    try {
      const response = await page.goto(`${baseUrl}/api/health?includeDetails=true&other=value`, {
        waitUntil: 'load',
        timeout: 5000,
      });
      if (!response) {
        throw new Error('No response received from page.goto');
      }
      expect(response.status()).toBe(200);
      const data = await response.json();
      expect(data).toMatchObject({
        status: 'ok',
        message: 'Server is healthy',
        timestamp: expect.any(String),
        uptime: expect.any(Number),
      });
    } finally {
      await page.close();
    }
  });
});
