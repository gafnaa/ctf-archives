import { Request, Response } from 'express';
import { HealthCheckQuery } from '../schemas/health.schema.js';

export class HealthHandler {
  public static check(req: Request, res: Response): void {
    const query = req.validatedQuery as HealthCheckQuery;
    const response = {
      status: 'ok',
      message: 'Server is healthy',
    };

    if (query?.includeDetails) {
      Object.assign(response, {
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
      });
    }

    res.json(response);
  }
}
