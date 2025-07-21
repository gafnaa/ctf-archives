import { z } from 'zod';

export const healthCheckSchema = z.object({
  query: z.object({
    includeDetails: z
      .union([
        z.boolean(),
        z
          .string()
          .refine((val) => val === '1' || val === '0' || val === 'true' || val === 'false', {
            message: 'includeDetails must be true, false, 1, 0, "true", or "false"',
          }),
      ])
      .transform((val) => {
        if (typeof val === 'string') {
          if (val === '1' || val === 'true') return true;
          if (val === '0' || val === 'false') return false;
          return false;
        }
        return val;
      })
      .optional(),
  }),
});

export type HealthCheckQuery = z.infer<typeof healthCheckSchema>['query'];
