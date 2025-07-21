import { HealthCheckQuery } from '../schemas/health.schema.js';
import { uploadFile } from '../schemas/upload.schema.js';


declare global {
  namespace Express {
    interface Request {
      validatedFiles?: uploadFile;
      validatedQuery?: HealthCheckQuery;
    }
  }
}

export {};
