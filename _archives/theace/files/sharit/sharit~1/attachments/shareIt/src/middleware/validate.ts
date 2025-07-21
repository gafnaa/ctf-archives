import { Request, Response, NextFunction } from 'express';
import { AnyZodObject, ZodError } from 'zod';
import jwt from 'jsonwebtoken';
import { secret_key } from '..';


export const validate = (schema: AnyZodObject) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = jwt.sign({ email: 'guest', admin: false }, secret_key, { expiresIn: '1h' });
      if (!req.headers.authorization) {
        req.headers.authorization = `Bearer ${token}`;
      }
      const validatedData = await schema.parseAsync({
        body: req.body,
        files: req.files,
        query: req.query,
        params: req.params,
      });
      req.validatedFiles = validatedData.files;
      req.validatedQuery = validatedData.query;
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        return res.status(400).json({
          status: 'error',
          message: 'Validation failed',
          errors: error.errors.map((err) => ({
            field: err.path.join('.'),
            message: err.message,
          })),
        });
      }
      next(error);
    }
  };
};
