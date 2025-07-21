import { z } from 'zod';

// Login schema

export const authLoginSchema = z.object({
    body: z.object({
      email: z.string().email({ message: 'Invalid email address' }),
      password: z.string().min(6, { message: 'Password must be at least 6 characters' }),
    }),
  });
  
export type AuthLoginRequest = z.infer<typeof authLoginSchema>['body'];


// Register schema with password confirmation
export const authRegisterSchema = z.object({
  body: z
    .object({
      email: z.string().email({ message: 'Invalid email address' }),
      password: z.string().min(6, { message: 'Password must be at least 6 characters' }),
    })
});

export type AuthRegisterRequest = z.infer<typeof authRegisterSchema>['body'];