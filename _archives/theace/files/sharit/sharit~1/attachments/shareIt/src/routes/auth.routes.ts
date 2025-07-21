import { Router } from 'express';
import { validate } from '../middleware/validate.js';
import { authLoginSchema, authRegisterSchema } from '../schemas/auth.schema.js';
import { AuthHandler } from '../handlers/auth.handler.js';

const router = Router();

router.post('/login', validate(authLoginSchema), AuthHandler.login);
router.post('/register', validate(authRegisterSchema), AuthHandler.register);
router.get('/init', AuthHandler.init); // Initialize the auth system
export default router;
