import express from 'express';
import { validate } from './middleware/validate.js';
import { healthCheckSchema } from './schemas/health.schema.js';
import { HealthHandler } from './handlers/health.handler.js';
import authRoutes from './routes/auth.routes.js';
import morgan from 'morgan';
import { Request, Response } from 'express';
import { Request as JWTRequest } from 'express-jwt';
import { uploadSchema } from './schemas/upload.schema.js';
import { UploadHandler } from './handlers/upload.handler.js';
import multer from 'multer';
import expressjwt from 'express-jwt';
import { browserCtx } from './__tests__/setup.js';
import cookieParser from 'cookie-parser';
import { AuthHandler, User } from './handlers/auth.handler.js';
import jwt from 'jsonwebtoken';

// file deepcode ignore DisablePoweredBy: bcs this just a challenge

const app = express();
// export const secret_key = 'secret_key';
export const port = process.env.PORT || 3000;

app.use(express.static('uploads'));
const upload = multer({ storage: multer.memoryStorage() });
export const secret_key = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

app.use(morgan('combined'));

app.use(express.json());
app.use((req, res, next) => {
  const secFetchMode = req.get('Sec-Fetch-Mode');

  if (secFetchMode && secFetchMode !== 'navigate') {
    return res.status(403).send('Blocked: Please navigating on your own. this is an api for unit test');
  }

  next();
});
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const jwtMiddleware = expressjwt.expressjwt({ secret: secret_key, algorithms: ['HS256'] });

app.get('/api/health', validate(healthCheckSchema), HealthHandler.check);
app.post(
  '/api/upload',
  upload.array('files', 1),
  validate(uploadSchema),
  expressjwt.expressjwt({ secret: secret_key, algorithms: ['HS256'] }),
  UploadHandler.Png
);

app.use('/api/auth', authRoutes);

app.post('/api/runtest', jwtMiddleware, async (req: JWTRequest, res: Response) => {
  if (!req.auth) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  if (!req.auth.admin) {
    return res.status(403).json({ message: 'Forbidden' });
  }
  const url = req.body.url as string;
  const timeout = req.body.timeout as number || 0;
  if (timeout > 5000) {
    return res.status(400).json({ message: 'Timeout is too long' });
  }
  if (!url) {
    return res.status(400).json({ message: 'URL is required' });
  }
  if (url.length > 60) {
    console.log('URL is too long');
    return res.status(400).json({ message: 'URL is too long' });
  }
  const urlP = new URL(url);
  if (!url.includes('http://localhost')) {
    return res.status(400).json({ message: 'URL must be localhost' });
  }

  const context = await browserCtx();
  await context.setExtraHTTPHeaders({
    Authorization: req.headers.authorization || '',
  });
  const user = jwt.decode(req.cookies.user || req.headers.authorization!.split(' ')[1]) as User;

  const page = await context.newPage();
  try {
    if (!user.debug_mode) {
      if (urlP.hostname) {
        if (!['localhost', '127.0.0.1'].includes(urlP.hostname)) {
          return res.status(400).json({ message: 'URL must be localhost' });
        }
      }

      const response = await page.goto(url, {
        waitUntil: 'load',
        timeout: timeout,
      });
      if (!response) {
        throw new Error('No response received');
      }
    }
    if (user.debug_mode) {
      if (urlP.hostname) {
        if (!['localhost', '127.0.0.1'].includes(urlP.hostname)) {
          return res.status(400).json({ message: 'URL must be localhost' });
        }
      }
      console.info('Debug mode is enabled, skipping page.goto for URL:', url);
      await page.goto(url, {
        waitUntil: 'load',
        timeout: timeout,
      });
      const content = await page.content();
      if (!content) {
        throw new Error('No response received from page.goto');
      }
      AuthHandler.users.push({
        email: user.email,
        password: 'dbgpass1234',
        debug_mode: false,
        log: content,
      });
    }
  } catch (error) {
    console.error('Error during page navigation:', error);
    return res.status(500).json({ message: 'Internal Server Error' });
  } finally {
    await page.waitForTimeout(timeout);
    // await page.waitForTimeout(100000000);
    await page.close();
    await context.close();
  }

  res.status(200).json({ message: 'unit test success' });
});

// Start server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

export default app;
