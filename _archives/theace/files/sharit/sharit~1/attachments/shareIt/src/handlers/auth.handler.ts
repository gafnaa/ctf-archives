import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { secret_key } from '..';

export interface User {
  email: string;
  password: string;
  log?: string;
  // default value
  debug_mode: boolean;
}

interface Admin {
  email: string;
  password: string;
}

function isPrivateIP(ip: string): boolean {
  var parts = ip.split('.');
  return (
    parts[0] === '10' ||
    (parts[0] === '172' && parseInt(parts[1], 10) >= 16 && parseInt(parts[1], 10) <= 31) ||
    (parts[0] === '192' && parts[1] === '168')
  );
}

export class AuthHandler {
  static users: User[] = [];
  static admins: Admin[] = [{ email: 'admin', password: Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) }];

  static async init(req: Request, res: Response) {
    let email = 'initdbg';
    let dbg = false;
    const parsedLocaladdr = req.socket.localAddress?.replace(/::ffff:/, '') || '';
    const parsedRemoteaddr = req.socket.remoteAddress?.replace(/::ffff:/, '') || '';
    if (!parsedRemoteaddr) {
      return res.status(400).json({ message: 'Invalid remote address' });
    }
    var isLocal = parsedLocaladdr === parsedRemoteaddr || parsedRemoteaddr === '::1' || isPrivateIP(parsedRemoteaddr);
    if (req.headers.authorization && isLocal) {
      const token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, secret_key);
      if (decoded) {
        const user = jwt.decode(token) as User;
        dbg = true;
        email = user.email;
      }
    }
    console.log(
      'debugging mode:',
      dbg,
      'email:',
      email,
      'localAddress:',
      parsedLocaladdr,
      'remoteAddress:',
      parsedRemoteaddr
    );
    res.cookie(
      'user',
      jwt.sign({ email: email, admin: false, debug_mode: dbg }, secret_key, { expiresIn: '1h' })
    );
    res.status(200).json({ message: 'Auth system initialized' });
  }

  static async login(req: Request, res: Response) {
    const { email, password } = req.body;
    const user = [...AuthHandler.users].reverse().find((u) => u.email === email);
    if (!user || user.password !== password) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const adminEmails = AuthHandler.admins.map((a) => a.email);
    const { password: _, ...userData } = user;
    for (const key in userData) {
      if (userData.hasOwnProperty(key)) {
        const keyClean = key.trim();
        if (keyClean.includes('email')) {
          const value = userData[key as keyof typeof userData];
          if (!value) continue;
          if (typeof value === 'boolean') continue;
          if (adminEmails.includes(value.trim())) {
            const token = jwt.sign({ email, admin: true }, secret_key, {
              expiresIn: '1h',
            });
            res.setHeader('Authorization', `Bearer ${token}`);
            return res.status(200).json({ user: user, token: token });
          }
        }
      }
    }
    const token = jwt.sign({ email, admin: false }, secret_key, {
      expiresIn: '1h',
    });
    res.setHeader('Authorization', `Bearer ${token}`);
    return res.status(200).json({ user: user, token: token });
  }

  // Register endpoint handler
  static async register(req: Request, res: Response) {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    if (AuthHandler.users.some((u) => u.email === email)) {
      return res.status(409).json({ message: 'Email already registered' });
    }
    AuthHandler.users.push(req.body);
    return res.status(201).json({ message: 'Registration successful' });
  }
}
