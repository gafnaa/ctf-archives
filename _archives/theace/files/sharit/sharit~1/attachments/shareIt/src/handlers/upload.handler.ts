import {  Response } from 'express';
import {  Request as JWTRequest } from 'express-jwt';
import fs from 'fs';

export class UploadHandler {
  static async Png(req: JWTRequest, res: Response) {
    if (!req.auth) {
        return res
            .status(401)
            .json({ message: 'Unauthorized' });
    }
    if (!req.auth.admin) {
      return res
        .status(403)
        .json({ message: 'Forbidden' });
    }
    if (!req.validatedFiles) {
      return res.status(400).json({ status: 'error', message: 'File is required' });
    }


    const fileName = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    const fileExtension = req.validatedFiles[0].originalname.split('.').pop();

    const fullFileName = fileName + '.' + fileExtension;
    
    fs.writeFileSync('./uploads/' + fullFileName, req.validatedFiles[0].buffer);
    
    return res.status(200).json({ message: fullFileName});
  }
}
