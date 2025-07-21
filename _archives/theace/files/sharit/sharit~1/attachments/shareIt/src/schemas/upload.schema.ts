import { z } from 'zod';


const fileSchema = z.object({
  originalname: z.string(),
  mimetype: z.any(),
  size: z.number().gt(0),
  buffer: z.instanceof(Buffer),
});


const allImage = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/x-icon',
  'image/vnd.microsoft.icon',
  'image/tiff',
  'image/heic',
  'image/heif',
  'image/avif',
  'image/jxl',
  'image/x-canon-cr2',
  'image/x-nikon-nef',
  'image/x-sony-arw',
  'image/x-adobe-dng',
  'image/dng',
  'image/x-olympus-orf',
  'image/x-panasonic-rw2'
];


export const uploadSchema = z.object({
  files: z
    .array(fileSchema)
    .min(1, { message: 'File is required' })
    .refine(
      (files) =>
        files.every(
          (f) =>
            allImage.includes(f.mimetype)
        ),
      { message: 'Only image files are supported' }
    ),
});

// export type HealthCheckQuery = z.infer<typeof healthCheckSchema>['query'];
export type uploadFile = z.infer<typeof uploadSchema>['files'];
