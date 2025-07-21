import express from 'express';
import path from 'path';
import { run } from './bot';

const app = express();
const PORT = 3001;

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

app.post('/run', async (req, res) => {
  try {
    console.log('🔁 /run triggered');
    await run();
    res.json({ success: true, message: 'Crawl complete.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to run.', error: err });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running at http://0.0.0.0:${PORT}`);
});