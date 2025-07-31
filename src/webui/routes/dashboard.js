import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { requireAuth } from '../server.js';

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Route pour afficher le tableau de bord
router.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

// Route pour exposer le nom d'utilisateur en session (optionnel)
router.get('/api/session', requireAuth, (req, res) => {
  const user = req.session.user || null;
  res.json({ user });
});

export default router;
