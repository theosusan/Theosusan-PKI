import express from 'express';
import path from 'path';
import db from '../../db/db.js';
import { fileURLToPath } from 'url';
import { generateKey } from '../../cli/manage_keys.js';
import { requireAuth } from '../server.js';
import { decrypt } from '../../util/crypto_util.js';
import { logError, logVerbose } from '../../util/log_helper.js';
import { deleteKeyById } from '../../cli/manage_keys.js';

const router = express.Router();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

router.get('/', requireAuth, async (req, res) => {
  res.sendFile(path.join(__dirname, '../public/keys.html'));
});

router.post('/', async (req, res) => {
  const { name } = req.body;
  const comment = 'THEOSUSAN-PKI[' + name.toUpperCase() + ']';
  try {
    const result = await generateKey({ name, comment, checkExists: true });
    
    if (result.success) {
      logVerbose(`Clé générée avec succès pour le nom "${name}"`);
      res.send(result.message);
    } else {
      logVerbose(`Échec génération clé pour "${name}": ${result.message}`);
      res.status(400).send(result.message);
    }
  } catch (err) {
    logError('❌ Erreur lors de la génération de la clé :', err);
    res.status(500).send('Erreur lors de la génération de la clé');
  }
});

router.get('/list', requireAuth, async (req, res) => {
  try {
    const rows = await db('ssh_keys')
      .select('id', 'name', 'publicKey')
      .whereNot('name', 'bastion')
      .orderBy('id', 'asc');

    logVerbose(`Liste des clés récupérée, ${rows.length} clés trouvées`);
    res.json(rows);
  } catch (err) {
    logError('❌ Erreur lors de la récupération des clés :', err);
    res.status(500).send('Erreur lors de la récupération des clés');
  }
});

router.get('/bastion', requireAuth, async (req, res) => {
  try {
    const bastionKey = await getBastionPublicKey();
    logVerbose('Clé bastion récupérée');
    res.json(bastionKey);
  } catch (err) {
    if (err.message === 'Clé bastion introuvable') {
      logVerbose(err.message);
      res.status(404).send(err.message);
    } else {
      logError('❌ Erreur lors de la récupération de la clé bastion :', err);
      res.status(500).send('Erreur lors de la récupération de la clé');
    }
  }
})

router.delete('/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await deleteKeyById(id);

    if (result.success) {
      logVerbose(`Clé id=${id} supprimée avec succès`);
      res.send(result.message);
    } else {
      logError(`Erreur suppression clé id=${id} : ${result.message}`);
      res.status(result.message === 'Clé non trouvée.' ? 404 : 500).send(result.message);
    }
  } catch (err) {
    logError(`❌ Exception lors de la suppression de la clé id=${id} :`, err);
    res.status(500).send('Erreur serveur');
  }
});

// Route pour télécharger la clé privée déchiffrée (sans extension)
router.get('/download/:id', requireAuth, async (req, res) => {
  try {
    const row = await db('ssh_keys').where({ id: req.params.id }).first();
    if (!row) {
      logVerbose(`Clé id=${req.params.id} introuvable pour téléchargement`);
      return res.status(404).send('Clé introuvable');
    }
    
    const decrypted = decrypt(row.privateKey);
    logVerbose(`Clé privée id=${req.params.id} déchiffrée et envoyée en téléchargement`);
    
    res.setHeader('Content-Disposition', `attachment; filename="${row.name}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(decrypted);
  } catch (err) {
    logError('❌ Erreur lors du téléchargement de la clé :', err);
    res.status(500).send('Erreur serveur');
  }
});

// Route pour afficher la clé privée déchiffrée (en texte simple)
router.get('/show-private/:id', requireAuth, async (req, res) => {
  try {
    const row = await db('ssh_keys').where({ id: req.params.id }).first();
    if (!row) {
      logVerbose(`Clé id=${req.params.id} introuvable pour affichage`);
      return res.status(404).send('Clé introuvable');
    }
    
    const decrypted = decrypt(row.privateKey);
    logVerbose(`Clé privée id=${req.params.id} déchiffrée et affichée en texte`);
    res.type('text/plain').send(decrypted);
  } catch (err) {
    logError('❌ Erreur lors de l’affichage de la clé :', err);
    res.status(500).send('Erreur serveur');
  }
});

//FONCTIONS

export async function getBastionPublicKey() {
  const row = await db('ssh_keys')
    .select('id', 'publicKey')
    .where('name', 'bastion')
    .first();

  if (!row) {
    throw new Error('Clé bastion introuvable');
  }
  return row;
}

export default router;
