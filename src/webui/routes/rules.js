import express from 'express';
import path from 'path';
import db from '../../db/db.js';
import { fileURLToPath } from 'url';
import { requireAuth } from '../server.js';
import { logError, logVerbose } from '../../util/log_helper.js';  // J'ai ajouté logVerbose ici

const router = express.Router();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

router.get('/', requireAuth, async (req, res) => {
    logVerbose('GET /rules - Envoi du fichier rules.html');
    res.sendFile(path.join(__dirname, '../public/rules.html'));
});

router.post('/add', requireAuth, async (req, res) => {
    let { host_id, key_ids } = req.body;
  
    try {
      validateHostIdAndKeys(host_id, key_ids);
      await insertRulesTransaction(host_id, key_ids);
      res.send('Associations créées avec succès.');
    } catch (err) {
      if (err.isClientError) {
        logVerbose(`POST /rules/add - ${err.message}`);
        return res.status(400).send(err.message);
      }
      logError('❌ Erreur lors de l’ajout des règles :', err);
      res.status(500).send('Erreur lors de l’ajout des règles');
    }
  });

// Liste des hôtes
router.get('/hosts', requireAuth, async (req, res) => {
    try {
        logVerbose('GET /rules/hosts - Récupération des hôtes');
        const rows = await db('hosts')
        .select('id', 'hostname')
        .orderBy('hostname', 'asc');
        res.json(rows);
    } catch (err) {
        logError('❌ Erreur lors de la récupération des hôtes :', err);
        res.status(500).send('Erreur lors de la récupération des hôtes');
    }
});

// Liste des clés
router.get('/keys', requireAuth, async (req, res) => {
    try {
        logVerbose('GET /rules/keys - Récupération des clés');
        const rows = await db('ssh_keys')
        .select('id', 'name')
        .whereNot('name', 'bastion')
        .orderBy('name', 'asc');
        res.json(rows);
    } catch (err) {
        logError('❌ Erreur lors de la récupération des clés :', err);
        res.status(500).send('Erreur lors de la récupération des clés');
    }
});

// Liste des règles : chaque host avec ses clés associées
router.get('/list', requireAuth, async (req, res) => {
    try {
        logVerbose('GET /rules/list - Récupération des règles');
        const rows = await db('rules')
        .join('hosts', 'rules.host_id', 'hosts.id')
        .join('ssh_keys', 'rules.key_id', 'ssh_keys.id')
        .select(
            'rules.id as rule_id',
            'hosts.id as host_id',
            'hosts.hostname',
            'ssh_keys.id as key_id',
            'ssh_keys.name as key_name'
        )
        .orderBy(['hosts.hostname', 'ssh_keys.name']);

        const grouped = {};
        for (const row of rows) {
            if (!grouped[row.host_id]) {
                grouped[row.host_id] = {
                    rule_id: row.rule_id, // ou null ? car plusieurs clés par host_id
                    host: {
                        id: row.host_id,
                        hostname: row.hostname
                    },
                    keys: []
                };
            }
            grouped[row.host_id].keys.push({
                id: row.key_id,
                name: row.key_name
            });
        }

        const result = Object.values(grouped);
        logVerbose(`GET /rules/list - Récupération terminée, ${result.length} hôtes avec règles`);
        res.json(result);

    } catch (err) {
        logError('❌ Erreur lors de la récupération des règles :', err);
        res.status(500).send('Erreur lors de la récupération des règles');
    }
});

router.post('/delete', requireAuth, async (req, res) => {
    try {
        let { host_id } = req.body;
        host_id = parseInt(host_id, 10);

        if (!host_id) {
            logVerbose('POST /rules/delete - host_id invalide ou manquant');
            return res.status(400).send('host_id requis et doit être un nombre valide.');
        }

        logVerbose(`POST /rules/delete - Suppression des règles pour host_id=${host_id}`);
        const deletedCount = await db('rules')
        .where('host_id', host_id)
        .del();

        logVerbose(`POST /rules/delete - Suppression réussie : ${deletedCount} règle(s) supprimée(s)`);
        res.send(`Suppression réussie : ${deletedCount} règle(s) supprimée(s) pour host_id = ${host_id}.`);
    } catch (err) {
        logError('❌ Erreur lors de la suppression des règles :', err);
        res.status(500).send('Erreur lors de la suppression des règles');
    }
});

router.post('/edit', requireAuth, async (req, res) => {
    let { host_id, changes } = req.body;

    host_id = parseInt(host_id, 10);
    if (!host_id || !Array.isArray(changes) || changes.length === 0) {
        logVerbose('POST /rules/edit - host_id ou liste des changements manquants ou invalides');
        return res.status(400).send('host_id et liste des changements sont requis.');
    }

    changes = changes.map(change => {
        return {
            key_id: parseInt(change.key_id, 10),
            action: change.action && change.action.toLowerCase()
        };
    }).filter(change =>
        !isNaN(change.key_id) && (change.action === 'add' || change.action === 'delete')
    );

    if (changes.length === 0) {
        logVerbose('POST /rules/edit - Liste des changements invalide ou vide après filtrage');
        return res.status(400).send('Liste des changements invalide ou vide.');
    }

    try {
        logVerbose(`POST /rules/edit - Début transaction pour host_id=${host_id} avec ${changes.length} changements`);
        await db.transaction(async trx => {
            for (const change of changes) {
                if (change.action === 'add') {
                    try {
                        await trx('rules').insert({
                            host_id,
                            key_id: change.key_id
                        });
                        logVerbose(`Ajout règle: host_id=${host_id}, key_id=${change.key_id}`);
                    } catch (err) {
                        if (err.code !== 'SQLITE_CONSTRAINT' && err.code !== '23505') {
                            logError('Erreur SQL inattendue lors de l\'ajout d\'une règle:', err);
                            throw err;
                        } else {
                            logVerbose(`Règle déjà existante ignorée à l'ajout : host_id=${host_id}, key_id=${change.key_id}`);
                        }
                    }
                } else if (change.action === 'delete') {
                    await trx('rules')
                    .where({ host_id, key_id: change.key_id })
                    .del();
                    logVerbose(`Suppression règle: host_id=${host_id}, key_id=${change.key_id}`);
                }
            }
        });
        logVerbose('POST /rules/edit - Transaction terminée avec succès');
        res.send('Modifications appliquées avec succès.');
    } catch (err) {
        logError('❌ Erreur lors de la modification des règles :', err);
        res.status(500).send('Erreur lors de la modification des règles');
    }
});


//FONCTIONS

function validateHostIdAndKeys(host_id, key_ids) {
    host_id = parseInt(host_id, 10);
    if (!host_id || !Array.isArray(key_ids) || key_ids.length === 0) {
      const error = new Error('ID de l’hôte ou liste de clés manquante.');
      error.isClientError = true;
      throw error;
    }
    
    const parsedKeys = key_ids.map(k => parseInt(k, 10)).filter(k => !isNaN(k));
    if (parsedKeys.length === 0) {
      const error = new Error('Liste de clés invalide.');
      error.isClientError = true;
      throw error;
    }
  
    return { host_id, key_ids: parsedKeys };
  }
  
  async function insertRulesTransaction(host_id, key_ids) {
    const insertData = key_ids.map(key_id => ({ host_id, key_id }));
  
    await db.transaction(async trx => {
      for (const entry of insertData) {
        try {
          await trx('rules').insert(entry);
          logVerbose(`Insertion rule: host_id=${entry.host_id}, key_id=${entry.key_id}`);
        } catch (err) {
          if (err.code !== 'SQLITE_CONSTRAINT' && err.code !== '23505') {
            throw err;
          } else {
            logVerbose(`Règle déjà existante ignorée : host_id=${entry.host_id}, key_id=${entry.key_id}`);
          }
        }
      }
    });
  }


export default router;
