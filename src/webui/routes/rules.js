import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { rateLimit } from 'express-rate-limit';

import db from '../../db/db.js';
import { requireAuth } from '../server.js';
import { logError, logVerbose } from '../../util/log_helper.js';

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const rulesWriteLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Trop de requêtes. Veuillez réessayer plus tard.'
    }
});

const rulesReadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message:
        'Trop de requêtes de lecture sur les règles. Veuillez réessayer plus tard.'
});

router.get('/', requireAuth, async (req, res) => {
    logVerbose('GET /rules - Envoi du fichier rules.html');

    res.sendFile(
        path.join(__dirname, '../public/rules.html')
    );
});

router.post(
    '/add',
    requireAuth,
    rulesWriteLimiter,
    async (req, res) => {
        try {
            const { host_id, key_ids } = validateHostIdAndKeys(
                req.body.host_id,
                req.body.key_ids
            );

            await insertRulesTransaction(host_id, key_ids);

            res.send('Associations créées avec succès.');

        } catch (err) {
            if (err.isClientError) {
                logVerbose(`POST /rules/add - ${err.message}`);

                return res
                    .status(400)
                    .send(err.message);
            }

            logError(
                '❌ Erreur lors de l’ajout des règles :',
                err
            );

            res
                .status(500)
                .send('Erreur lors de l’ajout des règles');
        }
    }
);

router.get(
    '/hosts',
    requireAuth,
    async (req, res) => {
        try {
            logVerbose(
                'GET /rules/hosts - Récupération des hôtes'
            );

            const rows = await db('hosts')
                .select('id', 'hostname')
                .orderBy('hostname', 'asc');

            res.json(rows);

        } catch (err) {
            logError(
                '❌ Erreur lors de la récupération des hôtes :',
                err
            );

            res
                .status(500)
                .send(
                    'Erreur lors de la récupération des hôtes'
                );
        }
    }
);

router.get(
    '/keys',
    requireAuth,
    async (req, res) => {
        try {
            logVerbose(
                'GET /rules/keys - Récupération des clés'
            );

            const rows = await db('ssh_keys')
                .select('id', 'name')
                .whereNot('name', 'bastion')
                .orderBy('name', 'asc');

            res.json(rows);

        } catch (err) {
            logError(
                '❌ Erreur lors de la récupération des clés :',
                err
            );

            res
                .status(500)
                .send(
                    'Erreur lors de la récupération des clés'
                );
        }
    }
);

router.get(
    '/list',
    requireAuth,
    rulesReadLimiter,
    async (req, res) => {
        try {
            logVerbose(
                'GET /rules/list - Récupération des règles'
            );

            const rows = await db('rules')
                .join(
                    'hosts',
                    'rules.host_id',
                    'hosts.id'
                )
                .join(
                    'ssh_keys',
                    'rules.key_id',
                    'ssh_keys.id'
                )
                .select(
                    'rules.id as rule_id',
                    'hosts.id as host_id',
                    'hosts.hostname',
                    'ssh_keys.id as key_id',
                    'ssh_keys.name as key_name'
                )
                .orderBy([
                    'hosts.hostname',
                    'ssh_keys.name'
                ]);

            const grouped = {};

            for (const row of rows) {
                if (!grouped[row.host_id]) {
                    grouped[row.host_id] = {
                        rule_id: row.rule_id,
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

            logVerbose(
                `GET /rules/list - Récupération terminée, ${result.length} hôtes avec règles`
            );

            res.json(result);

        } catch (err) {
            logError(
                '❌ Erreur lors de la récupération des règles :',
                err
            );

            res
                .status(500)
                .send(
                    'Erreur lors de la récupération des règles'
                );
        }
    }
);

router.post(
    '/delete',
    requireAuth,
    rulesWriteLimiter,
    async (req, res) => {
        try {
            let { host_id } = req.body;

            host_id = parseInt(host_id, 10);

            if (!host_id) {
                logVerbose(
                    'POST /rules/delete - host_id invalide ou manquant'
                );

                return res
                    .status(400)
                    .send(
                        'host_id requis et doit être un nombre valide.'
                    );
            }

            logVerbose(
                `POST /rules/delete - Suppression des règles pour host_id=${host_id}`
            );

            const deletedCount = await db('rules')
                .where('host_id', host_id)
                .del();

            logVerbose(
                `POST /rules/delete - Suppression réussie : ${deletedCount} règle(s) supprimée(s)`
            );

            res.send(
                `Suppression réussie : ${deletedCount} règle(s) supprimée(s) pour host_id = ${host_id}.`
            );

        } catch (err) {
            logError(
                '❌ Erreur lors de la suppression des règles :',
                err
            );

            res
                .status(500)
                .send(
                    'Erreur lors de la suppression des règles'
                );
        }
    }
);

router.post(
    '/edit',
    requireAuth,
    rulesWriteLimiter,
    async (req, res) => {
        let { host_id, changes } = req.body;

        host_id = parseInt(host_id, 10);

        const MAX_CHANGES = 100;

        if (
            !host_id ||
            !Array.isArray(changes) ||
            changes.length === 0
        ) {
            logVerbose(
                'POST /rules/edit - host_id ou liste des changements manquants ou invalides'
            );

            return res
                .status(400)
                .send(
                    'host_id et liste des changements sont requis.'
                );
        }

        if (changes.length > MAX_CHANGES) {
            logVerbose(
                `POST /rules/edit - Trop de changements : ${changes.length}`
            );

            return res
                .status(400)
                .send(
                    `Trop de modifications dans une seule requête. Maximum : ${MAX_CHANGES}.`
                );
        }

        changes = changes
            .map(change => ({
                key_id: parseInt(change.key_id, 10),
                action:
                    change.action &&
                    change.action.toLowerCase()
            }))
            .filter(
                change =>
                    !isNaN(change.key_id) &&
                    (
                        change.action === 'add' ||
                        change.action === 'delete'
                    )
            );

        if (changes.length === 0) {
            logVerbose(
                'POST /rules/edit - Liste des changements invalide ou vide après filtrage'
            );

            return res
                .status(400)
                .send(
                    'Liste des changements invalide ou vide.'
                );
        }

        try {
            logVerbose(
                `POST /rules/edit - Début transaction pour host_id=${host_id} avec ${changes.length} changements`
            );

            await db.transaction(async trx => {
                for (const change of changes) {
                    if (change.action === 'add') {
                        try {
                            await trx('rules')
                                .insert({
                                    host_id,
                                    key_id: change.key_id
                                });

                            logVerbose(
                                `Ajout règle: host_id=${host_id}, key_id=${change.key_id}`
                            );

                        } catch (err) {
                            if (!isDuplicateRuleError(err)) {
                                logError(
                                    'Erreur SQL inattendue lors de l\'ajout d\'une règle:',
                                    err
                                );

                                throw err;

                            } else {
                                logVerbose(
                                    `Règle déjà existante ignorée à l'ajout : host_id=${host_id}, key_id=${change.key_id}`
                                );
                            }
                        }
                    }

                    else if (change.action === 'delete') {
                        await trx('rules')
                            .where({
                                host_id,
                                key_id: change.key_id
                            })
                            .del();

                        logVerbose(
                            `Suppression règle: host_id=${host_id}, key_id=${change.key_id}`
                        );
                    }
                }
            });

            logVerbose(
                'POST /rules/edit - Transaction terminée avec succès'
            );

            res.send(
                'Modifications appliquées avec succès.'
            );

        } catch (err) {
            logError(
                '❌ Erreur lors de la modification des règles :',
                err
            );

            res
                .status(500)
                .send(
                    'Erreur lors de la modification des règles'
                );
        }
    }
);

function isDuplicateRuleError(err) {
    return (
        err?.code === 'ER_DUP_ENTRY' ||
        err?.errno === 1062 ||
        err?.code === 'SQLITE_CONSTRAINT' ||
        err?.code === '23505'
    );
}

function validateHostIdAndKeys(host_id, key_ids) {
    const MAX_KEYS = 100;

    host_id = parseInt(host_id, 10);

    if (
        !host_id ||
        !Array.isArray(key_ids) ||
        key_ids.length === 0
    ) {
        const error = new Error(
            'ID de l’hôte ou liste de clés manquante.'
        );

        error.isClientError = true;

        throw error;
    }

    if (key_ids.length > MAX_KEYS) {
        const error = new Error(
            `Trop de clés dans une seule requête. Maximum : ${MAX_KEYS}.`
        );

        error.isClientError = true;

        throw error;
    }

    const parsedKeys = key_ids
        .map(
            key => parseInt(key, 10)
        )
        .filter(
            key => !isNaN(key)
        );

    if (parsedKeys.length === 0) {
        const error = new Error(
            'Liste de clés invalide.'
        );

        error.isClientError = true;

        throw error;
    }

    return {
        host_id,
        key_ids: parsedKeys
    };
}

async function insertRulesTransaction(
    host_id,
    key_ids
) {
    const insertData = key_ids.map(
        key_id => ({
            host_id,
            key_id
        })
    );

    await db.transaction(async trx => {
        for (const entry of insertData) {
            try {
                await trx('rules')
                    .insert(entry);

                logVerbose(
                    `Insertion rule: host_id=${entry.host_id}, key_id=${entry.key_id}`
                );

            } catch (err) {
                if (!isDuplicateRuleError(err)) {
                    throw err;

                } else {
                    logVerbose(
                        `Règle déjà existante ignorée : host_id=${entry.host_id}, key_id=${entry.key_id}`
                    );
                }
            }
        }
    });
}

export default router;