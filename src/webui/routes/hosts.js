import express from 'express';
import db from '../../db/db.js';
import { requireAuth } from '../server.js';
import {
    logError,
    logVerbose
} from '../../util/log_helper.js';
import { rateLimit } from 'express-rate-limit';

const router = express.Router();

// ============================================================
// RATE LIMITING
// ============================================================

// Lecture de la liste des hôtes.
const hostsReadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error:
            'Trop de requêtes. Veuillez réessayer plus tard.'
    }
});

// Création / modification / suppression d'un hôte.
const hostsWriteLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error:
            'Trop de requêtes. Veuillez réessayer plus tard.'
    }
});

// ============================================================
// VALIDATION
// ============================================================

function isValidId(id) {
    return /^\d+$/.test(String(id));
}

function isValidString(value, maxLength = 255) {
    return (
        typeof value === 'string' &&
        value.trim().length > 0 &&
        value.trim().length <= maxLength
    );
}

function isValidPort(port) {
    const numericPort = Number(port);

    return (
        Number.isInteger(numericPort) &&
        numericPort >= 1 &&
        numericPort <= 65535
    );
}

// ============================================================
// PAGE PRINCIPALE
// ============================================================

router.get(
    '/',
    requireAuth,
    hostsReadLimiter,
    async (req, res) => {
        try {
            res.sendFile(
                new URL(
                    '../public/hosts.html',
                    import.meta.url
                ).pathname
            );
        } catch (err) {
            logError(
                '❌ Erreur lors du chargement de la page des hôtes :',
                err
            );

            res
                .status(500)
                .send('Erreur serveur');
        }
    }
);

// ============================================================
// LISTE DES HÔTES
// ============================================================

router.get(
    '/list',
    requireAuth,
    hostsReadLimiter,
    async (req, res) => {
        try {
            const rows = await db('hosts')
                .select(
                    'id',
                    'user',
                    'hostname',
                    'address',
                    'port',
                    'lastsync'
                )
                .orderBy(
                    'hostname',
                    'asc'
                );

            logVerbose(
                `Liste des hôtes récupérée, ${rows.length} hôtes trouvés`
            );

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

// ============================================================
// RÉCUPÉRATION D'UN HÔTE
// ============================================================

router.get(
    '/:id',
    requireAuth,
    hostsReadLimiter,
    async (req, res) => {
        const { id } = req.params;

        if (!isValidId(id)) {
            return res
                .status(400)
                .json({
                    error: 'Identifiant d’hôte invalide'
                });
        }

        try {
            const row = await db('hosts')
                .select(
                    'id',
                    'user',
                    'hostname',
                    'address',
                    'port',
                    'lastsync'
                )
                .where('id', id)
                .first();

            if (!row) {
                return res
                    .status(404)
                    .json({
                        error: 'Hôte introuvable'
                    });
            }

            res.json(row);
        } catch (err) {
            logError(
                `❌ Erreur lors de la récupération de l’hôte id=${id} :`,
                err
            );

            res
                .status(500)
                .json({
                    error: 'Erreur serveur'
                });
        }
    }
);

// ============================================================
// AJOUT D'UN HÔTE
// ============================================================

router.post(
    '/',
    requireAuth,
    hostsWriteLimiter,
    async (req, res) => {
        const {
            user,
            hostname,
            address,
            port
        } = req.body;

        if (
            !isValidString(user) ||
            !isValidString(hostname) ||
            !isValidString(address)
        ) {
            return res
                .status(400)
                .json({
                    error:
                        'Utilisateur, nom d’hôte et adresse sont requis'
                });
        }

        if (!isValidPort(port)) {
            return res
                .status(400)
                .json({
                    error:
                        'Le port doit être compris entre 1 et 65535'
                });
        }

        try {
            const existingHost = await db('hosts')
                .where({
                    hostname: hostname.trim()
                })
                .first();

            if (existingHost) {
                return res
                    .status(409)
                    .json({
                        error:
                            'Un hôte avec ce nom existe déjà'
                    });
            }

            const [id] = await db('hosts')
                .insert({
                    user: user.trim(),
                    hostname: hostname.trim(),
                    address: address.trim(),
                    port: Number(port)
                });

            logVerbose(
                `✅ Hôte "${hostname.trim()}" ajouté avec succès`
            );

            res
                .status(201)
                .json({
                    message:
                        'Hôte ajouté avec succès',
                    id
                });
        } catch (err) {
            logError(
                '❌ Erreur lors de l’ajout de l’hôte :',
                err
            );

            res
                .status(500)
                .json({
                    error:
                        'Erreur lors de l’ajout de l’hôte'
                });
        }
    }
);

// ============================================================
// MODIFICATION D'UN HÔTE
// ============================================================

router.put(
    '/:id',
    requireAuth,
    hostsWriteLimiter,
    async (req, res) => {
        const { id } = req.params;

        if (!isValidId(id)) {
            return res
                .status(400)
                .json({
                    error: 'Identifiant d’hôte invalide'
                });
        }

        const {
            user,
            hostname,
            address,
            port
        } = req.body;

        if (
            !isValidString(user) ||
            !isValidString(hostname) ||
            !isValidString(address)
        ) {
            return res
                .status(400)
                .json({
                    error:
                        'Utilisateur, nom d’hôte et adresse sont requis'
                });
        }

        if (!isValidPort(port)) {
            return res
                .status(400)
                .json({
                    error:
                        'Le port doit être compris entre 1 et 65535'
                });
        }

        try {
            const existingHost = await db('hosts')
                .where('id', id)
                .first();

            if (!existingHost) {
                return res
                    .status(404)
                    .json({
                        error: 'Hôte introuvable'
                    });
            }

            const duplicateHost = await db('hosts')
                .where('hostname', hostname.trim())
                .whereNot('id', id)
                .first();

            if (duplicateHost) {
                return res
                    .status(409)
                    .json({
                        error:
                            'Un autre hôte avec ce nom existe déjà'
                    });
            }

            await db('hosts')
                .where('id', id)
                .update({
                    user: user.trim(),
                    hostname: hostname.trim(),
                    address: address.trim(),
                    port: Number(port)
                });

            logVerbose(
                `✅ Hôte id=${id} modifié avec succès`
            );

            res.json({
                message:
                    'Hôte modifié avec succès'
            });
        } catch (err) {
            logError(
                `❌ Erreur lors de la modification de l’hôte id=${id} :`,
                err
            );

            res
                .status(500)
                .json({
                    error:
                        'Erreur lors de la modification de l’hôte'
                });
        }
    }
);

// ============================================================
// SUPPRESSION D'UN HÔTE
// ============================================================

router.delete(
    '/:id',
    requireAuth,
    hostsWriteLimiter,
    async (req, res) => {
        const { id } = req.params;

        if (!isValidId(id)) {
            return res
                .status(400)
                .json({
                    error: 'Identifiant d’hôte invalide'
                });
        }

        try {
            const existingHost = await db('hosts')
                .where('id', id)
                .first();

            if (!existingHost) {
                return res
                    .status(404)
                    .json({
                        error: 'Hôte introuvable'
                    });
            }

            await db('hosts')
                .where('id', id)
                .delete();

            logVerbose(
                `✅ Hôte id=${id} supprimé avec succès`
            );

            res.json({
                message:
                    'Hôte supprimé avec succès'
            });
        } catch (err) {
            logError(
                `❌ Erreur lors de la suppression de l’hôte id=${id} :`,
                err
            );

            res
                .status(500)
                .json({
                    error:
                        'Erreur lors de la suppression de l’hôte'
                });
        }
    }
);

export default router;