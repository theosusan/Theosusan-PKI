import express from 'express';
import path from 'path';
import db from '../../db/db.js';
import { fileURLToPath } from 'url';
import { requireAuth } from '../server.js';
import { logError, logVerbose } from '../../util/log_helper.js';
import { rateLimit } from 'express-rate-limit';

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


/*
 * Rate limiting pour les opérations de modification
 * des hôtes.
 *
 * Maximum 20 requêtes par IP toutes les 15 minutes.
 */
const hostWriteLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Trop de requêtes. Veuillez réessayer plus tard.'
    }
});


/*
 * Rate limiting pour les opérations de lecture.
 *
 * Permet d'éviter qu'un endpoint ne soit utilisé
 * abusivement tout en conservant une limite suffisamment
 * élevée pour une utilisation normale de l'interface.
 */
const hostReadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Trop de requêtes. Veuillez réessayer plus tard.'
    }
});


/*
 * PAGE PRINCIPALE
 */

router.get(
    '/',
    requireAuth,
    async (req, res) => {

        logVerbose(
            'GET /hosts - Envoi du fichier hosts.html'
        );

        res.sendFile(
            path.join(__dirname, '../public/hosts.html')
        );

    }
);


/*
 * LISTE DES HÔTES
 */

router.get(
    '/list',
    requireAuth,
    hostReadLimiter,
    async (req, res) => {

        try {

            logVerbose(
                'GET /hosts/list - Récupération des hôtes'
            );

            const rows =
                await db('hosts')
                    .select(
                        'id',
                        'hostname',
                        'username',
                        'port'
                    )
                    .orderBy(
                        'hostname',
                        'asc'
                    );

            logVerbose(
                `GET /hosts/list - ${rows.length} hôtes récupérés`
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


/*
 * AJOUT D'UN HÔTE
 */

router.post(
    '/',
    requireAuth,
    hostWriteLimiter,
    async (req, res) => {

        try {

            let {
                hostname,
                username,
                port
            } = req.body;


            /*
             * Validation du hostname.
             */

            if (
                typeof hostname !== 'string' ||
                !hostname.trim()
            ) {

                return res
                    .status(400)
                    .send(
                        'Nom d’hôte requis.'
                    );

            }


            hostname =
                hostname.trim();


            /*
             * Limite de taille du hostname.
             */

            if (
                hostname.length > 253
            ) {

                return res
                    .status(400)
                    .send(
                        'Nom d’hôte trop long.'
                    );

            }


            /*
             * Validation du username.
             */

            if (
                typeof username !== 'string' ||
                !username.trim()
            ) {

                return res
                    .status(400)
                    .send(
                        'Nom d’utilisateur requis.'
                    );

            }


            username =
                username.trim();


            /*
             * Limite de taille du username.
             */

            if (
                username.length > 100
            ) {

                return res
                    .status(400)
                    .send(
                        'Nom d’utilisateur trop long.'
                    );

            }


            /*
             * Validation du port.
             */

            port =
                parseInt(
                    port,
                    10
                );


            if (
                !Number.isInteger(port) ||
                port < 1 ||
                port > 65535
            ) {

                return res
                    .status(400)
                    .send(
                        'Port invalide. Le port doit être compris entre 1 et 65535.'
                    );

            }


            /*
             * Vérification de l'existence de l'hôte.
             */

            const existingHost =
                await db('hosts')
                    .where(
                        'hostname',
                        hostname
                    )
                    .first();


            if (existingHost) {

                logVerbose(
                    `POST /hosts - Hôte déjà existant : ${hostname}`
                );

                return res
                    .status(409)
                    .send(
                        'Cet hôte existe déjà.'
                    );

            }


            /*
             * Insertion.
             */

            const [id] =
                await db('hosts')
                    .insert({
                        hostname,
                        username,
                        port
                    });


            logVerbose(
                `POST /hosts - Hôte créé : id=${id}, hostname=${hostname}`
            );


            res
                .status(201)
                .json({
                    success: true,
                    id,
                    hostname,
                    username,
                    port
                });

        } catch (err) {

            logError(
                '❌ Erreur lors de la création de l’hôte :',
                err
            );

            res
                .status(500)
                .send(
                    'Erreur lors de la création de l’hôte'
                );

        }

    }
);


/*
 * MODIFICATION D'UN HÔTE
 */

router.put(
    '/:id',
    requireAuth,
    hostWriteLimiter,
    async (req, res) => {

        try {

            const id =
                parseInt(
                    req.params.id,
                    10
                );


            if (
                !Number.isInteger(id) ||
                id <= 0
            ) {

                return res
                    .status(400)
                    .send(
                        'ID d’hôte invalide.'
                    );

            }


            let {
                hostname,
                username,
                port
            } = req.body;


            /*
             * Validation du hostname.
             */

            if (
                typeof hostname !== 'string' ||
                !hostname.trim()
            ) {

                return res
                    .status(400)
                    .send(
                        'Nom d’hôte requis.'
                    );

            }


            hostname =
                hostname.trim();


            if (
                hostname.length > 253
            ) {

                return res
                    .status(400)
                    .send(
                        'Nom d’hôte trop long.'
                    );

            }


            /*
             * Validation du username.
             */

            if (
                typeof username !== 'string' ||
                !username.trim()
            ) {

                return res
                    .status(400)
                    .send(
                        'Nom d’utilisateur requis.'
                    );

            }


            username =
                username.trim();


            if (
                username.length > 100
            ) {

                return res
                    .status(400)
                    .send(
                        'Nom d’utilisateur trop long.'
                    );

            }


            /*
             * Validation du port.
             */

            port =
                parseInt(
                    port,
                    10
                );


            if (
                !Number.isInteger(port) ||
                port < 1 ||
                port > 65535
            ) {

                return res
                    .status(400)
                    .send(
                        'Port invalide. Le port doit être compris entre 1 et 65535.'
                    );

            }


            /*
             * Vérification de l'existence de l'hôte.
             */

            const existingHost =
                await db('hosts')
                    .where(
                        'id',
                        id
                    )
                    .first();


            if (!existingHost) {

                return res
                    .status(404)
                    .send(
                        'Hôte introuvable.'
                    );

            }


            /*
             * Vérification des doublons.
             */

            const duplicateHost =
                await db('hosts')
                    .where(
                        'hostname',
                        hostname
                    )
                    .whereNot(
                        'id',
                        id
                    )
                    .first();


            if (duplicateHost) {

                return res
                    .status(409)
                    .send(
                        'Un autre hôte utilise déjà ce nom.'
                    );

            }


            /*
             * Mise à jour.
             */

            await db('hosts')
                .where(
                    'id',
                    id
                )
                .update({
                    hostname,
                    username,
                    port
                });


            logVerbose(
                `PUT /hosts/${id} - Hôte modifié avec succès`
            );


            res.json({
                success: true,
                id,
                hostname,
                username,
                port
            });

        } catch (err) {

            logError(
                '❌ Erreur lors de la modification de l’hôte :',
                err
            );

            res
                .status(500)
                .send(
                    'Erreur lors de la modification de l’hôte'
                );

        }

    }
);


/*
 * SUPPRESSION D'UN HÔTE
 */

router.delete(
    '/:id',
    requireAuth,
    hostWriteLimiter,
    async (req, res) => {

        try {

            const id =
                parseInt(
                    req.params.id,
                    10
                );


            if (
                !Number.isInteger(id) ||
                id <= 0
            ) {

                return res
                    .status(400)
                    .send(
                        'ID d’hôte invalide.'
                    );

            }


            /*
             * Vérification de l'existence.
             */

            const host =
                await db('hosts')
                    .where(
                        'id',
                        id
                    )
                    .first();


            if (!host) {

                return res
                    .status(404)
                    .send(
                        'Hôte introuvable.'
                    );

            }


            /*
             * Suppression des règles associées.
             */

            await db('rules')
                .where(
                    'host_id',
                    id
                )
                .del();


            /*
             * Suppression de l'hôte.
             */

            const deleted =
                await db('hosts')
                    .where(
                        'id',
                        id
                    )
                    .del();


            if (!deleted) {

                return res
                    .status(404)
                    .send(
                        'Hôte introuvable.'
                    );

            }


            logVerbose(
                `DELETE /hosts/${id} - Hôte supprimé avec succès`
            );


            res.json({
                success: true,
                message:
                    'Hôte supprimé avec succès.'
            });

        } catch (err) {

            logError(
                '❌ Erreur lors de la suppression de l’hôte :',
                err
            );

            res
                .status(500)
                .send(
                    'Erreur lors de la suppression de l’hôte'
                );

        }

    }
);


export default router;