import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { rateLimit } from 'express-rate-limit';

import db from '../../db/db.js';
import { requireAuth } from '../server.js';
import { addHost, deleteHostById } from '../../cli/manage_hosts.js';
import {
    connectSSH,
    installSSHFile,
    remoteSshPath
} from '../../cli/ssh_commands.js';
import {
    decrypt,
    generateSalt
} from '../../util/crypto_util.js';
import {
    logError,
    logVerbose
} from '../../util/log_helper.js';
import { getBastionPublicKey } from './keys.js';

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


/*
 * Rate limiting pour les opérations de modification
 * des hôtes.
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
 * Rate limiting spécifique à la synchronisation SSH.
 *
 * Une synchronisation déclenche potentiellement :
 * - une connexion SSH ;
 * - un transfert de fichier ;
 * - l'exécution d'un script distant.
 *
 * On applique donc une limite plus stricte.
 */
const hostSyncLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error:
            'Trop de synchronisations. Veuillez réessayer plus tard.'
    }
});


/*
 * PAGE PRINCIPALE
 */
router.get(
    '/',
    requireAuth,
    hostReadLimiter,
    async (req, res) => {
        logVerbose(
            'GET /hosts - Envoi du fichier hosts.html'
        );

        res.sendFile(
            path.join(
                __dirname,
                '../public/hosts.html'
            )
        );
    }
);


/*
 * LISTE DES HÔTES
 *
 * IMPORTANT :
 * La table utilise :
 *
 * id
 * user
 * hostname
 * address
 * port
 * lastsync
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
                        'user',
                        'address',
                        'port',
                        'lastsync'
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
                user,
                address,
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
             * Validation de l'utilisateur SSH.
             */
            if (
                typeof user !== 'string' ||
                !user.trim()
            ) {
                return res
                    .status(400)
                    .send(
                        'Nom d’utilisateur requis.'
                    );
            }

            user = user.trim();

            if (
                user.length > 100
            ) {
                return res
                    .status(400)
                    .send(
                        'Nom d’utilisateur trop long.'
                    );
            }


            /*
             * Validation de l'adresse.
             */
            if (
                typeof address !== 'string' ||
                !address.trim()
            ) {
                return res
                    .status(400)
                    .send(
                        'Adresse de l’hôte requise.'
                    );
            }

            address = address.trim();

            if (
                address.length > 255
            ) {
                return res
                    .status(400)
                    .send(
                        'Adresse de l’hôte trop longue.'
                    );
            }


            /*
             * Port par défaut : 22.
             */
            if (
                port === undefined ||
                port === null ||
                port === ''
            ) {
                port = 22;
            }

            port =
                Number(port);

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
             * Vérification des doublons.
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
             * Utilisation de la fonction commune
             * manage_hosts.js.
             */
            const result =
                await addHost({
                    hostname,
                    user,
                    address,
                    port,
                    checkExists: true
                });


            if (!result.success) {
                return res
                    .status(409)
                    .send(
                        result.message
                    );
            }


            logVerbose(
                `POST /hosts - Hôte créé : ${hostname} (${user}@${address}:${port})`
            );

            res
                .status(201)
                .send(
                    result.message
                );

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
 * SYNCHRONISATION SSH
 *
 * Cette route avait disparu de la nouvelle version
 * de hosts.js.
 *
 * Le hosts.html actuel envoie uniquement :
 *
 * {
 *     id: <id de l'hôte>
 * }
 *
 * On récupère donc toutes les informations directement
 * depuis la base de données.
 */
router.post(
    '/connect',
    requireAuth,
    hostSyncLimiter,
    async (req, res) => {
        let temporaryFilePath = null;

        try {
            const id =
                Number(req.body.id);

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
             * Récupération de l'hôte depuis la base.
             */
            const hostInfo =
                await db('hosts')
                    .where(
                        'id',
                        id
                    )
                    .first();

            if (!hostInfo) {
                return res
                    .status(404)
                    .send(
                        'Hôte introuvable.'
                    );
            }


            const {
                hostname,
                user,
                address,
                port
            } = hostInfo;

            const sshPort =
                port || 22;


            logVerbose(
                `🔄 Début synchronisation de ${hostname} (${user}@${address}:${sshPort})`
            );


            /*
             * Récupération de la clé privée bastion.
             */
            const privateKey =
                await getPrivateKey();


            /*
             * Connexion SSH.
             */
            const conn =
                await connectSSH({
                    host: address,
                    port: sshPort,
                    username: user,
                    privateKey
                });

            logVerbose(
                `🔐 Connexion SSH établie à ${user}@${address}:${sshPort}`
            );


            /*
             * Vérification de la présence du script
             * update_keys.sh.
             */
            let scriptExists;

            try {
                scriptExists =
                    await checkRemoteScriptPresence(
                        conn,
                        user
                    );
            } finally {
                conn.end();
            }


            /*
             * Installation du script s'il est absent.
             */
            if (!scriptExists) {
                logVerbose(
                    `📦 Script update_keys.sh absent sur ${address}, installation...`
                );

                const localScriptPath =
                    path.resolve(
                        'src',
                        'scripts',
                        'update_keys.sh'
                    );

                if (
                    !fs.existsSync(
                        localScriptPath
                    )
                ) {
                    throw new Error(
                        `Script local introuvable : ${localScriptPath}`
                    );
                }

                await installSSHFile({
                    host: address,
                    port: sshPort,
                    username: user,
                    privateKey,
                    localFilePath:
                        localScriptPath,
                    remoteFilePath:
                        'update_keys.sh',
                    chmodMode: '700'
                });

                logVerbose(
                    `✅ Script installé avec succès sur ${address}`
                );
            } else {
                logVerbose(
                    `✅ Script déjà présent sur ${address}`
                );
            }


            /*
             * Récupération des clés publiques associées
             * à cet hôte.
             */
            const publicKeys =
                await getPublicKeysByHostId(
                    id
                );


            /*
             * Récupération de la clé publique du bastion.
             */
            const bastionPublicKey =
                (
                    await getBastionPublicKey()
                ).publicKey;


            if (
                typeof bastionPublicKey !== 'string' ||
                !bastionPublicKey.trim()
            ) {
                throw new Error(
                    'Clé publique bastion invalide ou vide.'
                );
            }


            /*
             * Construction du fichier authorized_keys.
             */
            const allKeys = [
                bastionPublicKey.trim(),
                ...publicKeys
                    .filter(
                        key =>
                            typeof key === 'string'
                    )
                    .map(
                        key =>
                            key.trim()
                    )
                    .filter(
                        key =>
                            key.length > 0
                    )
            ].join('\n') + '\n';


            /*
             * Création d'un fichier temporaire.
             */
            const randomSalt =
                generateSalt();

            const tmpFilename =
                `authorized_keys.theosusan-pki.${randomSalt}`;

            temporaryFilePath =
                path.join(
                    '/tmp',
                    tmpFilename
                );

            fs.writeFileSync(
                temporaryFilePath,
                allKeys,
                {
                    encoding: 'utf8',
                    mode: 0o600
                }
            );


            /*
             * Transfert du fichier authorized_keys.
             */
            await installSSHFile({
                host: address,
                port: sshPort,
                username: user,
                privateKey,
                localFilePath:
                    temporaryFilePath,
                remoteFilePath:
                    'authorized_keys.theosusan-pki',
                chmodMode: '600'
            });

            logVerbose(
                `📁 Fichier authorized_keys transféré sur ${address}`
            );


            /*
             * Exécution du script distant.
             */
            const {
                code,
                output
            } =
                await runRemoteUpdateScript({
                    host: address,
                    port: sshPort,
                    username: user,
                    privateKey
                });


            if (code !== 0) {
                logError(
                    `❌ Script update échoué (code ${code}) sur ${address} :\n${output}`
                );

                return res
                    .status(500)
                    .send(
                        `Update terminé avec erreur (code ${code})\n\n${output}`
                    );
            }


            logVerbose(
                `✅ Script update exécuté avec succès sur ${address}`
            );


            /*
             * Mise à jour de la date de dernière synchronisation.
             */
            await db('hosts')
                .where(
                    'id',
                    id
                )
                .update({
                    lastsync:
                        db.fn.now()
                });


            logVerbose(
                `⏱️ lastsync mis à jour pour l’hôte id=${id}`
            );


            res.send(
                `✅ Synchronisation réussie pour ${hostname}\n\n${output}`
            );

        } catch (err) {
            logError(
                '❌ Erreur dans POST /hosts/connect :',
                err
            );

            res
                .status(500)
                .send(
                    'Erreur de connexion ou de synchronisation SSH.'
                );

        } finally {

            /*
             * Suppression du fichier temporaire local.
             */
            if (
                temporaryFilePath
            ) {
                try {
                    if (
                        fs.existsSync(
                            temporaryFilePath
                        )
                    ) {
                        fs.unlinkSync(
                            temporaryFilePath
                        );

                        logVerbose(
                            `🧹 Fichier temporaire supprimé : ${temporaryFilePath}`
                        );
                    }
                } catch (cleanupError) {
                    logError(
                        '⚠️ Impossible de supprimer le fichier temporaire :',
                        cleanupError
                    );
                }
            }
        }
    }
);


/*
 * MODIFICATION D'UN HÔTE
 *
 * Cette route est conservée pour les clients qui
 * utilisent PUT /hosts/:id.
 */
router.put(
    '/:id',
    requireAuth,
    hostWriteLimiter,
    async (req, res) => {
        try {
            const id =
                Number(req.params.id);

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
                user,
                address,
                port
            } = req.body;


            /*
             * Validation hostname.
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
             * Validation user.
             */
            if (
                typeof user !== 'string' ||
                !user.trim()
            ) {
                return res
                    .status(400)
                    .send(
                        'Nom d’utilisateur requis.'
                    );
            }

            user =
                user.trim();

            if (
                user.length > 100
            ) {
                return res
                    .status(400)
                    .send(
                        'Nom d’utilisateur trop long.'
                    );
            }


            /*
             * Validation address.
             */
            if (
                typeof address !== 'string' ||
                !address.trim()
            ) {
                return res
                    .status(400)
                    .send(
                        'Adresse de l’hôte requise.'
                    );
            }

            address =
                address.trim();

            if (
                address.length > 255
            ) {
                return res
                    .status(400)
                    .send(
                        'Adresse de l’hôte trop longue.'
                    );
            }


            /*
             * Port par défaut.
             */
            if (
                port === undefined ||
                port === null ||
                port === ''
            ) {
                port = 22;
            }

            port =
                Number(port);

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
             * Vérification de l'existence.
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
                    user,
                    address,
                    port
                });


            logVerbose(
                `PUT /hosts/${id} - Hôte modifié avec succès`
            );


            res.json({
                success: true,
                id,
                hostname,
                user,
                address,
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
 *
 * On conserve la désinstallation distante du script
 * avant la suppression en base lorsque cela est possible.
 */
router.delete(
    '/:id',
    requireAuth,
    hostWriteLimiter,
    async (req, res) => {
        try {
            const id =
                Number(req.params.id);

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


            const hostInfo =
                await db('hosts')
                    .where(
                        'id',
                        id
                    )
                    .first();

            if (!hostInfo) {
                return res
                    .status(404)
                    .send(
                        'Hôte introuvable.'
                    );
            }


            const {
                user,
                address,
                port
            } = hostInfo;


            /*
             * Tentative de désinstallation distante.
             *
             * Une panne SSH ne bloque pas la suppression
             * de l'hôte dans l'application.
             */
            try {
                const privateKey =
                    await getPrivateKey();

                const conn =
                    await connectSSH({
                        host: address,
                        port: port || 22,
                        username: user,
                        privateKey
                    });

                logVerbose(
                    `🔐 Connexion SSH établie pour suppression de ${user}@${address}:${port || 22}`
                );


                const scriptExists =
                    await checkUninstallScript(
                        conn,
                        user
                    );


                if (scriptExists) {
                    logVerbose(
                        '📄 Script update_keys.sh trouvé, tentative de désinstallation'
                    );

                    const uninstallSuccess =
                        await runUninstallScript(
                            conn,
                            user
                        );

                    if (uninstallSuccess) {
                        logVerbose(
                            '✅ Désinstallation distante réussie'
                        );
                    } else {
                        logError(
                            '❌ La désinstallation distante a échoué'
                        );
                    }
                } else {
                    logVerbose(
                        'ℹ️ Script update_keys.sh absent, rien à désinstaller'
                    );
                }


                conn.end();

            } catch (sshError) {
                logError(
                    `⚠️ Connexion SSH échouée vers ${address}:${port || 22}, suppression locale poursuivie :`,
                    sshError
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
                    `Hôte "${hostInfo.hostname}" supprimé avec succès.`
            });

        } catch (err) {
            logError(
                '❌ Erreur lors de la suppression de l’hôte :',
                err
            );

            res
                .status(500)
                .send(
                    'Erreur serveur lors de la suppression.'
                );
        }
    }
);


/*
 * Récupération de la clé privée du bastion.
 */
async function getPrivateKey(
    name = 'bastion'
) {
    const keyRow =
        await db('ssh_keys')
            .where({
                name
            })
            .first();

    if (!keyRow) {
        throw new Error(
            'Clé privée bastion introuvable en base'
        );
    }

    return decrypt(
        keyRow.privateKey
    );
}


/*
 * Vérifie si update_keys.sh existe sur l'hôte distant.
 */
function checkRemoteScriptPresence(
    conn,
    username
) {
    const remotePath =
        remoteSshPath(
            username,
            'update_keys.sh'
        );

    const checkCommand =
        `[ -f ${shellQuote(remotePath)} ] && echo "EXISTS" || echo "MISSING"`;


    return new Promise(
        (resolve, reject) => {

            conn.exec(
                checkCommand,
                (err, stream) => {

                    if (err) {
                        return reject(err);
                    }

                    let output = '';

                    stream.on(
                        'data',
                        data => {
                            output +=
                                data.toString();
                        }
                    );

                    stream.stderr.on(
                        'data',
                        data => {
                            logError(
                                `❌ STDERR check script : ${data.toString().trim()}`
                            );
                        }
                    );

                    stream.on(
                        'close',
                        () => {
                            resolve(
                                output.trim() ===
                                'EXISTS'
                            );
                        }
                    );
                }
            );
        }
    );
}


/*
 * Récupération des clés publiques associées à un hôte.
 *
 * Les associations sont stockées dans :
 *
 * rules.host_id
 * rules.key_id
 *
 * et les clés publiques dans :
 *
 * ssh_keys.publicKey
 */
async function getPublicKeysByHostId(
    hostId
) {
    const rows =
        await db('rules')
            .join(
                'ssh_keys',
                'rules.key_id',
                'ssh_keys.id'
            )
            .where(
                'rules.host_id',
                hostId
            )
            .select(
                'ssh_keys.publicKey'
            );

    return rows
        .map(
            row => row.publicKey
        )
        .filter(
            key =>
                typeof key === 'string' &&
                key.trim().length > 0
        );
}


/*
 * Exécution du script update_keys.sh distant.
 */
async function runRemoteUpdateScript({
    host,
    port,
    username,
    privateKey
}) {
    const remotePath =
        remoteSshPath(
            username,
            'update_keys.sh'
        );

    const command =
        `${shellQuote(remotePath)} update ${shellQuote(username)}`;


    const conn =
        await connectSSH({
            host,
            port,
            username,
            privateKey
        });


    return new Promise(
        (resolve, reject) => {

            conn.exec(
                command,
                (err, stream) => {

                    if (err) {
                        conn.end();

                        return reject(
                            new Error(
                                `Erreur d’exécution du script update : ${err.message}`
                            )
                        );
                    }


                    let stdout = '';
                    let stderr = '';


                    stream.on(
                        'data',
                        data => {
                            stdout +=
                                data.toString();
                        }
                    );


                    stream.stderr.on(
                        'data',
                        data => {
                            const text =
                                data.toString();

                            stderr += text;

                            logError(
                                `❌ STDERR update : ${text.trim()}`
                            );
                        }
                    );


                    stream.on(
                        'close',
                        code => {
                            conn.end();

                            resolve({
                                code,
                                output:
                                    `${stdout}${stderr}`.trim()
                            });
                        }
                    );
                }
            );
        }
    );
}


/*
 * Vérifie si update_keys.sh existe avant suppression.
 */
function checkUninstallScript(
    conn,
    username
) {
    const remotePath =
        remoteSshPath(
            username,
            'update_keys.sh'
        );

    const checkCommand =
        `[ -f ${shellQuote(remotePath)} ] && echo "EXISTS" || echo "MISSING"`;


    return new Promise(
        (resolve, reject) => {

            conn.exec(
                checkCommand,
                (err, stream) => {

                    if (err) {
                        return reject(err);
                    }

                    let output = '';

                    stream.on(
                        'data',
                        data => {
                            output +=
                                data.toString();
                        }
                    );

                    stream.stderr.on(
                        'data',
                        data => {
                            logError(
                                `❌ STDERR check uninstall : ${data.toString().trim()}`
                            );
                        }
                    );

                    stream.on(
                        'close',
                        () => {
                            resolve(
                                output.trim() ===
                                'EXISTS'
                            );
                        }
                    );
                }
            );
        }
    );
}


/*
 * Exécution du script de désinstallation.
 */
function runUninstallScript(
    conn,
    username
) {
    const remotePath =
        remoteSshPath(
            username,
            'update_keys.sh'
        );

    const uninstallCommand =
        `${shellQuote(remotePath)} uninstall ${shellQuote(username)}`;


    return new Promise(
        resolve => {

            conn.exec(
                uninstallCommand,
                (err, stream) => {

                    if (err) {
                        logError(
                            `❌ Erreur uninstall sur ${username} :`,
                            err
                        );

                        return resolve(false);
                    }


                    stream.stderr.on(
                        'data',
                        data => {
                            logError(
                                `❌ STDERR uninstall : ${data.toString().trim()}`
                            );
                        }
                    );


                    stream.on(
                        'close',
                        code => {
                            resolve(
                                code === 0
                            );
                        }
                    );
                }
            );
        }
    );
}


/*
 * Échappement d'une valeur destinée au shell.
 *
 * Les commandes SSH utilisent des paramètres issus de la
 * base de données. On ne doit pas les concaténer directement
 * dans une commande shell.
 */
function shellQuote(
    value
) {
    return `'${String(value).replace(
        /'/g,
        `'\\''`
    )}'`;
}


export default router;