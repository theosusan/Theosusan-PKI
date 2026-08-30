import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import db from '../../db/db.js';
import { comparePassword } from '../../util/crypto_util.js';

import { logVerbose, logError } from '../../util/log_helper.js';

import { Issuer, generators } from 'openid-client';

import dotenv from 'dotenv';

import ejs from 'ejs';

import { rateLimit } from 'express-rate-limit';

dotenv.config();

const router = express.Router();

// Pour gérer correctement les chemins avec ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// ============================================================
// RATE LIMITING
// ============================================================
//
// Protection contre les attaques par force brute sur le login.
//
// 5 tentatives maximum par IP sur une fenêtre de 15 minutes.
//
// Cette limitation est volontairement stricte car cette route
// effectue une vérification de mot de passe.
//

const loginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: true,
    legacyHeaders: false,

    message: {
        error: 'Trop de tentatives de connexion. Veuillez réessayer dans quelques minutes.'
    }
});


// ============================================================
// RATE LIMITING OIDC
// ============================================================
//
// Protection de la route qui initie une authentification OIDC.
//
// Une limite plus élevée est utilisée ici car cette route peut
// être appelée normalement plusieurs fois par un utilisateur.
//

const oidcLoginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: true,
    legacyHeaders: false,

    message: {
        error: 'Trop de demandes d’authentification. Veuillez réessayer plus tard.'
    }
});


// ============================================================
// CONFIGURATION OIDC
// ============================================================

const OIDC_ISSUER_URL =
    process.env.OIDC_ISSUER_URL;

const OIDC_CLIENT_ID =
    process.env.OIDC_CLIENT_ID;

const OIDC_CLIENT_SECRET =
    process.env.OIDC_CLIENT_SECRET;

const OIDC_REDIRECT_URI =
    process.env.OIDC_REDIRECT_URI ||
    'https://theosusan-pki.theosusan.fr/oidc/callback';

let oidcClientPromise;

const BASE_LOGIN_METHOD =
    process.env.BASE_LOGIN_METHOD === 'true';


function getOidcClient() {

    if (!oidcClientPromise) {

        oidcClientPromise =
            Issuer
                .discover(OIDC_ISSUER_URL)
                .then((issuer) => {

                    return new issuer.Client({

                        client_id:
                            OIDC_CLIENT_ID,

                        client_secret:
                            OIDC_CLIENT_SECRET,

                        redirect_uris:
                            [OIDC_REDIRECT_URI],

                        response_types:
                            ['code']

                    });

                });

    }

    return oidcClientPromise;
}


// ============================================================
// PAGE LOGIN
// ============================================================

router.get('/', (req, res) => {

    ejs.renderFile(
        path.join(
            __dirname,
            '../public/login.ejs'
        ),
        {
            loginEnabled:
                BASE_LOGIN_METHOD
        },
        (err, str) => {

            if (err) {

                logError(
                    'Erreur template login:',
                    err
                );

                res
                    .status(500)
                    .send(
                        'Erreur serveur'
                    );

                return;
            }

            res.send(str);

        }
    );

});


// ============================================================
// RÉCUPÉRATION DE L'IP UTILISATEUR
// ============================================================

function getUserIp(req) {

    let userIp =
        req.headers['x-forwarded-for'] ||
        req.socket.remoteAddress ||
        '';

    if (
        userIp.startsWith('::ffff:')
    ) {

        userIp =
            userIp.substring(7);

    }

    return userIp;

}


// ============================================================
// LOGIN CLASSIQUE
// ============================================================

if (BASE_LOGIN_METHOD) {

    router.post(
        '/login',
        loginRateLimiter,
        async (req, res) => {

            const {
                username,
                password
            } = req.body;


            if (
                !username ||
                !password
            ) {

                logError(
                    'Nom d’utilisateur et mot de passe requis'
                );

                return res
                    .status(400)
                    .json({
                        error:
                            'Nom d’utilisateur et mot de passe requis'
                    });

            }


            try {

                const rows =
                    await db('users')
                        .select('password')
                        .where({
                            username
                        });


                if (
                    rows.length === 0
                ) {

                    logError(
                        'Utilisateur non trouvé'
                    );

                    return res
                        .status(401)
                        .json({
                            error:
                                'Utilisateur non trouvé'
                        });

                }


                const hashedPwd =
                    rows[0].password;


                const isMatch =
                    await comparePassword(
                        password,
                        hashedPwd
                    );


                const userIp =
                    getUserIp(req);


                if (isMatch) {

                    req.session.user =
                        username;


                    logVerbose(
                        `✅ Utilisateur "${username}" connecté depuis l'IP : ${userIp}`
                    );


                    await db('users')
                        .where({
                            username
                        })
                        .update({
                            lastLogin:
                                db.fn.now()
                        });


                    logVerbose(
                        `✅ Utilisateur "${username}" connecté depuis l'IP : ${userIp}`
                    );


                    return res
                        .status(200)
                        .json({
                            message:
                                'Connexion réussie'
                        });

                } else {

                    logError(
                        `❌ Utilisateur "${username}" tentative de connexion KO depuis l'IP : ${userIp}, Mot de passe incorrect`
                    );


                    return res
                        .status(401)
                        .json({
                            error:
                                'Mot de passe incorrect'
                        });

                }

            } catch (err) {

                logError(
                    'Erreur login:',
                    err
                );


                return res
                    .status(500)
                    .json({
                        error:
                            'Erreur serveur'
                    });

            }

        }
    );

} else {

    // Si désactivé, bloquer la route login

    router.post(
        '/login',
        loginRateLimiter,
        (req, res) => {

            logVerbose(
                'Authentification utilisateur/mot de passe désactivée'
            );

            res
                .status(403)
                .json({
                    error:
                        'Authentification utilisateur/mot de passe désactivée'
                });

        }
    );

}


// ============================================================
// INITIATION AUTHENTIFICATION OIDC
// ============================================================

router.get(
    '/oidc/login',
    oidcLoginRateLimiter,
    async (req, res) => {

        try {

            const oidcClient =
                await getOidcClient();


            const codeVerifier =
                generators.codeVerifier();


            const codeChallenge =
                generators.codeChallenge(
                    codeVerifier
                );


            const state =
                generators.state();


            req.session.codeVerifier =
                codeVerifier;


            req.session.oidcState =
                state;


            const url =
                oidcClient.authorizationUrl({

                    scope:
                        'openid profile email',

                    code_challenge:
                        codeChallenge,

                    code_challenge_method:
                        'S256',

                    state

                });


            res.redirect(url);

        } catch (err) {

            logError(
                'OIDC login error:',
                err
            );

            res
                .status(500)
                .send(
                    'Erreur OIDC'
                );

        }

    }
);


// ============================================================
// CALLBACK OIDC
// ============================================================

router.get(
    '/oidc/callback',
    async (req, res) => {

        try {

            const oidcClient =
                await getOidcClient();


            const params =
                oidcClient.callbackParams(
                    req
                );


            const codeVerifier =
                req.session.codeVerifier;


            const state =
                req.session.oidcState;


            const tokenSet =
                await oidcClient.callback(
                    OIDC_REDIRECT_URI,
                    params,
                    {
                        code_verifier:
                            codeVerifier,

                        state
                    }
                );


            const userinfo =
                await oidcClient.userinfo(
                    tokenSet.access_token
                );


            req.session.user =
                userinfo.name ||
                userinfo.preferred_username ||
                userinfo.email ||
                userinfo.sub;


            /*
             * Les valeurs utilisées uniquement pendant
             * le handshake OIDC ne sont plus nécessaires
             * après validation du callback.
             */

            delete req.session.codeVerifier;
            delete req.session.oidcState;


            logVerbose(
                `✅ Utilisateur "${req.session.user}" connecté depuis l'IP : ${getUserIp(req)}`
            );


            res.redirect(
                '/dashboard'
            );

        } catch (err) {

            logError(
                'OIDC callback error:',
                err
            );

            res
                .status(500)
                .send(
                    'Erreur OIDC'
                );

        }

    }
);


// ============================================================
// LOGOUT
// ============================================================

router.post(
    '/logout',
    async (req, res) => {

        req.session.destroy(
            () => {

                res.clearCookie(
                    'connect.sid'
                );

                res.sendStatus(
                    200
                );

            }
        );

    }
);


export default router;