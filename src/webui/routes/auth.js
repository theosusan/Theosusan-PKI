import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import db from '../../db/db.js';
import { comparePassword } from '../../util/crypto_util.js';
import {
    logVerbose,
    logError
} from '../../util/log_helper.js';

import * as openidClient from 'openid-client';

import dotenv from 'dotenv';
import ejs from 'ejs';
import { rateLimit } from 'express-rate-limit';

dotenv.config();

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================
// RATE LIMITING
// ============================================================

const loginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error:
            'Trop de tentatives de connexion. Veuillez réessayer dans quelques minutes.'
    }
});

const oidcLoginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error:
            'Trop de demandes d’authentification. Veuillez réessayer plus tard.'
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

// ============================================================
// CLIENT OIDC
// ============================================================

function getOidcClient() {
    if (!oidcClientPromise) {
        oidcClientPromise = openidClient.discovery(
            new URL(OIDC_ISSUER_URL),
            OIDC_CLIENT_ID,
            OIDC_CLIENT_SECRET
        );
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
// RÉCUPÉRATION DE L'IP
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

                    return res
                        .status(200)
                        .json({
                            message:
                                'Connexion réussie'
                        });
                }

                logError(
                    `❌ Utilisateur "${username}" tentative de connexion KO depuis l'IP : ${userIp}, Mot de passe incorrect`
                );

                return res
                    .status(401)
                    .json({
                        error:
                            'Mot de passe incorrect'
                    });
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
                openidClient.randomPKCECodeVerifier();

            const codeChallenge =
                await openidClient.calculatePKCECodeChallenge(
                    codeVerifier
                );

            const state =
                openidClient.randomState();

            const nonce =
                openidClient.randomNonce();

            req.session.codeVerifier =
                codeVerifier;

            req.session.oidcState =
                state;

            req.session.oidcNonce =
                nonce;

            const authorizationUrl =
                openidClient.buildAuthorizationUrl(
                    oidcClient,
                    {
                        redirect_uri:
                            OIDC_REDIRECT_URI,

                        scope:
                            'openid profile email',

                        code_challenge:
                            codeChallenge,

                        code_challenge_method:
                            'S256',

                        state,

                        nonce
                    }
                );

            res.redirect(
                authorizationUrl.href
            );
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

            const codeVerifier =
                req.session.codeVerifier;

            const state =
                req.session.oidcState;

            const nonce =
                req.session.oidcNonce;

            if (!codeVerifier) {
                logError(
                    'OIDC callback sans code_verifier de session'
                );

                return res
                    .status(400)
                    .send(
                        'Session OIDC invalide ou expirée'
                    );
            }

            const currentUrl =
                new URL(
                    `${req.protocol}://${req.get('host')}${req.originalUrl}`
                );

            const tokens =
                await openidClient.authorizationCodeGrant(
                    oidcClient,
                    currentUrl,
                    {
                        pkceCodeVerifier:
                            codeVerifier,

                        expectedState:
                            state,

                        expectedNonce:
                            nonce,

                        idTokenExpected:
                            true
                    }
                );

            const claims =
                tokens.claims();

            let user;

            if (claims) {
                user =
                    claims.name ||
                    claims.preferred_username ||
                    claims.email ||
                    claims.sub;
            }

            if (
                !user &&
                tokens.access_token
            ) {
                const userinfo =
                    await openidClient.fetchUserInfo(
                        oidcClient,
                        tokens.access_token,
                        claims?.sub
                    );

                user =
                    userinfo.name ||
                    userinfo.preferred_username ||
                    userinfo.email ||
                    userinfo.sub;
            }

            if (!user) {
                throw new Error(
                    'Impossible de déterminer l’utilisateur OIDC'
                );
            }

            req.session.user =
                user;

            delete req.session.codeVerifier;
            delete req.session.oidcState;
            delete req.session.oidcNonce;

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

            delete req.session.codeVerifier;
            delete req.session.oidcState;
            delete req.session.oidcNonce;

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