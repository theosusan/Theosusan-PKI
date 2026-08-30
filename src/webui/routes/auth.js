import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import db from '../../db/db.js';
import { comparePassword } from '../../util/crypto_util.js';
import { logVerbose, logError } from '../../util/log_helper.js';
import { Issuer, generators } from 'openid-client';
import dotenv from 'dotenv';
import ejs from 'ejs';
dotenv.config();

const router = express.Router();

// Pour gérer correctement les chemins avec ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// OIDC config
const OIDC_ISSUER_URL = process.env.OIDC_ISSUER_URL;
const OIDC_CLIENT_ID = process.env.OIDC_CLIENT_ID;
const OIDC_CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET;
const OIDC_REDIRECT_URI = process.env.OIDC_REDIRECT_URI
  || 'https://theosusan-pki.theosusan.fr/oidc/callback';

let oidcClientPromise;

const BASE_LOGIN_METHOD = process.env.BASE_LOGIN_METHOD === 'true';

function getOidcClient() {
  if (!oidcClientPromise) {
    oidcClientPromise = Issuer.discover(OIDC_ISSUER_URL).then((issuer) => {
      return new issuer.Client({
        client_id: OIDC_CLIENT_ID,
        client_secret: OIDC_CLIENT_SECRET,
        redirect_uris: [OIDC_REDIRECT_URI],
        response_types: ['code'],
      });
    });
  }
  return oidcClientPromise;
}

// Route GET / (page login)
router.get('/', (req, res) => {
  ejs.renderFile(path.join(__dirname, '../public/login.ejs'), { loginEnabled: BASE_LOGIN_METHOD }, (err, str) => {
    if (err) {
      logError('Erreur template login:', err);
      res.status(500).send('Erreur serveur');
      return;
    }
    res.send(str);
  });
});

// Middleware pour extraire IP utilisateur
function getUserIp(req) {
  let userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  if (userIp.startsWith('::ffff:')) {
    userIp = userIp.substring(7);
  }
  return userIp;
}

// POST /login - Authentification uniquement si activé
if (BASE_LOGIN_METHOD) {
  router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
      logError('Nom d’utilisateur et mot de passe requis');
      return res.status(400).json({ error: 'Nom d’utilisateur et mot de passe requis' });
      
    }
    
    try {
      const rows = await db('users').select('password').where({ username });
      if (rows.length === 0) {
        logError('Utilisateur non trouvé');
        return res.status(401).json({ error: 'Utilisateur non trouvé' });
      }
      
      const hashedPwd = rows[0].password;
      const isMatch = await comparePassword(password, hashedPwd);
      const userIp = getUserIp(req);
      
      if (isMatch) {
        req.session.user = username; // Stockage en session
        logVerbose(`✅ Utilisateur "${username}" connecté depuis l'IP : ${userIp}`);
        
        // Optionnel : mise à jour lastLogin dans la base
        await db('users').where({ username }).update({ lastLogin: db.fn.now() });
        
        logVerbose(`✅ Utilisateur "${username}" connecté depuis l'IP : ${userIp}`);
        return res.status(200).json({ message: 'Connexion réussie' });
      } else {
        logError(`❌ Utilisateur "${username}" tentative de connexion KO depuis l'IP : ${userIp}, Mot de passe incorrect`);
        return res.status(401).json({ error: 'Mot de passe incorrect' });
      }
    } catch (err) {
      logError('Erreur login:', err);
      return res.status(500).json({ error: 'Erreur serveur' });
    }
  });
} else {
  // Si désactivé, bloquer la route login
  router.post('/login', (req, res) => {
    logVerbose("Authentification utilisateur/mot de passe désactivée");
    res.status(403).json({ error: "Authentification utilisateur/mot de passe désactivée" });
  });
}

// Route pour initier l'authentification OIDC
router.get('/oidc/login', async (req, res) => {
  try {
    const oidcClient = await getOidcClient();
    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);
    const state = generators.state();
    req.session.codeVerifier = codeVerifier;
    req.session.oidcState = state;
    const url = oidcClient.authorizationUrl({
      scope: 'openid profile email',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
    });
    res.redirect(url);
  } catch (err) {
    logError('OIDC login error:', err);
    res.status(500).send('Erreur OIDC');
  }
});

// Callback OIDC
router.get('/oidc/callback', async (req, res) => {
  try {
    const oidcClient = await getOidcClient();
    const params = oidcClient.callbackParams(req);
    const codeVerifier = req.session.codeVerifier;
    const state = req.session.oidcState;
    const tokenSet = await oidcClient.callback(
      OIDC_REDIRECT_URI,
      params,
      { code_verifier: codeVerifier, state }
    );
    const userinfo = await oidcClient.userinfo(tokenSet.access_token);
    req.session.user = userinfo.name || userinfo.preferred_username || userinfo.email || userinfo.sub;
    logVerbose(`✅ Utilisateur "${req.session.user}" connecté depuis l'IP : ${getUserIp(req)}`);
    res.redirect('/dashboard');
  } catch (err) {
    logError('OIDC callback error:', err);
    res.status(500).send('Erreur OIDC');
  }
});

// POST /logout - Déconnexion
router.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.sendStatus(200);
  });
});

export default router;
