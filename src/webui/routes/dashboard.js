import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { requireAuth } from '../server.js';
import { logVerbose } from '../../util/log_helper.js';

const router = express.Router();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


/*
 * PAGE DASHBOARD
 *
 * Cette route est uniquement accessible aux utilisateurs
 * authentifiés.
 */

router.get(
    '/',
    requireAuth,
    async (req, res) => {

        logVerbose(
            'GET /dashboard - Envoi du fichier dashboard.html'
        );

        res.sendFile(
            path.join(
                __dirname,
                '../public/dashboard.html'
            )
        );

    }
);


export default router;