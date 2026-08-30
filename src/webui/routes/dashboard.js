import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { requireAuth } from '../server.js';
import { logVerbose } from '../../util/log_helper.js';
import rateLimit from 'express-rate-limit';

const router = express.Router();

const dashboardRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per window
    standardHeaders: true,
    legacyHeaders: false
});

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
    dashboardRateLimiter,
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