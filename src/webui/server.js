import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import { logInfo } from '../util/log_helper.js';
import authRoutes from './routes/auth.js';
import dashboardRoutes from './routes/dashboard.js';
import keysRouter from './routes/keys.js';
import hostsRouter from './routes/hosts.js';
import rulesRouter from './routes/rules.js';

const app = express();
const port = 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(session({
  secret: process.env.SECRET_KEY,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // true en prod HTTPS
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));  // ../../public depuis webui/

app.use('/', authRoutes);
app.use('/dashboard', dashboardRoutes);
app.use('/keys', keysRouter);
app.use('/hosts', hostsRouter);
app.use('/rules', rulesRouter);

export function startWebUI() {
  return new Promise((resolve) => {
    app.listen(port, () => {
      logInfo(`🌐 WebUI démarré sur http://localhost:${port}`);
      resolve();
    });
  });
}

export function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    next();
  } else {
    res.redirect('/'); // Redirection vers la page de connexion
  }
}
