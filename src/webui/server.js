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

app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SECRET_KEY,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === 'true',
    sameSite: 'lax'
  }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use((req, res, next) => {
  if (/\.(html|ejs)$/i.test(req.path)) {
    return res.redirect('/');
  }
  next();
});
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

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
