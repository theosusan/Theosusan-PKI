import dotenv from 'dotenv';
dotenv.config();

const LOG_LEVEL = process.env.LOG_LEVEL?.toLowerCase() || 'info';

const RESET = '\x1b[0m';
const BLUE = '\x1b[34m';
const RED = '\x1b[31m';

function getTimestamp() {
  const now = new Date();
  const pad = (n) => n.toString().padStart(2, '0');
  
  const day = pad(now.getDate());
  const month = pad(now.getMonth() + 1); // Mois commence à 0
  const year = now.getFullYear();
  
  const hours = pad(now.getHours());
  const minutes = pad(now.getMinutes());
  const seconds = pad(now.getSeconds());
  
  return `${day}/${month}/${year} ${hours}:${minutes}:${seconds}`;
}

// ✅ logInfo: toujours affiché
export function logInfo(...args) {
  console.log(`[${getTimestamp()}] [INFO]`, ...args);
}

// ✅ logVerbose: affiché si LOG_LEVEL = 'verbose' ou 'trace'
// Affiche stack trace uniquement si trace
export function logVerbose(...args) {
  if (LOG_LEVEL === 'verbose' || LOG_LEVEL === 'trace') {
    console.debug(`[${getTimestamp()}] ${BLUE}[VERBOSE]${RESET}`, ...args);
    if (LOG_LEVEL === 'trace') {
      console.trace();
    }
  }
}

// ✅ logError: toujours affiché
// Affiche stack trace d'erreur si disponible, et trace complète si LOG_LEVEL = 'trace'
export function logError(...args) {
  console.error(`[${getTimestamp()}] ${RED}[ERROR]${RESET}`, ...args);
  
  const err = args.find(arg => arg instanceof Error);
  if (err?.stack && LOG_LEVEL !== 'trace') {
    console.error(err.stack);
  }
  
  if (LOG_LEVEL === 'trace') {
    console.trace();
  }
}
