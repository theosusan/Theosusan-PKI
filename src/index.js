import { init } from './util/init.js';
import { startWebUI } from './webui/server.js';
import { logError } from './util/log_helper.js';

async function main() {
  try {
    await init();
    
    await startWebUI();
    
  } catch (err) {
    logError('❌ Erreur lors du démarrage :', err);
    process.exit(1);
  }
}

main();