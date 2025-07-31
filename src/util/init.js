import { initDatabase } from '../db/init_db.js';
import { generateKey } from '../cli/manage_keys.js';
import { addUser } from '../cli/manage_users.js';
import { logInfo, logVerbose, logError } from '../util/log_helper.js';
import { exit } from 'process';

export async function init() {
  
  
  try {
    
    await initDatabase();
    
    // Générer la clé bastion ED25519 si elle n'existe pas
    const generatekey = await generateKey({
      type: 'ed25519',
      name: 'bastion',
      comment: 'THEOSUSAN-PKI[BASTION]',
      checkExists: true
    });
    
    if (generatekey.success) {
      logVerbose('✅ Clé bastion créée.');
    } else {
      if (!generatekey.message.includes("existe déjà")) {
        throw new Error(generatekey.message);
      }
    }
    
    // Créer l'utilisateur admin par défaut (si pas déjà présent)
    await addUser({ username: 'admin', password: 'admin', checkExists: true });
    
    
  } catch (err) {
    logError(`❌ Échec de l'initialisation : ${err.message}`);
    exit(1); // Quitte le processus avec code d'erreur
  }
  
  logInfo('ℹ️  Service theosusan-pki prêt à démarrer.');
}
