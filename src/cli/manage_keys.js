import fs from 'fs/promises';
import { execFile } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import os from 'os';
import db from '../db/db.js';
import { encrypt } from '../util/crypto_util.js';
import { logError, logVerbose } from '../util/log_helper.js';

const execFileAsync = promisify(execFile);

export async function generateKey({
  type = 'ed25519',
  name = 'default_key',
  comment = '',
  checkExists = false
} = {}) {
  try {
    if (checkExists) {
      const existing = await db('ssh_keys').where({ name }).first();
      if (existing) {
        logVerbose(`ℹ️  La clé '${name}' existe déjà.`);
        return { success: false, message: `La clé '${name}' existe déjà.` };
      }
    }
    
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sshkey-'));
    const keyFilename = type === 'rsa' ? 'id_rsa' : 'id_ed25519';
    const privateKeyPath = path.join(tmpDir, keyFilename);
    const publicKeyPath = privateKeyPath + '.pub';

    try {
      await execFileAsync('ssh-keygen', [
        '-t', type,
        '-f', privateKeyPath,
        '-N', '',
        '-C', comment
      ]);

      const privateKey = await fs.readFile(privateKeyPath, 'utf8');
      const publicKey = await fs.readFile(publicKeyPath, 'utf8');
      const encryptedPrivateKey = encrypt(privateKey);

      await db('ssh_keys').insert({
        name,
        type,
        publicKey,
        privateKey: encryptedPrivateKey,
        createdAt: db.fn.now()
      });
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
    
    logVerbose(`✅ Clé '${name}' créée avec succès.`);
    
    return { success: true, message: 'Clé créée avec succès.' };
    
  } catch (err) {
    logError(`❌ Erreur lors de la génération ou insertion de la clé : ${err.message}`);
    return { success: false, message: err?.message || err };
  }
}

export async function deleteKeyById(id) {
  try {
    // Récupérer la clé avant suppression
    const key = await db('ssh_keys').where({ id }).first();
    if (!key) {
      return { success: false, message: 'Clé non trouvée.' };
    }

    if (key.name === 'bastion') {
      return { success: false, message: 'La clé bastion ne peut pas être supprimée.' };
    }

    // Supprimer la clé
    await db('ssh_keys').where({ id }).del();
    
    logVerbose(`Clé '${key.name}' supprimée.`);
    return { success: true, message: `Clé '${key.name}' supprimée avec succès.` };
    
  } catch (err) {
    logError(`❌ Erreur lors de la suppression de la clé id=${id} : ${err.message}`);
    return { success: false, message: 'Erreur serveur lors de la suppression: ' + err.message };
  }
}
