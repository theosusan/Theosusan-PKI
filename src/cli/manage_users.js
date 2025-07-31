import db from '../db/db.js';
import { hashPassword } from '../util/crypto_util.js';
import { logVerbose } from '../util/log_helper.js';

export async function addUser({ username, password, checkExists = true }) {
  if (checkExists) {
    const existing = await db('users').where({ username }).first();
    if (existing) {
      logVerbose(`ℹ️  Utilisateur '${username}' déjà présent.`);
      return; // utilisateur déjà présent
    }
  }
  
  const hashedPassword = await hashPassword(password);
  
  await db('users').insert({
    username,
    password: hashedPassword,
    lastLogin: null
  });
  
  logVerbose(`✅ Utilisateur '${username}' créé.`);
}
