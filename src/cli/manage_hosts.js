import db from '../db/db.js';
import { logVerbose, logError } from '../util/log_helper.js';

/**
* Ajoute un hôte dans la base de données.
*/
export async function addHost({ hostname, user, address, port = 22, lastsync = null, checkExists = true }) {
  if (!hostname) {
    throw new Error("Le champ 'hostname' est obligatoire.");
  }
  if (!user) {
    throw new Error("Le champ 'user' est obligatoire.");
  }
  if (!address) {
    throw new Error("Le champ 'address' est obligatoire.");
  }
  
  if (checkExists) {
    const existing = await db('hosts').where({ hostname }).first();
    if (existing) {
      logVerbose(`ℹ️  Hôte '${hostname}' déjà présent.`);
      return { success: false, message: `Hôte '${hostname}' déjà présent.` };
    }
  }
  
  await db('hosts').insert({
    hostname,
    user,
    address,
    port,
    lastsync,
  });

  logVerbose(`✅ Hôte '${hostname}' créé.`);
  return { success: true, message: `Hôte '${hostname}' créé.` };
}

/**
* Supprime un hôte en base de données par son ID.
*/
export async function deleteHostById(id) {
  try {
    // Récupérer l'hôte avant suppression
    const host = await db('hosts').where({ id }).first();

    if (!host) {
      return { success: false, message: 'Hôte non trouvé.' };
    }

    // Supprimer l'hôte
    const deleted = await db('hosts').where({ id }).del();

    if (deleted) {
      logVerbose(`Hôte "${host.hostname}" supprimé.`);
      return { success: true, message: `Hôte "${host.hostname}" supprimé avec succès.` };
    } else {
      return { success: false, message: 'Erreur lors de la suppression.' };
    }
  } catch (err) {
    logError(`❌ Erreur lors de la suppression de l’hôte : ${err.message}`);
    return { success: false, message: 'Erreur serveur lors de la suppression: ' + err.message };
  }
}

