import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import db from '../../db/db.js';
import { requireAuth } from '../server.js';
import { addHost, deleteHostById } from '../../cli/manage_hosts.js';
import { logError, logVerbose } from '../../util/log_helper.js';
import { connectSSH, installSSHFile, remoteSshPath } from '../../cli/ssh_commands.js';
import { decrypt, generateSalt } from  '../../util/crypto_util.js';
import { getBastionPublicKey } from './keys.js';


const router = express.Router();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Affichage de la page hosts.html
router.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/hosts.html'));
});

// ROUTE Ajout d’un hôte
router.post('/', requireAuth, async (req, res) => {
  const { hostname, user, address, port } = req.body;
  
  try {
    const result = await addHost({ hostname, user, address, port: port || 22 });
    if (!result.success) {
      logVerbose(`Ajout hôte refusé : ${result.message}`);
      return res.status(409).send(result.message);
    }
    logVerbose(`Hôte ajouté : ${hostname} (${user}@${address}:${port || 22})`);
    res.send('Hôte ajouté avec succès');
  } catch (err) {
    logError('❌ Erreur lors de l’ajout de l’hôte :', err);
    res.status(500).send('Erreur lors de l’ajout de l’hôte');
  }
});

// ROUTE Liste des hôtes
router.get('/list', requireAuth, async (req, res) => {
  try {
    const rows = await db('hosts')
    .select('id', 'hostname', 'user', 'address', 'port', 'lastsync')
    .orderBy('id', 'asc');
    logVerbose(`GET /hosts/list - Liste des hôtes récupérée, ${rows.length} hôtes trouvés`);
    res.json(rows);
  } catch (err) {
    logError('❌ Erreur lors de la récupération des hôtes :', err);
    res.status(500).send('Erreur lors de la récupération des hôtes');
  }
});

// ROUTE Suppression d’un hôte
router.delete('/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  
  try {
    const hostInfo = await getHostInfo(id);
    const { user: username, address: host, port } = hostInfo;
    
    const privateKey = await getPrivateKey();
    
    let conn;
    try {
      conn = await attemptSSHConnection({ host, port, username, privateKey });
      logVerbose(`🔐 Connexion SSH établie à ${username}@${host}:${port || 22}`);
      
      const scriptExists = await checkUninstallScript(conn, username);
      if (scriptExists) {
        logVerbose(`📄 Script trouvé, tentative de désinstallation`);
        const uninstallSuccess = await runUninstallScript(conn, username);
        if (uninstallSuccess) {
          logVerbose(`✅ Désinstallation réussie`);
        } else {
          logError(`❌ La désinstallation a échoué`);
        }
      } else {
        logVerbose(`ℹ️ Script absent, rien à désinstaller`);
      }
      
      conn.end();
    } catch (sshErr) {
      logError(`⚠️  Connexion SSH échouée vers ${host}:${port}`, sshErr);
      if (conn) conn.end();
    }
    
    await proceedToDelete(id, res);
    
  } catch (err) {
    logError(`❌ Erreur générale dans DELETE /hosts/${id} :`, err.message || err);
    res.status(500).send(err.message || 'Erreur serveur');
  }
});


// ROUTE Connexion SSH
router.post('/connect', requireAuth, async (req, res) => {
  const { id } = req.body;
  let tmpFilePath;

  try {
    if (!id) {
      return res.status(400).send('id hôte requis');
    }

    const hostInfo = await getHostInfo(id);
    const host = hostInfo.address;
    const username = hostInfo.user;
    const sshPort = hostInfo.port ? Number(hostInfo.port) : 22;

    const privateKey = await getPrivateKey();
    const conn = await connectSSH({ host, port: sshPort, username, privateKey });
    logVerbose(`🔐 Connexion SSH établie à ${username}@${host}:${sshPort}`);

    const scriptExists = await checkRemoteScriptPresence(conn, username);
    conn.end();

    if (!scriptExists) {
      logVerbose(`📦 Script manquant, installation sur ${host}...`);
      const localScriptPath = path.resolve('src', 'scripts', 'update_keys.sh');
      await installSSHFile({
        host,
        port: sshPort,
        username,
        privateKey,
        localFilePath: localScriptPath,
        remoteFilePath: 'update_keys.sh',
        chmodMode: '700'
      });
      logVerbose(`✅ Script installé avec succès sur ${host}`);
    } else {
      logVerbose(`✅ Script déjà présent sur ${host}`);
    }

    const publicKeys = await getPublicKeysByHostId(Number(id));
    const bastionPublicKey = (await getBastionPublicKey()).publicKey;
    const publicKeysTrimmed = publicKeys.map(k => k.trim());
    const bastionPublicKeyTrimmed = bastionPublicKey.trim();
    const allKeys = [bastionPublicKeyTrimmed, ...publicKeysTrimmed].join('\n') + '\n';

    const randomSalt = generateSalt();
    const tmpFilename = `authorized_keys.theosusan-pki.${randomSalt}`;
    tmpFilePath = path.join('/tmp', tmpFilename);
    fs.writeFileSync(tmpFilePath, allKeys, { encoding: 'utf8' });

    await installSSHFile({
      host,
      port: sshPort,
      username,
      privateKey,
      localFilePath: tmpFilePath,
      remoteFilePath: 'authorized_keys.theosusan-pki',
      chmodMode: '600'
    });
    logVerbose(`📁 Fichier temporaire transféré sur ${host}`);

    const { code, output } = await runRemoteUpdateScript({ host, port: sshPort, username, privateKey });

    if (code === 0) {
      logVerbose(`✅ Script update exécuté avec succès sur ${host}`);
      await db('hosts').where({ id }).update({ lastsync: db.fn.now() });
      logVerbose(`⏱️  Mise à jour de lastsync pour hôte id=${id}`);
      res.send(`✅ Connexion SSH et update OK sur ${host}\n\n${output}`);
    } else {
      logError(`❌ Script update a échoué (code ${code}) sur ${host} :\n${output}`);
      res.status(500).send(`Update terminé avec erreur (code ${code})\n\n${output}`);
    }

  } catch (err) {
    logError(`❌ Erreur dans POST /connect :`, err);
    res.status(500).send(`Erreur de connexion ou d’exécution SSH : ${err.message}`);
  } finally {
    if (tmpFilePath) {
      try { fs.unlinkSync(tmpFilePath); } catch { /* ignore */ }
    }
  }
});



// FONCTIONS

async function checkRemoteScriptPresence(conn, username) {
  const remotePath = remoteSshPath(username, 'update_keys.sh');
  const checkCmd = `[ -f "${remotePath}" ] && echo "EXISTS" || echo "MISSING"`;
  
  return new Promise((resolve, reject) => {
    conn.exec(checkCmd, (err, stream) => {
      if (err) return reject(err);
      
      let output = '';
      stream.on('data', (data) => (output += data.toString()));
      stream.on('close', () => resolve(output.trim() === 'EXISTS'));
      stream.stderr.on('data', (data) => logError(`❌ STDERR check script: ${data.toString().trim()}`));
    });
  });
}

async function runRemoteUpdateScript({ host, port, username, privateKey }) {
  const remotePath = remoteSshPath(username, 'update_keys.sh');
  const command = `"${remotePath}" update ${username}`;
  const conn = await connectSSH({ host, port, username, privateKey });
  
  return new Promise((resolve, reject) => {
    conn.exec(command, (err, stream) => {
      if (err) {
        conn.end();
        return reject(new Error(`Erreur d’exécution du script update : ${err.message}`));
      }
      
      let stdout = '';
      let stderr = '';
      
      stream.on('data', (data) => (stdout += data.toString()));
      stream.stderr.on('data', (data) => {
        stderr += data.toString();
        logError(`❌ STDERR update : ${data.toString().trim()}`);
      });
      
      stream.on('close', (code) => {
        conn.end();
        resolve({ code, output: `${stdout}${stderr}`.trim() });
      });
    });
  });
}

async function getHostInfo(id) {
  const hostInfo = await db('hosts').where({ id }).first();
  if (!hostInfo) throw new Error(`Hôte id=${id} non trouvé en base`);
  return hostInfo;
}

async function getPrivateKey(name = 'bastion') {
  const keyRow = await db('ssh_keys').where({ name }).first();
  if (!keyRow) throw new Error('Clé privée bastion introuvable en base');
  return decrypt(keyRow.privateKey);
}

async function attemptSSHConnection({ host, port, username, privateKey }) {
  return await connectSSH({
    host,
    port: port || 22,
    username,
    privateKey,
  });
}

function checkUninstallScript(conn, username) {
  return new Promise((resolve, reject) => {
    const remotePath = remoteSshPath(username, 'update_keys.sh');
    const checkCmd = `[ -f "${remotePath}" ] && echo "EXISTS" || echo "MISSING"`;
    
    conn.exec(checkCmd, (err, stream) => {
      if (err) return reject(err);
      
      let output = '';
      stream.on('data', (data) => output += data.toString());
      stream.on('close', () => resolve(output.trim() === 'EXISTS'));
      stream.stderr.on('data', (data) => logError(`❌ STDERR check script: ${data.toString().trim()}`));
    });
  });
}

function runUninstallScript(conn, username) {
  return new Promise((resolve) => {
    const remotePath = remoteSshPath(username, 'update_keys.sh');
    const uninstallCmd = `"${remotePath}" uninstall ${username}`;
    
    conn.exec(uninstallCmd, (err, stream) => {
      if (err) {
        logError(`❌ Erreur uninstall sur ${username}:`, err);
        return resolve(false);
      }
      
      let uninstallError = '';
      stream.stderr.on('data', (data) => {
        uninstallError += data.toString();
        logError(`❌ STDERR uninstall : ${data.toString().trim()}`);
      });
      
      stream.on('close', (code) => {
        resolve(code === 0);
      });
    });
  });
}

async function proceedToDelete(id, res) {
  try {
    const result = await deleteHostById(id);
    if (result.success) {
      logVerbose(`🗑️  Hôte id=${id} supprimé de la base`);
      res.send(result.message);
    } else {
      logError(`❌ Erreur suppression en base pour id=${id} : ${result.message}`);
      res.status(500).send(result.message);
    }
  } catch (err) {
    logError(`❌ Exception lors de la suppression en base pour id=${id} :`, err);
    res.status(500).send('Erreur serveur lors de la suppression');
  }
}

async function getPublicKeysByHostId(host_id) {
  if (!host_id || isNaN(host_id)) {
    throw new Error('host_id invalide');
  }
  
  const rows = await db('rules')
  .join('ssh_keys', 'rules.key_id', 'ssh_keys.id')
  .where('rules.host_id', host_id)
  .select('ssh_keys.publicKey');
  
  // rows est un tableau d'objets { publicKey: '...' }
  return rows.map(row => row.publicKey);
}

// END
export default router;
