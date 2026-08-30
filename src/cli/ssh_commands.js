import { Client } from 'ssh2';
import fs from 'fs';
import { logError, logVerbose } from '../util/log_helper.js';

export function remoteSshDir(username) {
  return username === 'root' ? '/root/.ssh' : `/home/${username}/.ssh`;
}

export function remoteSshPath(username, filename) {
  return `${remoteSshDir(username)}/${filename}`;
}

export async function connectSSH({ host, port = 22, username, privateKey }) {
  return new Promise((resolve, reject) => {
    const conn = new Client();

    conn.on('ready', () => {
      resolve(conn);
    });

    conn.on('error', (err) => {
      reject(err);
    });

    conn.connect({
      host,
      port,
      username,
      privateKey
    });
  });
}

function execCommand(conn, command) {
  return new Promise((resolve, reject) => {
    conn.exec(command, (err, stream) => {
      if (err) return reject(err);

      let stdout = '';
      let stderr = '';

      stream.on('data', (data) => {
        stdout += data.toString();
      });
      stream.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      stream.on('close', (code) => {
        resolve({ code, stdout, stderr });
      });
    });
  });
}

export async function installSSHFile({ host, port = 22, username, privateKey, localFilePath, remoteFilePath, chmodMode = '700' }) {
  const conn = new Client();
  const remoteDir = remoteSshDir(username);
  const remoteScriptPath = remoteSshPath(username, remoteFilePath);

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      conn.end();
      reject(new Error('⏰ Timeout lors de l’installation du fichier SSH'));
    }, 15000);

    const fail = (err) => {
      clearTimeout(timeout);
      conn.end();
      reject(err);
    };

    conn.on('ready', async () => {
      try {
        const mkdir = await execCommand(conn, `mkdir -p "${remoteDir}" && chmod 700 "${remoteDir}"`);
        if (mkdir.code !== 0) {
          return fail(new Error(`Impossible de créer ${remoteDir} : ${mkdir.stderr || mkdir.stdout}`));
        }

        conn.sftp((err, sftp) => {
          if (err) return fail(err);

          const readStream = fs.createReadStream(localFilePath);
          const writeStream = sftp.createWriteStream(remoteScriptPath);

          writeStream.on('close', async () => {
            logVerbose(`📁 Fichier transféré vers ${remoteScriptPath}`);
            try {
              const chmod = await execCommand(conn, `chmod ${chmodMode} "${remoteScriptPath}"`);
              clearTimeout(timeout);
              conn.end();
              if (chmod.code === 0) {
                logVerbose(`✅ chmod ${chmodMode} appliqué avec succès`);
                resolve();
              } else {
                logError(`❌ chmod échoué avec code ${chmod.code}`);
                reject(new Error(`chmod échoué avec code ${chmod.code}`));
              }
            } catch (chmodErr) {
              fail(chmodErr);
            }
          });

          writeStream.on('error', fail);
          readStream.on('error', fail);
          readStream.pipe(writeStream);
        });
      } catch (err) {
        fail(err);
      }
    });

    conn.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    conn.connect({ host, port, username, privateKey });
  });
}
