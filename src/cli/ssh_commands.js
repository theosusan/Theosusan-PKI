import { Client } from 'ssh2';
import fs from 'fs';
import {logError, logVerbose } from '../util/log_helper.js';

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

export async function installSSHFile({ host, port = 22, username, privateKey, localFilePath, remoteFilePath, chmodMode = '700' }) {
  const conn = new Client();

  const remoteScriptPath = `/home/${username}/.ssh/${remoteFilePath}`;

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      conn.end();
      reject(new Error('⏰ Timeout lors de l’installation du fichier SSH'));
    }, 15000);

    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) {
          clearTimeout(timeout);
          conn.end();
          return reject(err);
        }

        const readStream = fs.createReadStream(localFilePath);
        const writeStream = sftp.createWriteStream(remoteScriptPath);

        writeStream.on('close', () => {
          logVerbose(`📁 Fichier transféré vers ${remoteScriptPath}`);

          // 🔐 Appliquer les permissions spécifiées
          conn.exec(`chmod ${chmodMode} ${remoteScriptPath}`, (err, stream) => {
            if (err) {
              clearTimeout(timeout);
              conn.end();
              return reject(err);
            }

            let resolved = false;

            stream.on('data', (data) => {
              logVerbose(`📥 stdout chmod: ${data.toString().trim()}`);
            });

            stream.stderr.on('data', (data) => {
              logError(`❌ STDERR chmod : ${data.toString().trim()}`);
            });

            stream.on('exit', (code, signal) => {
              logVerbose(`ℹ️ chmod exited with code ${code}, signal ${signal}`);
              if (!resolved) {
                resolved = true;
                clearTimeout(timeout);
                conn.end();

                if (code === 0) {
                  logVerbose(`✅ chmod ${chmodMode} appliqué avec succès (via exit)`);
                  resolve();
                } else {
                  logError(`❌ chmod échoué avec code ${code}`);
                  reject(new Error(`chmod échoué avec code ${code}`));
                }
              }
            });

            stream.on('close', (code) => {
              if (!resolved) {
                resolved = true;
                clearTimeout(timeout);
                conn.end();

                if (code === 0) {
                  logVerbose(`✅ chmod ${chmodMode} appliqué avec succès (via close)`);
                  resolve();
                } else {
                  logError(`❌ chmod échoué avec code ${code}`);
                  reject(new Error(`chmod échoué avec code ${code}`));
                }
              }
            });
          });
        });

        writeStream.on('error', (err) => {
          clearTimeout(timeout);
          conn.end();
          reject(err);
        });

        readStream.pipe(writeStream);
      });
    });

    conn.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    conn.connect({ host, port, username, privateKey });
  });
}
