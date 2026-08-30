import crypto from 'crypto';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';

dotenv.config();

if (!process.env.SECRET_KEY) {
  throw new Error('SECRET_KEY manquante');
}

const algorithm = 'aes-256-gcm';
const key = crypto.createHash('sha256').update(process.env.SECRET_KEY).digest();

export function encrypt(text) {
  const iv = crypto.randomBytes(12); // 12 bytes IV recommandé pour GCM
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const tag = cipher.getAuthTag();
  
  // On concatène iv + tag + encrypted en hex
  return iv.toString('hex') + tag.toString('hex') + encrypted;
}

export function decrypt(encrypted) {
  const iv = Buffer.from(encrypted.slice(0, 24), 'hex');    // 12 bytes IV (24 hex chars)
  const tag = Buffer.from(encrypted.slice(24, 56), 'hex');  // 16 bytes tag (32 hex chars)
  const encryptedText = encrypted.slice(56);
  
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  decipher.setAuthTag(tag);
  
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// --- Ajout bcrypt pour hasher le mot de passe ---

const saltRounds = 10;

/**
* Hash un mot de passe en bcrypt.
* @param {string} password Texte clair
* @returns {Promise<string>} Le hash bcrypt
*/
export async function hashPassword(password) {
  return bcrypt.hash(password, saltRounds);
}

/**
* Compare un mot de passe clair avec un hash bcrypt.
* @param {string} password Texte clair
* @param {string} hashed Hash bcrypt
* @returns {Promise<boolean>} true si match, false sinon
*/
export async function comparePassword(password, hashed) {
  return bcrypt.compare(password, hashed);
}

//Generation de salt
export function generateSalt(length = 6) {
  return crypto.randomBytes(length).toString('hex');
}
