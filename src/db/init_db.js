// init_db.js
import db from './db.js';
import { logVerbose, logError } from '../util/log_helper.js';

export async function initDatabase() {
  try {
    // Vérifier et créer la table ssh_keys si elle n'existe pas
    const existsSshKeys = await db.schema.hasTable('ssh_keys');
    if (!existsSshKeys) {
      await db.schema.createTable('ssh_keys', (table) => {
        table.increments('id').primary();
        table.string('name').unique().notNullable();
        table.string('type', 50).notNullable();
        table.text('privateKey').notNullable();
        table.text('publicKey').notNullable();
        table.dateTime('createdAt').notNullable();
      });
      logVerbose('✅ Table ssh_keys créée');
    }
    
    // Vérifier et créer la table users si elle n'existe pas
    const existsUsers = await db.schema.hasTable('users');
    if (!existsUsers) {
      await db.schema.createTable('users', (table) => {
        table.increments('id').primary();
        table.string('username').unique().notNullable();
        table.string('password').notNullable();
        table.dateTime('lastLogin');
      });
      logVerbose('✅ Table users créée');
    }
    
    // Vérifier et créer la table hosts si elle n'existe pas
    const existsHosts = await db.schema.hasTable('hosts');
    if (!existsHosts) {
      await db.schema.createTable('hosts', (table) => {
        table.increments('id').primary();
        table.string('user').notNullable();
        table.string('hostname').unique().notNullable();
        table.string('address').notNullable();
        table.integer('port');
        table.dateTime('lastsync');
      });
      logVerbose('✅ Table hosts créée');
    }
    
    const existsRules = await db.schema.hasTable('rules');
    if (!existsRules) {
      await db.schema.createTable('rules', (table) => {
        table.increments('id').primary();
        
        table.integer('host_id').unsigned().notNullable()
        .references('id').inTable('hosts')
        .onDelete('CASCADE');
        
        table.integer('key_id').unsigned().notNullable()
        .references('id').inTable('ssh_keys')
        .onDelete('CASCADE');
        
        // Contrainte unique combinée pour empêcher les doublons exacts
        table.unique(['host_id', 'key_id']);
      });
      logVerbose('✅ Table rules créée');
    }
    
  } catch (err) {
    logError('❌ Erreur d\'initialisation de la base :', err);
    process.exit(1);
  }
}
