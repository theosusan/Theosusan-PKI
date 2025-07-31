Gestion de clés SSH

Generation de paires au format ed25519
Ajout d'hosts
Règles pour associer des clés aux hosts

Bouton de synchronisation pour déployer

Différents types de logs : info / verbose / trace


Installation :

Necessite une bdd mariadb/mysql

créer un .env (partir de .env_exemple)

execution : npm install puis npm start

Url : localhost:3000

login par défaut = admin/admin
Pour le moment il n'est pas possible de créer d'user ou de le changer, préferer l'oidc

Après le premier login, récupérer la clé publique de bastion sur le dashboard et l'ajouter manuellement aux authorized_keys des hosts.


Dockerfile soon


30% codé par moi, 70% par chatgpt



TREE :

└── src
    ├── cli
    │   ├── manage_hosts.js
    │   ├── manage_keys.js
    │   ├── manage_users.js
    │   └── ssh_commands.js
    ├── db
    │   ├── db.js
    │   └── init_db.js
    ├── index.js
    ├── scripts
    │   └── update_keys.sh
    ├── util
    │   ├── crypto_util.js
    │   ├── init.js
    │   └── log_helper.js
    └── webui
        ├── public
        │   ├── css
        │   ├── dashboard.html
        │   ├── hosts.html
        │   ├── js
        │   ├── keys.html
        │   ├── login.ejs
        │   ├── robots.txt
        │   └── rules.html
        ├── routes
        │   ├── auth.js
        │   ├── dashboard.js
        │   ├── hosts.js
        │   ├── keys.js
        │   └── rules.js
        └── server.js