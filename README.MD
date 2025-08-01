# Gestion de clés SSH



- Génération de paires de clés au format ed25519  
- Ajout et gestion des hosts  
- Règles pour associer des clés SSH aux hosts  
- Bouton de synchronisation pour déployer les clés sur les hosts  
- Différents types de logs : info / verbose / trace  


### 30% codé par moi, 70% par chatgpt



## Installation :



1. Nécessite une bdd mariadb/mysql

2. Copier le fichier `.env_exemple` en `.env` et adapter la configuration 


3. Exécuter :
```bash
  npm install
  npm start
```

4. Url : localhost:3000

5. login par défaut = admin/admin

- Pour plus de sécurité, mettre l'app derrière un reverse-proxy comme Nginx

- Pour le moment il n'est pas possible de créer d'user ou de le changer, préferer l'oidc

6. [Image Docker](https://hub.docker.com/r/theosusan/theosusan-pki)


## Utilsation

Après le premier login, récupérer la clé publique de bastion sur le dashboard et l'ajouter manuellement aux authorized_keys des hosts.

![dashboard](https://raw.githubusercontent.com/theosusan/Theosusan-PKI/refs/heads/main/screen1.png)



## Roadmap

- Gestion des users locaux
- Ui plus propre


## Tree

```bash
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
        │   │   └── main.css
        │   ├── dashboard.html
        │   ├── favicon.ico
        │   ├── hosts.html
        │   ├── js
        │   │   └── main.js
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
```
