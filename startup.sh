#!/bin/bash

required_vars=(DB_HOST DB_NAME DB_USER DB_PASSWORD SECRET_KEY OIDC_CLIENT_ID OIDC_CLIENT_SECRET OIDC_ISSUER_URL)
optional_vars=(BASE_LOGIN_METHOD LOG_LEVEL)

# Fonction pour ajouter une variable manquante dans .env
add_var_to_env() {
    local var="$1"
    local value="${!var}"

    # Valeur par défaut si variable optionnelle
    if [ "$var" == "BASE_LOGIN_METHOD" ] && [ -z "$value" ]; then
        value=true
    elif [ "$var" == "LOG_LEVEL" ] && [ -z "$value" ]; then
        value=info
    fi

    if [ -z "$value" ]; then
        echo "Erreur : la variable d'environnement $var est manquante et nécessaire pour compléter .env"
        return 1
    fi

    return 0
}

# Si .env existe, vérifier les clés obligatoires
if [ -f .env ]; then
    missing=0
    for var in "${required_vars[@]}"; do
        if ! grep -q "^${var}=" .env; then
            add_var_to_env "$var" || missing=1
        fi
    done

    # Vérifie ou ajoute les variables optionnelles
    for var in "${optional_vars[@]}"; do
        if ! grep -q "^${var}=" .env; then
            add_var_to_env "$var"
        fi
    done

    if [ "$missing" -eq 1 ]; then
        echo "Erreur : certaines variables obligatoires n'ont pas pu être ajoutées. Abandon."
        exit 1
    fi

else
    missing=0
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            echo "Erreur : variable d'environnement $var manquante."
            missing=1
        fi
    done

    if [ "$missing" -eq 1 ]; then
        echo "Abandon : impossible de créer .env sans toutes les variables requises."
        exit 1
    fi

    {
        for var in "${required_vars[@]}"; do
            echo "${var}=${!var}"
        done
        echo "BASE_LOGIN_METHOD=${BASE_LOGIN_METHOD:-true}"
        echo "LOG_LEVEL=${LOG_LEVEL:-info}"
    } >> .env
fi

# Démarrage de l'application
if [ -f package.json ]; then
    echo "startup OK!"
    npm start
else
    echo "package.json manquant !"
    exit 1
fi
