
# Password Manager RMI

## Description

Cette application Java utilise RMI (Remote Method Invocation) pour permettre aux utilisateurs de stocker et gérer leurs mots de passe personnels de manière centralisée et sécurisée.  
Elle offre une interface Swing intuitive côté client et serveur, avec une communication sécurisée en SSL/TLS.

---

## 1. Structure du projet

```

password-manager-rmi/
├── PasswordManagerRemote.java        # Interface RMI distante
├── BasicResponse.java                # Réponse simple : succès + message
├── RegisterResponse.java             # Réponse d'inscription (token inclus)
├── LoginResponse.java                # Réponse de connexion
├── PasswordResponse.java             # Mot de passe déchiffré
├── AccountListResponse.java          # Liste de comptes utilisateur
├── Account.java                      # Objet de compte (site, login, pass chiffré)
├── PasswordManagerRMIServer.java     # Serveur RMI avec interface graphique
├── PasswordManagerRMIClient.java     # Client Swing
├── keystore.jks                      # Certificat SSL serveur
├── truststore.jks                    # Certificat de confiance client
├── gson-2.8.9.jar                    # Librairie JSON (nécessaire)
├── sqlite-jdbc-3.42.0.0.jar          # Pilote JDBC SQLite
└── README.md                         # Ce fichier

````

---

## 2. Compilation

```bash
/usr/lib/jvm/java-11-openjdk-amd64/bin/javac \
-cp ".:gson-2.8.9.jar:sqlite-jdbc-3.42.0.0.jar" *.java
````

---

## 3. Exécution

### a) Démarrer le serveur

```bash
/usr/lib/jvm/java-11-openjdk-amd64/bin/java \
--add-opens=java.base/java.lang=ALL-UNNAMED \
--add-opens=java.base/java.util=ALL-UNNAMED \
--add-opens=java.rmi/sun.rmi.server=ALL-UNNAMED \
-Djavax.net.ssl.keyStore=keystore.jks \
-Djavax.net.ssl.keyStorePassword=password \
-Djavax.net.ssl.trustStore=truststore.jks \
-Djavax.net.ssl.trustStorePassword=motdepasse \
-cp ".:gson-2.8.9.jar:sqlite-jdbc-3.42.0.0.jar" \
PasswordManagerRMIServer
```

### b) Démarrer le client

```bash
/usr/lib/jvm/java-11-openjdk-amd64/bin/java \
--add-opens=java.base/java.lang=ALL-UNNAMED \
--add-opens=java.base/java.util=ALL-UNNAMED \
--add-opens=java.rmi/sun.rmi.server=ALL-UNNAMED \
-Djavax.net.ssl.trustStore=truststore.jks \
-Djavax.net.ssl.trustStorePassword=motdepasse \
-cp ".:gson-2.8.9.jar:sqlite-jdbc-3.42.0.0.jar" \
PasswordManagerRMIClient
```

---

## 4. Configuration SSL

Dans le code Java (client et serveur) :

```java
System.setProperty("javax.net.ssl.keyStore", "keystore.jks");
System.setProperty("javax.net.ssl.keyStorePassword", "password");
System.setProperty("javax.net.ssl.trustStore", "truststore.jks");
System.setProperty("javax.net.ssl.trustStorePassword", "motdepasse");
```

* `keystore.jks` : contient le certificat SSL du serveur
* `truststore.jks` : utilisé côté client pour vérifier l'identité du serveur

---

## 5. Méthodes RMI exposées

```java
public interface PasswordManagerRemote extends Remote {
    LoginResponse login(String username, String password) throws RemoteException;
    RegisterResponse register(String username, String password) throws RemoteException;
    PasswordResponse getPassword(String token, String label) throws RemoteException;
    BasicResponse addAccount(String token, Account acc) throws RemoteException;
    AccountListResponse listAccounts(String token) throws RemoteException;
}
```

---

## 6. Interface utilisateur

### Serveur

* Bouton "Se connecter" ➜ démarre automatiquement le registre RMI
* Logs affichés en temps réel : connexions, opérations, temps de réponse

### Client

* Connexion à l’adresse IP (localhost par défaut) et port (1099 par défaut)
* Création de compte ou authentification
* Gestion des comptes : ajout, modification, suppression

---

## 7. Sécurité implémentée

| Mécanisme                     | Description                                            |
| ----------------------------- | ------------------------------------------------------ |
| Chiffrement des mots de passe | AES-256 (stockés chiffrés dans SQLite)                 |
| Authentification              | SHA-256 avec sel                                       |
| Sessions sécurisées           | Token de session aléatoire                             |
| Isolation des données         | Chaque utilisateur voit ses propres comptes uniquement |
| Validation d’entrée           | Vérification et nettoyage des champs                   |
| SSL/TLS                       | Chiffrement des échanges RMI                           |

---

## 8. Monitoring (côté serveur)

* Nombre de connexions actives
* Statistiques par utilisateur
* Temps moyen de réponse
* Journalisation graphique en direct

---

## 9. Dépannage

| Erreur                 | Solution                                       |
| ---------------------- | ---------------------------------------------- |
| ClassNotFoundException | Vérifiez le classpath et les `.class`          |
| ConnectException       | Vérifiez que le serveur est bien lancé         |
| NotBoundException      | Le service n’est pas enregistré                |
| AccessControlException | Vérifiez la politique de sécurité Java         |
| SSLHandshakeException  | Vérifiez les mots de passe keystore/truststore |

---

## 10. Conclusion

Ce projet démontre la mise en œuvre d'une application de gestion de mots de passe sécurisée, utilisant RMI pour la communication client-serveur, et intégrant le chiffrement SSL/TLS, la validation, l'authentification sécurisée, et une interface utilisateur graphique complète.

---

## Auteurs

* **Hasna Daoui** – Développement, sécurité, interfaces
* **Nana Diawara** – Conception, base de données, tests
