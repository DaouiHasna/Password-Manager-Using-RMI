// File: PasswordManagerRemote.java

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

/**
 * Interface RMI pour le gestionnaire de mots de passe.
 * Définit toutes les méthodes accessibles à distance.
 */
public interface PasswordManagerRemote extends Remote {
    
    /**
     * Enregistrer un nouvel utilisateur
     */
    RegisterResponse register(String username, String password) throws RemoteException;
    
    /**
     * Connexion d'un utilisateur
     */
    LoginResponse login(String username, String password) throws RemoteException;
    
    /**
     * Obtenir la liste des comptes d'un utilisateur
     */
    AccountListResponse getAccounts(String sessionToken) throws RemoteException;
    
    /**
     * Obtenir le mot de passe d'un compte spécifique
     */
    PasswordResponse getPassword(String sessionToken, int accountId) throws RemoteException;
    
    /**
     * Créer un nouveau compte
     */
    BasicResponse createAccount(String sessionToken, String compte, String accountUsername, 
                               String password, String notes) throws RemoteException;
    
    /**
     * Mettre à jour un compte existant
     */
    BasicResponse updateAccount(String sessionToken, int id, String compte, String accountUsername,
                               String password, String notes) throws RemoteException;
    
    /**
     * Supprimer un compte
     */
    BasicResponse deleteAccount(String sessionToken, int id) throws RemoteException;
    
    /**
     * Rechercher des comptes
     */
    AccountListResponse searchAccounts(String sessionToken, String searchTerm) throws RemoteException;
    
    /**
     * Déconnecter un utilisateur (invalider la session)
     */
    BasicResponse logout(String sessionToken) throws RemoteException;
}
