import javax.swing.*;
import java.awt.*;
import java.io.FileInputStream;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import javax.rmi.ssl.SslRMIServerSocketFactory;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import java.rmi.server.UnicastRemoteObject;
import java.security.KeyStore;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;

import java.sql.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Serveur RMI pour le gestionnaire de mots de passe avec interface Swing.
 */
public class PasswordManagerRMIServer extends UnicastRemoteObject implements PasswordManagerRemote {
    private static final String KEYSTORE_PATH = "keystore.p12";
private static final String KEYSTORE_PASSWORD = "managerpassword"; // Le mot de passe que vous avez utilisé

private static final String AES_CIPHER = "AES/CBC/PKCS5Padding";
private static final String TRUSTSTORE_PATH = "truststore.p12"; // Même fichier que le serveur
private static final String TRUSTSTORE_PASSWORD = "managerpassword"; 
private static final int SSL_PORT = 1099; // Port pour SS
    private static final String DB_URL = "jdbc:sqlite:password_manager.db";
    private static final Map<String, String> activeSessions = new ConcurrentHashMap<>();
    private static SecretKey serverKey;
    private final JTextArea logArea;
    
 
private static void configureSSL() throws Exception {
    // Charger le keystore
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
        keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
    }
    
    // Configurer le KeyManager
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());
    
    // Créer le contexte SSL
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
    
    // Définir les propriétés système pour RMI SSL
    System.setProperty("javax.net.ssl.keyStore", KEYSTORE_PATH);
    System.setProperty("javax.net.ssl.keyStorePassword", KEYSTORE_PASSWORD);
     System.setProperty("javax.net.ssl.trustStore", TRUSTSTORE_PATH);
        System.setProperty("javax.net.ssl.trustStorePassword", TRUSTSTORE_PASSWORD);
    System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");
    
    // Configurer RMI pour utiliser SSL
    System.setProperty("java.rmi.server.hostname", "192.168.139.129"); // Votre IP
    System.setProperty("javax.rmi.ssl.client.enabledCipherSuites", "TLS_RSA_WITH_AES_128_CBC_SHA");
    System.setProperty("javax.rmi.ssl.client.enabledProtocols", "TLSv1.2");
}
    // Constructeur protégé (requis pour UnicastRemoteObject)
protected PasswordManagerRMIServer(JTextArea logArea) throws Exception {
    super(SSL_PORT); // Utilise le port SSL au lieu du port par défaut
    this.logArea = logArea;
    initializeDatabase();
    generateServerKey();
    log("[RMI-SERVER] Serveur RMI avec SSL initialisé sur le port " + SSL_PORT);
}    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            int port = (args.length > 0) ? Integer.parseInt(args[0]) : 1099;
            new ServerFrame(port).setVisible(true);
        });
    }

    /** Interface Swing pour le serveur RMI */
    static class ServerFrame extends JFrame {
        private final JTextArea logArea;
        private final JButton startButton;
        private final int port;
        private volatile boolean running = false;

        ServerFrame(int port) {
            super("Password Manager RMI Server");
            this.port = port;
            setSize(700, 500);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setLocationRelativeTo(null);

            Container cp = getContentPane();
            cp.setLayout(new BorderLayout(10, 10));
            cp.setBackground(Color.WHITE);

            JPanel top = new JPanel(new GridLayout(3, 1, 5, 5));
            top.setBackground(Color.WHITE);
            top.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

            JLabel title = new JLabel("Secure Password Manager RMI Server (SSL/TLS)", JLabel.CENTER);
            title.setFont(new Font("Segoe UI", Font.BOLD, 18));
            top.add(title);
            
            JLabel portLabel = new JLabel("Port RMI Registry: " + port, JLabel.CENTER);
            portLabel.setFont(new Font("Segoe UI", Font.PLAIN, 14));
            top.add(portLabel);

            startButton = new JButton("Démarrer le serveur RMI SSL");
            startButton.setFont(new Font("Segoe UI", Font.PLAIN, 14));
            startButton.addActionListener(e -> {
                startButton.setEnabled(false);
                new Thread(this::startRMIServer).start();
            });
            top.add(startButton);

            cp.add(top, BorderLayout.NORTH);

            logArea = new JTextArea();
            logArea.setEditable(false);
            logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
            logArea.setBackground(new Color(248, 248, 248));
            JScrollPane scroll = new JScrollPane(logArea);
            scroll.setBorder(BorderFactory.createTitledBorder("Logs du serveur"));
            cp.add(scroll, BorderLayout.CENTER);
            
            JPanel bottom = new JPanel(new FlowLayout());
            bottom.setBackground(Color.WHITE);
            JLabel info = new JLabel("Service RMI SSL: PasswordManagerService (Port: " + SSL_PORT + ")");
            info.setFont(new Font("Segoe UI", Font.ITALIC, 12));
            bottom.add(info);
            cp.add(bottom, BorderLayout.SOUTH);
        }

        private void log(String msg) {
            SwingUtilities.invokeLater(() -> {
                String timestamp = new java.util.Date().toString();
                logArea.append("[" + timestamp + "] " + msg + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }
        private void startRMIServer() {
    running = true;
    try {
        // Configurer SSL avant de créer le registre
        configureSSL();
        log("[RMI-SERVER] Configuration SSL terminée");
        
        // Créer le registre RMI avec SSL
        Registry registry = LocateRegistry.createRegistry(port);
        log("[RMI-SERVER] Registre RMI avec SSL créé sur le port " + port);
        
        // Créer et enregistrer l'objet distant
        PasswordManagerRMIServer server = new PasswordManagerRMIServer(logArea);
        registry.rebind("PasswordManagerService", server);
        log("[RMI-SERVER] Service 'PasswordManagerService' enregistré avec SSL");
        log("[RMI-SERVER] Serveur RMI SSL prêt et en attente de connexions sécurisées...");
        
        // Garder le serveur actif
        while (running) {
            Thread.sleep(1000);
        }
        
    } catch (Exception ex) {
        log("[RMI-SERVER] Erreur SSL: " + ex.getMessage());
        ex.printStackTrace();
        SwingUtilities.invokeLater(() -> startButton.setEnabled(true));
    }
}       
     } 

    // Méthode utilitaire pour les logs
    private void log(String msg) {
        if (logArea != null) {
            SwingUtilities.invokeLater(() -> {
                String timestamp = new java.util.Date().toString();
                logArea.append("[" + timestamp + "] " + msg + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }
        System.out.println(msg);
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // IMPLÉMENTATION DES MÉTHODES RMI
    // ═══════════════════════════════════════════════════════════════════════════════

    @Override
    public RegisterResponse register(String username, String password) {
        try {
            username = sanitize(username);
            
            if (!isValidUsername(username) || !isValidPassword(password)) {
                return new RegisterResponse(false, "Format d'entrée invalide");
            }

            try (Connection conn = DriverManager.getConnection(DB_URL)) {
                // Vérifier si l'utilisateur existe déjà
                String check = "SELECT username FROM users WHERE username = ?";
                try (PreparedStatement ps = conn.prepareStatement(check)) {
                    ps.setString(1, username);
                    ResultSet rs = ps.executeQuery();
                    if (rs.next()) {
                        return new RegisterResponse(false, "Nom d'utilisateur déjà existant");
                    }
                }

                // Créer le nouvel utilisateur
                String salt = generateSalt();
                String hashed = hash(password, salt);
                String insert = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)";
                try (PreparedStatement ps = conn.prepareStatement(insert)) {
                    ps.setString(1, username);
                    ps.setString(2, hashed);
                    ps.setString(3, salt);
                    ps.executeUpdate();
                }

                log("[RMI-SERVER] Utilisateur enregistré: " + username);
                return new RegisterResponse(true, "Enregistrement réussi");
            }
        } catch (Exception e) {
            log("[RMI-SERVER] Erreur lors de l'enregistrement: " + e.getMessage());
            return new RegisterResponse(false, "Échec de l'enregistrement: " + e.getMessage());
        }
    }

    @Override
    public LoginResponse login(String username, String password) {
        try {
            username = sanitize(username);

            try (Connection conn = DriverManager.getConnection(DB_URL)) {
                String query = "SELECT password_hash, salt FROM users WHERE username = ?";
                try (PreparedStatement ps = conn.prepareStatement(query)) {
                    ps.setString(1, username);
                    ResultSet rs = ps.executeQuery();
                    if (rs.next()) {
                        String storedHash = rs.getString("password_hash");
                        String salt = rs.getString("salt");
                        String inputHash = hash(password, salt);
                        if (storedHash.equals(inputHash)) {
                            String token = generateSessionToken();
                            activeSessions.put(token, username);
                            log("[RMI-SERVER] Connexion réussie: " + username);
                            return new LoginResponse(true, "Connexion réussie", token);
                        }
                    }
                }
            }
            return new LoginResponse(false, "Identifiants invalides");
        } catch (Exception e) {
            log("[RMI-SERVER] Erreur lors de la connexion: " + e.getMessage());
            return new LoginResponse(false, "Échec de la connexion: " + e.getMessage());
        }
    }

    @Override
    public AccountListResponse getAccounts(String sessionToken) {
        try {
            String user = activeSessions.get(sessionToken);
            if (user == null) {
                return new AccountListResponse(false, "Session invalide");
            }

            try (Connection conn = DriverManager.getConnection(DB_URL)) {
                String query = "SELECT id, compte, account_username, notes FROM accounts WHERE username = ?";
                try (PreparedStatement ps = conn.prepareStatement(query)) {
                    ps.setString(1, user);
                    ResultSet rs = ps.executeQuery();

                    List<Account> accounts = new ArrayList<>();
                    while (rs.next()) {
                        accounts.add(new Account(
                            rs.getInt("id"),
                            rs.getString("compte"),
                            rs.getString("account_username"),
                            rs.getString("notes")
                        ));
                    }
                    log("[RMI-SERVER] [" + user + "] Liste des comptes récupérée (" + accounts.size() + " comptes)");
                    return new AccountListResponse(true, "Comptes récupérés", accounts);
                }
            }
        } catch (Exception e) {
            log("[RMI-SERVER] Erreur lors de la récupération des comptes: " + e.getMessage());
            return new AccountListResponse(false, "Erreur lors de la récupération: " + e.getMessage());
        }
    }

    @Override
    public PasswordResponse getPassword(String sessionToken, int accountId) {
        try {
            String user = activeSessions.get(sessionToken);
            if (user == null) {
                return new PasswordResponse(false, "Session invalide");
            }

            try (Connection conn = DriverManager.getConnection(DB_URL)) {
                String query = "SELECT encrypted_password FROM accounts WHERE id = ? AND username = ?";
                try (PreparedStatement ps = conn.prepareStatement(query)) {
                    ps.setInt(1, accountId);
                    ps.setString(2, user);
                    ResultSet rs = ps.executeQuery();
                    if (rs.next()) {
                        String enc = rs.getString("encrypted_password");
                        String plain = decrypt(enc);
                        log("[RMI-SERVER] [" + user + "] Mot de passe récupéré pour le compte ID " + accountId);
                        return new PasswordResponse(true, "Mot de passe récupéré", plain);
                    } else {
                        return new PasswordResponse(false, "Compte non trouvé");
                    }
                }
            }
        } catch (Exception e) {
            log("[RMI-SERVER] Erreur lors de la récupération du mot de passe: " + e.getMessage());
            return new PasswordResponse(false, "Erreur: " + e.getMessage());
        }
    }

    @Override
    public BasicResponse createAccount(String sessionToken, String compte, String accountUsername,
                                     String password, String notes) {
        try {
            String user = activeSessions.get(sessionToken);
            if (user == null) {
                return new BasicResponse(false, "Session invalide");
            }

            compte = sanitize(compte);
            accountUsername = sanitize(accountUsername);
            notes = sanitize(notes);
            String encPwd = encrypt(password);

            try (Connection conn = DriverManager.getConnection(DB_URL)) {
                String insert = "INSERT INTO accounts (username, compte, account_username, encrypted_password, notes) VALUES (?, ?, ?, ?, ?)";
                try (PreparedStatement ps = conn.prepareStatement(insert)) {
                    ps.setString(1, user);
                    ps.setString(2, compte);
                    ps.setString(3, accountUsername);
                    ps.setString(4, encPwd);
                    ps.setString(5, notes);
                    ps.executeUpdate();
                }
                log("[RMI-SERVER] [" + user + "] Compte créé: " + compte);
                return new BasicResponse(true, "Compte créé avec succès");
            }
        } catch (Exception e) {
            log("[RMI-SERVER] Erreur lors de la création du compte: " + e.getMessage());
            return new BasicResponse(false, "Échec de la création: " + e.getMessage());
        }
    }

    @Override
    public BasicResponse updateAccount(String sessionToken, int id, String compte, String accountUsername,
                                     String password, String notes) {
        try {
            String user = activeSessions.get(sessionToken);
            if (user == null) {
                return new BasicResponse(false, "Session invalide");
            }

            compte = sanitize(compte);
            accountUsername = sanitize(accountUsername);
            notes = sanitize(notes);
            String encPwd = encrypt(password);

            try (Connection conn = DriverManager.getConnection(DB_URL)) {
                String update = "UPDATE accounts SET compte=?, account_username=?, encrypted_password=?, notes=? WHERE id=? AND username=?";
                try (PreparedStatement ps = conn.prepareStatement(update)) {
                    ps.setString(1, compte);
                    ps.setString(2, accountUsername);
                    ps.setString(3, encPwd);
                    ps.setString(4, notes);
                    ps.setInt(5, id);
                    ps.setString(6, user);
                    int rows = ps.executeUpdate();
                    if (rows > 0) {
                        log("[RMI-SERVER] [" + user + "] Compte mis à jour ID " + id);
                        return new BasicResponse(true, "Compte mis à jour");
                    } else {
                        return new BasicResponse(false, "Compte non trouvé ou non autorisé");
                    }
                }
            }
        } catch (Exception e) {
            log("[RMI-SERVER] Erreur lors de la mise à jour: " + e.getMessage());
            return new BasicResponse(false, "Échec de la mise à jour: " + e.getMessage());
        }
    }

    @Override
    public BasicResponse deleteAccount(String sessionToken, int id) {
        try {
            String user = activeSessions.get(sessionToken);
            if (user == null) {
                return new BasicResponse(false, "Session invalide");
            }

            try (Connection conn = DriverManager.getConnection(DB_URL)) {
                String del = "DELETE FROM accounts WHERE id=? AND username=?";
                try (PreparedStatement ps = conn.prepareStatement(del)) {
                    ps.setInt(1, id);
                    ps.setString(2, user);
                    int rows = ps.executeUpdate();
                    if (rows > 0) {
                        log("[RMI-SERVER] [" + user + "] Compte supprimé ID " + id);
                        return new BasicResponse(true, "Compte supprimé");
                    } else {
                        return new BasicResponse(false, "Compte non trouvé ou non autorisé");
                    }
                }
            }
        } catch (Exception e) {
            log("[RMI-SERVER] Erreur lors de la suppression: " + e.getMessage());
            return new BasicResponse(false, "Échec de la suppression: " + e.getMessage());
        }
    }

    @Override
    public AccountListResponse searchAccounts(String sessionToken, String searchTerm) {
        try {
            String user = activeSessions.get(sessionToken);
            if (user == null) {
                return new AccountListResponse(false, "Session invalide");
            }

            searchTerm = sanitize(searchTerm);
            try (Connection conn = DriverManager.getConnection(DB_URL)) {
                String q = "SELECT id, compte, account_username, notes FROM accounts WHERE username=? AND (compte LIKE ? OR account_username LIKE ?)";
                try (PreparedStatement ps = conn.prepareStatement(q)) {
                    ps.setString(1, user);
                    ps.setString(2, "%" + searchTerm + "%");
                    ps.setString(3, "%" + searchTerm + "%");
                    ResultSet rs = ps.executeQuery();

                    List<Account> accounts = new ArrayList<>();
                    while (rs.next()) {
                        accounts.add(new Account(
                            rs.getInt("id"),
                            rs.getString("compte"),
                            rs.getString("account_username"),
                            rs.getString("notes")
                        ));
                    }
                    log("[RMI-SERVER] [" + user + "] Recherche effectuée pour '" + searchTerm + "' (" + accounts.size() + " résultats)");
                    return new AccountListResponse(true, "Recherche terminée", accounts);
                }
            }
        } catch (Exception e) {
            log("[RMI-SERVER] Erreur lors de la recherche: " + e.getMessage());
            return new AccountListResponse(false, "Échec de la recherche: " + e.getMessage());
        }
    }

    @Override
    public BasicResponse logout(String sessionToken) {
        String user = activeSessions.remove(sessionToken);
        if (user != null) {
            log("[RMI-SERVER] Déconnexion: " + user);
            return new BasicResponse(true, "Déconnexion réussie");
        }
        return new BasicResponse(false, "Session invalide");
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // MÉTHODES UTILITAIRES
    // ═══════════════════════════════════════════════════════════════════════════════

 private static void initializeDatabase() throws SQLException {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            String createUsers = 
    "CREATE TABLE IF NOT EXISTS users (" +
    "  username TEXT PRIMARY KEY," +
    "  password_hash TEXT NOT NULL," +
    "  salt TEXT NOT NULL," +
    "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
    ");";

            String createAccounts = 
    "CREATE TABLE IF NOT EXISTS accounts (" +
    "  id INTEGER PRIMARY KEY AUTOINCREMENT," +
    "  username TEXT NOT NULL," +
    "  compte TEXT NOT NULL," +
    "  account_username TEXT NOT NULL," +
    "  encrypted_password TEXT NOT NULL," +
    "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
    "  FOREIGN KEY(username) REFERENCES users(username)" +
    ");";

            conn.createStatement().execute(createUsers);
            conn.createStatement().execute(createAccounts);
        }
    }
    private static void generateServerKey() throws Exception {
        String secret = "0123456789abcdef0123456789abcdef"; // 32 caractères pour AES-256
    serverKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "AES");
    }

    private static String generateSalt() {
        SecureRandom rnd = new SecureRandom();
        byte[] salt = new byte[16];
        rnd.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private static String hash(String password, String salt) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(Base64.getDecoder().decode(salt));
        byte[] hashed = md.digest(password.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hashed);
    }

    private static String generateSessionToken() {
        SecureRandom rnd = new SecureRandom();
        byte[] t = new byte[32];
        rnd.nextBytes(t);
        return Base64.getEncoder().encodeToString(t);
    }

 // Encrypt
private static String encrypt(String plain) throws Exception {
    Cipher cipher = Cipher.getInstance(AES_CIPHER);
    byte[] iv = new byte[16];
    SecureRandom random = new SecureRandom();
    random.nextBytes(iv);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.ENCRYPT_MODE, serverKey, ivSpec);
    byte[] encrypted = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));

    // Préfixer l'IV au message chiffré, puis encoder en Base64
    byte[] combined = new byte[iv.length + encrypted.length];
    System.arraycopy(iv, 0, combined, 0, iv.length);
    System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
    return Base64.getEncoder().encodeToString(combined);
}

// Decrypt
private static String decrypt(String cipherText) throws Exception {
    byte[] combined = Base64.getDecoder().decode(cipherText);

    // Extraire l'IV (premiers 16 octets)
    byte[] iv = Arrays.copyOfRange(combined, 0, 16);
    byte[] encrypted = Arrays.copyOfRange(combined, 16, combined.length);

    Cipher cipher = Cipher.getInstance(AES_CIPHER);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(Cipher.DECRYPT_MODE, serverKey, ivSpec);

    byte[] decrypted = cipher.doFinal(encrypted);
    return new String(decrypted, StandardCharsets.UTF_8);
}

    private static String sanitize(String s) {
        if (s == null) return "";
        return s.replaceAll("[<>\"'%;()&+]", "");
    }

    private static boolean isValidUsername(String s) {
        return s != null && s.matches("^[a-zA-Z0-9_.-]{3,50}$");
    }

    private static boolean isValidPassword(String s) {
        return s != null && s.length() >= 6;
    }
}
