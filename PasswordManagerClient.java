import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import javax.rmi.ssl.SslRMIServerSocketFactory;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import java.util.List;

/**
 * Client RMI avec interface graphique avancée pour le gestionnaire de mots de passe.
 * Version avec tableau et fonctionnalités complètes.
 */
public class PasswordManagerClient extends JFrame {
    // Nouvelles constantes pour SSL côté client
private static final String TRUSTSTORE_PATH = "truststore.p12"; // Même fichier que le serveur
private static final String TRUSTSTORE_PASSWORD = "managerpassword"; // Même mot de passe
   private static final String KEYSTORE_PATH = "keystore.p12";
private static final String KEYSTORE_PASSWORD = "managerpassword"; 
private static final String SERVER_HOST = "192.168.139.129"; // IP du serveur
private static final int RMI_PORT = 1099; // Port RMI standard
    private PasswordManagerRemote server;
    private String currentSessionToken;
    private String currentUser;
    
    // Composants GUI
    private JTextField serverField, portField, usernameField, searchField;
    private JPasswordField passwordField;
    private JButton connectButton, loginButton, registerButton;
    private JTextArea logArea;
    private JPanel mainPanel;
    private CardLayout cardLayout;
    
    // Composants pour le tableau des comptes
    private JTable accountsTable;
    private DefaultTableModel tableModel;
    private JButton addButton, viewButton, editButton, deleteButton, searchButton, refreshButton;
    
    private static void configureClientSSL() {
    try {
        // Configurer le trust store pour valider le certificat du serveur
        System.setProperty("javax.net.ssl.trustStore", TRUSTSTORE_PATH);
        System.setProperty("javax.net.ssl.trustStorePassword", TRUSTSTORE_PASSWORD);
         System.setProperty("javax.net.ssl.keyStore", KEYSTORE_PATH);
    System.setProperty("javax.net.ssl.keyStorePassword", KEYSTORE_PASSWORD);
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        
        // Optionnel : Configurer les protocoles SSL autorisés
        System.setProperty("https.protocols", "TLSv1.2,TLSv1.3");
        
        // Désactiver la vérification du hostname si nécessaire (pour les tests)
        // System.setProperty("com.sun.net.ssl.checkRevocation", "false");
        
        System.out.println("[CLIENT-SSL] Configuration SSL côté client terminée");
        
    } catch (Exception e) {
        System.err.println("[CLIENT-SSL] Erreur lors de la configuration SSL: " + e.getMessage());
        e.printStackTrace();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MÉTHODE DE CONNEXION RMI MODIFIÉE - REMPLACER VOTRE MÉTHODE DE CONNEXION
// ═══════════════════════════════════════════════════════════════════════════════

    

    public PasswordManagerClient() {
        super("Password Manager RMI Client - Enhanced");
        initializeGUI();
        initializeSSLConnection();
    }
     private void initializeSSLConnection() {
        try {
            // Configuration SSL
            configureClientSSL();
            
         
            
        } catch (Exception e) {
            System.err.println("Erreur d'initialisation SSL: " + e.getMessage());
            throw new RuntimeException("Impossible d'établir une connexion SSL", e);
        }
    }
    private void initializeGUI() {
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1000, 700);
        setLocationRelativeTo(null);
        
        cardLayout = new CardLayout();
        mainPanel = new JPanel(cardLayout);
        
        // Panel de connexion au serveur
        JPanel connectionPanel = createConnectionPanel();
        mainPanel.add(connectionPanel, "CONNECTION");
        
        // Panel de login/register
        JPanel authPanel = createAuthPanel();
        mainPanel.add(authPanel, "AUTH");
        
        // Panel principal (après connexion)
        JPanel appPanel = createAppPanel();
        mainPanel.add(appPanel, "APP");
        
        add(mainPanel);
        cardLayout.show(mainPanel, "CONNECTION");
    }
    
    private JPanel createConnectionPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // Titre
        JLabel title = new JLabel("Connexion au serveur RMI", JLabel.CENTER);
        title.setFont(new Font("Segoe UI", Font.BOLD, 18));
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        form.add(title, gbc);
        
        // Serveur
        gbc.gridwidth = 1; gbc.gridy++;
        gbc.gridx = 0; form.add(new JLabel("Serveur:"), gbc);
        gbc.gridx = 1; 
        serverField = new JTextField("localhost", 15);
        form.add(serverField, gbc);
        
        // Port
        gbc.gridy++;
        gbc.gridx = 0; form.add(new JLabel("Port:"), gbc);
        gbc.gridx = 1;
        portField = new JTextField("1099", 15);
        form.add(portField, gbc);
        
        // Bouton de connexion
        gbc.gridy++; gbc.gridx = 0; gbc.gridwidth = 2;
        connectButton = new JButton("Se connecter au serveur");
        connectButton.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        connectButton.addActionListener(this::connectToServer);
        form.add(connectButton, gbc);
        
        panel.add(form, BorderLayout.CENTER);
        
        // Zone de log
        logArea = new JTextArea(8, 50);
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("Logs"));
        panel.add(logScroll, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createAuthPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        
        // Titre
        JLabel title = new JLabel("Authentification", JLabel.CENTER);
        title.setFont(new Font("Segoe UI", Font.BOLD, 18));
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        form.add(title, gbc);
        
        // Username
        gbc.gridwidth = 1; gbc.gridy++;
        gbc.gridx = 0; form.add(new JLabel("Nom d'utilisateur:"), gbc);
        gbc.gridx = 1;
        usernameField = new JTextField(15);
        form.add(usernameField, gbc);
        
        // Password
        gbc.gridy++;
        gbc.gridx = 0; form.add(new JLabel("Mot de passe:"), gbc);
        gbc.gridx = 1;
        passwordField = new JPasswordField(15);
        form.add(passwordField, gbc);
        
        // Boutons
        gbc.gridy++; gbc.gridx = 0;
        loginButton = new JButton("Se connecter");
        loginButton.addActionListener(this::login);
        form.add(loginButton, gbc);
        
        gbc.gridx = 1;
        registerButton = new JButton("S'enregistrer");
        registerButton.addActionListener(this::register);
        form.add(registerButton, gbc);
        
        // Bouton retour
        gbc.gridy++; gbc.gridx = 0; gbc.gridwidth = 2;
        JButton backButton = new JButton("← Retour à la connexion serveur");
        backButton.addActionListener(e -> {
            server = null;
            cardLayout.show(mainPanel, "CONNECTION");
            connectButton.setEnabled(true);
        });
        form.add(backButton, gbc);
        
        panel.add(form, BorderLayout.CENTER);
        return panel;
    }
    
    private JPanel createAppPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Barre d'outils supérieure
        JPanel topToolbar = new JPanel(new BorderLayout());
        
        // Barre de recherche
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchPanel.add(new JLabel("Rechercher:"));
        searchField = new JTextField(20);
        searchButton = new JButton("🔍");
        searchButton.addActionListener(this::searchAccounts);
        
        // Permettre la recherche avec Entrée
        searchField.addActionListener(this::searchAccounts);
        
        searchPanel.add(searchField);
        searchPanel.add(searchButton);
        
        // Boutons d'action
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        refreshButton = new JButton("Actualiser");
        JButton logoutButton = new JButton("Déconnexion");
        
        refreshButton.addActionListener(e -> loadAccounts());
        logoutButton.addActionListener(e -> logout());
        
        actionPanel.add(refreshButton);
        actionPanel.add(logoutButton);
        
        topToolbar.add(searchPanel, BorderLayout.WEST);
        topToolbar.add(actionPanel, BorderLayout.EAST);
        
        panel.add(topToolbar, BorderLayout.NORTH);
        
        // Tableau des comptes
        String[] columnNames = {"ID", "Service", "Utilisateur", "Notes", "Date création"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Empêcher l'édition directe
            }
        };
        
        accountsTable = new JTable(tableModel);
        accountsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        accountsTable.getTableHeader().setReorderingAllowed(false);
        
        // Ajuster la largeur des colonnes
        accountsTable.getColumnModel().getColumn(0).setPreferredWidth(50);  // ID
        accountsTable.getColumnModel().getColumn(1).setPreferredWidth(150); // Service
        accountsTable.getColumnModel().getColumn(2).setPreferredWidth(150); // Utilisateur
        accountsTable.getColumnModel().getColumn(3).setPreferredWidth(200); // Notes
        accountsTable.getColumnModel().getColumn(4).setPreferredWidth(150); // Date
        
        // Double-clic pour voir les détails
        accountsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    viewAccountDetails();
                }
            }
        });
        
        JScrollPane tableScrollPane = new JScrollPane(accountsTable);
        tableScrollPane.setBorder(BorderFactory.createTitledBorder("Mes comptes"));
        panel.add(tableScrollPane, BorderLayout.CENTER);
        
        // Barre d'outils inférieure
        JPanel bottomToolbar = new JPanel(new FlowLayout());
        
        addButton = new JButton("Ajouter");
        viewButton = new JButton("Voir détails");
        editButton = new JButton("Modifier");
        deleteButton = new JButton("Supprimer");
        
        addButton.addActionListener(e -> showAddAccountDialog());
        viewButton.addActionListener(e -> viewAccountDetails());
        editButton.addActionListener(e -> editSelectedAccount());
        deleteButton.addActionListener(e -> deleteSelectedAccount());
        
        bottomToolbar.add(addButton);
        bottomToolbar.add(viewButton);
        bottomToolbar.add(editButton);
        bottomToolbar.add(deleteButton);
        
        // Désactiver les boutons qui nécessitent une sélection
        viewButton.setEnabled(false);
        editButton.setEnabled(false);
        deleteButton.setEnabled(false);
        
        // Écouter les changements de sélection
        accountsTable.getSelectionModel().addListSelectionListener(e -> {
            boolean hasSelection = accountsTable.getSelectedRow() != -1;
            viewButton.setEnabled(hasSelection);
            editButton.setEnabled(hasSelection);
            deleteButton.setEnabled(hasSelection);
        });
        
        panel.add(bottomToolbar, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append("[" + new java.util.Date() + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    
    }

    
    private void connectToServer(ActionEvent e)   // Méthode appelée par le bouton (ActionListener)
{
    String serverHost = serverField.getText().trim();
    String portText = portField.getText().trim();
    
    if (serverHost.isEmpty() || portText.isEmpty()) {
        log("Veuillez remplir tous les champs");
        return;
    }
     
    int port;
    try {
        port = Integer.parseInt(portText);
    } catch (NumberFormatException ex) {
        log("Port invalide: " + portText);
        return;
    }
    
    connectButton.setEnabled(false);
    connectButton.setText("Connexion SSL en cours...");
    
    SwingWorker<Boolean, String> worker = new SwingWorker<Boolean, String>() {
        @Override
        protected Boolean doInBackground() throws Exception {
         try {
    configureClientSSL();
    Registry registry = LocateRegistry.getRegistry(serverHost, port);
    server = (PasswordManagerRemote) registry.lookup("PasswordManagerService");
    server.toString();
    return true;
} catch (Exception ex) {
    publish("Erreur de connexion: " + ex.getMessage());
    return false;
}
  }
        
        @Override
        protected void process(java.util.List<String> chunks) {
            for (String message : chunks) {
                log(message);
            }
        }
        
        @Override
        protected void done() {
            try {
                Boolean success = get();
                if (success) {
                    connectButton.setText("Connecté (SSL)");
                    connectButton.setEnabled(false);
                        cardLayout.show(mainPanel, "AUTH");
                        usernameField.requestFocus();
                    
                    // Activer les autres composants de l'interface
                    // enableMainInterface(); // Si vous avez cette méthode
                    
                } else {
                    connectButton.setText("Se connecter");
                    connectButton.setEnabled(true);
                }
            } catch (Exception ex) {
                log("Erreur inattendue: " + ex.getMessage());
                connectButton.setText("Se connecter");
                connectButton.setEnabled(true);
            }
        }
    };
    
    worker.execute();
}

 private void login(ActionEvent e) {
        if (server == null) {
            log("Pas de connexion au serveur");
            return;
        }
        
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());
        
        if (username.isEmpty() || password.isEmpty()) {
            log("Veuillez remplir tous les champs");
            return;
        }
        
        setAuthButtonsEnabled(false);
        
        SwingWorker<LoginResponse, String> worker = new SwingWorker<LoginResponse, String>() {
            @Override
            protected LoginResponse doInBackground() throws Exception {
                publish("Tentative de connexion pour: " + username);
                return server.login(username, password);
            }
            
            @Override
            protected void process(List<String> chunks) {
                for (String message : chunks) {
                    log(message);
                }
            }
            
            @Override
            protected void done() {
                try {
                    LoginResponse response = get();
                    
                    if (response.success) {
                        currentSessionToken = response.sessionToken;
                        currentUser = username;
                        log("Connexion réussie!");
                        
                        cardLayout.show(mainPanel, "APP");
                        setTitle("Password Manager - " + currentUser);
                        loadAccounts();
                        
                        passwordField.setText("");
                        
                    } else {
                        log("Échec de la connexion: " + response.message);
                        setAuthButtonsEnabled(true);
                    }
                } catch (Exception ex) {
                    log("Erreur lors de la connexion: " + ex.getMessage());
                    setAuthButtonsEnabled(true);
                }
            }
        };
        
        worker.execute();
    }


    
  
    
    private void register(ActionEvent e) {
        if (server == null) {
            log("Pas de connexion au serveur");
            return;
        }
        
        String username = usernameField.getText().trim();
        String password = new String(passwordField.getPassword());
        
        if (username.isEmpty() || password.isEmpty()) {
            log("Veuillez remplir tous les champs");
            return;
        }
        
        if (password.length() < 6) {
            log("Le mot de passe doit contenir au moins 6 caractères");
            return;
        }
        
        setAuthButtonsEnabled(false);
        
        SwingWorker<RegisterResponse, String> worker = new SwingWorker<RegisterResponse, String>() {
            @Override
            protected RegisterResponse doInBackground() throws Exception {
                publish("Tentative d'enregistrement pour: " + username);
                return server.register(username, password);
            }
            
            @Override
            protected void process(List<String> chunks) {
                for (String message : chunks) {
                    log(message);
                }
            }
            
            @Override
            protected void done() {
                try {
                    RegisterResponse response = get();
                    
                    if (response.success) {
                        log("Enregistrement réussi! Vous pouvez maintenant vous connecter.");
                        passwordField.setText("");
                    } else {
                        log("Échec de l'enregistrement: " + response.message);
                    }
                    
                    setAuthButtonsEnabled(true);
                    
                } catch (Exception ex) {
                    log("Erreur lors de l'enregistrement: " + ex.getMessage());
                    setAuthButtonsEnabled(true);
                }
            }
        };
        
        worker.execute();
    }
    
    private void setAuthButtonsEnabled(boolean enabled) {
        loginButton.setEnabled(enabled);
        registerButton.setEnabled(enabled);
        loginButton.setText(enabled ? "Se connecter" : "Connexion...");
        registerButton.setText(enabled ? "S'enregistrer" : "Enregistrement...");
    }
    
    private void loadAccounts() {
        if (server == null || currentSessionToken == null) return;
        
        SwingWorker<AccountListResponse, String> worker = new SwingWorker<AccountListResponse, String>(){
            @Override
            protected AccountListResponse doInBackground() throws Exception {
                return server.getAccounts(currentSessionToken);
            }
            
            @Override
            protected void done() {
                try {
                    AccountListResponse response = get();
                    
                    if (response.success) {
                        updateAccountsTable(response.accounts);
                        log("Comptes chargés: " + (response.accounts != null ? response.accounts.size() : 0) + " comptes");
                        
                    } else {
                        log("Erreur lors du chargement: " + response.message);
                        if (response.message.contains("Session invalide")) {
                            returnToAuth();
                        }
                    }
                } catch (Exception ex) {
                    log("Erreur lors du chargement des comptes: " + ex.getMessage());
                }
            }
        };
        
        worker.execute();
    }
    
    private void updateAccountsTable(List<Account> accounts) {
        // Vider le tableau
        tableModel.setRowCount(0);
        
        if (accounts != null && !accounts.isEmpty()) {
            for (Account account : accounts) {
                Object[] row = {
                    account.id,
                    account.compte,
                    account.accountUsername,
                    account.notes != null ? account.notes : "",
                    "N/A" // Date de création pas encore disponible dans l'interface
                };
                tableModel.addRow(row);
            }
        }
    }
    
    private void searchAccounts(ActionEvent e) {
        String searchTerm = searchField.getText().trim();
        if (searchTerm.isEmpty()) {
            loadAccounts(); // Recharger tous les comptes
            return;
        }
        
        if (server == null || currentSessionToken == null) return;
        
        SwingWorker<AccountListResponse, String> worker = new SwingWorker<AccountListResponse, String>() {
            @Override
            protected AccountListResponse doInBackground() throws Exception {
                return server.searchAccounts(currentSessionToken, searchTerm);
            }
            
            @Override
            protected void done() {
                try {
                    AccountListResponse response = get();
                    
                    if (response.success) {
                        updateAccountsTable(response.accounts);
                        log("Recherche terminée: " + (response.accounts != null ? response.accounts.size() : 0) + " résultats pour '" + searchTerm + "'");
                        
                    } else {
                        log("Erreur lors de la recherche: " + response.message);
                    }
                } catch (Exception ex) {
                    log("Erreur lors de la recherche: " + ex.getMessage());
                }
            }
        };
        
        worker.execute();
    }
    
    private void viewAccountDetails() {
        int selectedRow = accountsTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, "Veuillez sélectionner un compte");
            return;
        }
        
        int accountId = (Integer) tableModel.getValueAt(selectedRow, 0);
        
        SwingWorker<PasswordResponse, Void> worker = new SwingWorker<PasswordResponse, Void>() {
            @Override
            protected PasswordResponse doInBackground() throws Exception {
                return server.getPassword(currentSessionToken, accountId);
            }
            
            @Override
            protected void done() {
                try {
                    PasswordResponse response = get();
                    
                    if (response.success) {
                        showAccountDetailsDialog(selectedRow, response.password);
                    } else {
                        JOptionPane.showMessageDialog(PasswordManagerClient.this, 
                            "Erreur lors de la récupération du mot de passe: " + response.message);
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(PasswordManagerClient.this, 
                        "Erreur: " + ex.getMessage());
                }
            }
        };
        
        worker.execute();
    }
    
    private void showAccountDetailsDialog(int tableRow, String password) {
        JDialog dialog = new JDialog(this, "Détails du compte", true);
        dialog.setSize(400, 300);
        dialog.setLocationRelativeTo(this);
        
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Récupérer les données du tableau
        Object[] rowData = new Object[tableModel.getColumnCount()];
        for (int i = 0; i < tableModel.getColumnCount(); i++) {
            rowData[i] = tableModel.getValueAt(tableRow, i);
        }
        
        gbc.gridx = 0; gbc.gridy = 0; panel.add(new JLabel("ID:"), gbc);
        gbc.gridx = 1; panel.add(new JLabel(rowData[0].toString()), gbc);
        
        gbc.gridx = 0; gbc.gridy = 1; panel.add(new JLabel("Service:"), gbc);
        gbc.gridx = 1; panel.add(new JLabel(rowData[1].toString()), gbc);
        
        gbc.gridx = 0; gbc.gridy = 2; panel.add(new JLabel("Utilisateur:"), gbc);
        gbc.gridx = 1; panel.add(new JLabel(rowData[2].toString()), gbc);
        
        gbc.gridx = 0; gbc.gridy = 3; panel.add(new JLabel("Mot de passe:"), gbc);
        JTextField passwordField = new JTextField(password, 20);
        passwordField.setEditable(false);
        gbc.gridx = 1; panel.add(passwordField, gbc);
        
        gbc.gridx = 0; gbc.gridy = 4; panel.add(new JLabel("Notes:"), gbc);
        JTextArea notesArea = new JTextArea(rowData[3].toString(), 3, 20);
        notesArea.setEditable(false);
        notesArea.setBackground(panel.getBackground());
        gbc.gridx = 1; panel.add(new JScrollPane(notesArea), gbc);
        
        JPanel buttons = new JPanel();
        JButton copyPasswordButton = new JButton("Copier le mot de passe");
        JButton closeButton = new JButton("Fermer");
        
        copyPasswordButton.addActionListener(e -> {
            java.awt.datatransfer.StringSelection stringSelection = 
                new java.awt.datatransfer.StringSelection(password);
            java.awt.datatransfer.Clipboard clipboard = 
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
            JOptionPane.showMessageDialog(dialog, "Mot de passe copié dans le presse-papiers!");
        });
        
        closeButton.addActionListener(e -> dialog.dispose());
        
        buttons.add(copyPasswordButton);
        buttons.add(closeButton);
        
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 2;
        panel.add(buttons, gbc);
        
        dialog.add(panel);
        dialog.setVisible(true);
    }
    
    private void editSelectedAccount() {
        int selectedRow = accountsTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, "Veuillez sélectionner un compte");
            return;
        }
        
        int accountId = (Integer) tableModel.getValueAt(selectedRow, 0);
        String currentService = tableModel.getValueAt(selectedRow, 1).toString();
        String currentUsername = tableModel.getValueAt(selectedRow, 2).toString();
        String currentNotes = tableModel.getValueAt(selectedRow, 3).toString();
        
        // Récupérer d'abord le mot de passe actuel
        SwingWorker<PasswordResponse, Void> worker = new SwingWorker<PasswordResponse, Void>() {
            @Override
            protected PasswordResponse doInBackground() throws Exception {
                return server.getPassword(currentSessionToken, accountId);
            }
            
            @Override
            protected void done() {
                try {
                    PasswordResponse response = get();
                    
                    if (response.success) {
                        showEditAccountDialog(accountId, currentService, currentUsername, 
                                            response.password, currentNotes);
                    } else {
                        JOptionPane.showMessageDialog(PasswordManagerClient.this, 
                            "Erreur lors de la récupération du mot de passe: " + response.message);
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(PasswordManagerClient.this, 
                        "Erreur: " + ex.getMessage());
                }
            }
        };
        
        worker.execute();
    }
  private void returnToAuth() {
        currentSessionToken = null;
        currentUser = null;
        cardLayout.show(mainPanel, "AUTH");
        setTitle("Password Manager RMI Client");
        usernameField.setText("");
        passwordField.setText("");
    }
    
    private void showAddAccountDialog() {
        JDialog dialog = new JDialog(this, "Ajouter un compte", true);
        dialog.setSize(400, 300);
        dialog.setLocationRelativeTo(this);
        
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        
        JTextField serviceField = new JTextField(20);
        JTextField userField = new JTextField(20);
        JPasswordField passField = new JPasswordField(20);
        JTextField notesField = new JTextField(20);
        
        gbc.gridx = 0; gbc.gridy = 0; panel.add(new JLabel("Service:"), gbc);
        gbc.gridx = 1; panel.add(serviceField, gbc);
        
        gbc.gridx = 0; gbc.gridy = 1; panel.add(new JLabel("Utilisateur:"), gbc);
        gbc.gridx = 1; panel.add(userField, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2; panel.add(new JLabel("Mot de passe:"), gbc);
        gbc.gridx = 1; panel.add(passField, gbc);
        
        gbc.gridx = 0; gbc.gridy = 3; panel.add(new JLabel("Notes:"), gbc);
        gbc.gridx = 1; panel.add(notesField, gbc);
        
        JPanel buttons = new JPanel();
        JButton saveButton = new JButton("Sauvegarder");
        JButton cancelButton = new JButton("Annuler");
        
        saveButton.addActionListener(e -> {
            String service = serviceField.getText().trim();
            String user = userField.getText().trim();
            String pass = new String(passField.getPassword());
            String notes = notesField.getText().trim();
            
            if (service.isEmpty() || user.isEmpty() || pass.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, "Veuillez remplir les champs obligatoires");
                return;
            }
            
            saveButton.setEnabled(false);
            saveButton.setText("Sauvegarde...");
            
            SwingWorker<BasicResponse, Void> worker = new SwingWorker<BasicResponse, Void>() {
                @Override
                protected BasicResponse doInBackground() throws Exception {
                    return server.createAccount(currentSessionToken, service, user, pass, notes);
                }
                
                @Override
                protected void done() {
                    try {
                        BasicResponse response = get();
                        
                        if (response.success) {
                            log("Compte créé avec succès!");
                            dialog.dispose();
                            loadAccounts();
                        } else {
                            log("Erreur lors de la création: " + response.message);
                            saveButton.setEnabled(true);
                            saveButton.setText("Sauvegarder");
                        }
                    } catch (Exception ex) {
                        log("Erreur: " + ex.getMessage());
                        saveButton.setEnabled(true);
                        saveButton.setText("Sauvegarder");
                    }
                }
            };
            
            worker.execute();
        });
        
        cancelButton.addActionListener(e -> dialog.dispose());
        
        buttons.add(saveButton);
        buttons.add(cancelButton);
        
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        panel.add(buttons, gbc);
        
        dialog.add(panel);
        dialog.setVisible(true);
    }

private void deleteSelectedAccount() {
    int selectedRow = accountsTable.getSelectedRow();
    if (selectedRow == -1) {
        JOptionPane.showMessageDialog(this, "Veuillez sélectionner un compte");
        return;
    }
    
    int accountId = (Integer) tableModel.getValueAt(selectedRow, 0);
    String serviceName = tableModel.getValueAt(selectedRow, 1).toString();
    
    // Demander confirmation
    int result = JOptionPane.showConfirmDialog(
        this,
        "Êtes-vous sûr de vouloir supprimer le compte '" + serviceName + "' ?\n" +
        "Cette action est irréversible.",
        "Confirmer la suppression",
        JOptionPane.YES_NO_OPTION,
        JOptionPane.WARNING_MESSAGE
    );
    
    if (result != JOptionPane.YES_OPTION) {
        return;
    }
    
    // Désactiver temporairement le bouton de suppression
    deleteButton.setEnabled(false);
    deleteButton.setText("Suppression...");
    
    SwingWorker<BasicResponse, Void> worker = new SwingWorker<BasicResponse, Void>() {
        @Override
        protected BasicResponse doInBackground() throws Exception {
            return server.deleteAccount(currentSessionToken, accountId);
        }
        
        @Override
        protected void done() {
            try {
                BasicResponse response = get();
                
                if (response.success) {
                    log("Compte '" + serviceName + "' supprimé avec succès!");
                    loadAccounts(); // Recharger la liste
                } else {
                    log("Erreur lors de la suppression: " + response.message);
                    JOptionPane.showMessageDialog(PasswordManagerClient.this, 
                        "Erreur lors de la suppression: " + response.message);
                }
            } catch (Exception ex) {
                log("Erreur lors de la suppression: " + ex.getMessage());
                JOptionPane.showMessageDialog(PasswordManagerClient.this, 
                    "Erreur: " + ex.getMessage());
            } finally {
                // Réactiver le bouton (si une ligne est toujours sélectionnée)
                boolean hasSelection = accountsTable.getSelectedRow() != -1;
                deleteButton.setEnabled(hasSelection);
                deleteButton.setText("Supprimer");
            }
        }
    };
    
    worker.execute();
}

private void showEditAccountDialog(int accountId, String service, String username, String password, String notes) {
    JDialog dialog = new JDialog(this, "Modifier le compte", true);
    dialog.setSize(400, 350);
    dialog.setLocationRelativeTo(this);
    
    JPanel panel = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.insets = new Insets(5, 5, 5, 5);
    
    // Champs pré-remplis avec les valeurs actuelles
    JTextField serviceField = new JTextField(service, 20);
    JTextField userField = new JTextField(username, 20);
    JPasswordField passField = new JPasswordField(password, 20);
    JTextField notesField = new JTextField(notes, 20);
    
    gbc.gridx = 0; gbc.gridy = 0; 
    gbc.anchor = GridBagConstraints.WEST;
    panel.add(new JLabel("Service:"), gbc);
    gbc.gridx = 1; panel.add(serviceField, gbc);
    
    gbc.gridx = 0; gbc.gridy = 1; panel.add(new JLabel("Utilisateur:"), gbc);
    gbc.gridx = 1; panel.add(userField, gbc);
    
    gbc.gridx = 0; gbc.gridy = 2; panel.add(new JLabel("Mot de passe:"), gbc);
    gbc.gridx = 1; panel.add(passField, gbc);
    
    gbc.gridx = 0; gbc.gridy = 3; panel.add(new JLabel("Notes:"), gbc);
    gbc.gridx = 1; panel.add(notesField, gbc);
    
    // Bouton pour générer un nouveau mot de passe
    JPanel passwordPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
    JButton generateButton = new JButton("Générer");
    generateButton.setPreferredSize(new Dimension(80, 25));
    generateButton.addActionListener(e -> {
        String newPassword = generateRandomPassword();
        passField.setText(newPassword);
    });
    passwordPanel.add(generateButton);
    
    gbc.gridx = 1; gbc.gridy = 4; 
    gbc.anchor = GridBagConstraints.WEST;
    panel.add(passwordPanel, gbc);
    
    // Boutons d'action
    JPanel buttons = new JPanel();
    JButton saveButton = new JButton("Sauvegarder");
    JButton cancelButton = new JButton("Annuler");
    
    saveButton.addActionListener(e -> {
        String newService = serviceField.getText().trim();
        String newUser = userField.getText().trim();
        String newPass = new String(passField.getPassword());
        String newNotes = notesField.getText().trim();
        
        if (newService.isEmpty() || newUser.isEmpty() || newPass.isEmpty()) {
            JOptionPane.showMessageDialog(dialog, "Veuillez remplir les champs obligatoires");
            return;
        }
        
        saveButton.setEnabled(false);
        saveButton.setText("Sauvegarde...");
        
        SwingWorker<BasicResponse, Void> worker = new SwingWorker<BasicResponse, Void>() {
            @Override
            protected BasicResponse doInBackground() throws Exception {
                return server.updateAccount(currentSessionToken, accountId, newService, newUser, newPass, newNotes);
            }
            
            @Override
            protected void done() {
                try {
                    BasicResponse response = get();
                    
                    if (response.success) {
                        log("Compte modifié avec succès!");
                        dialog.dispose();
                        loadAccounts(); // Recharger la liste pour voir les modifications
                    } else {
                        log("Erreur lors de la modification: " + response.message);
                        JOptionPane.showMessageDialog(dialog, 
                            "Erreur lors de la modification: " + response.message);
                        saveButton.setEnabled(true);
                        saveButton.setText("Sauvegarder");
                    }
                } catch (Exception ex) {
                    log("Erreur: " + ex.getMessage());
                    JOptionPane.showMessageDialog(dialog, "Erreur: " + ex.getMessage());
                    saveButton.setEnabled(true);
                    saveButton.setText("Sauvegarder");
                }
            }
        };
        
        worker.execute();
    });
    
    cancelButton.addActionListener(e -> dialog.dispose());
    
    buttons.add(saveButton);
    buttons.add(cancelButton);
    
    gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 2;
    gbc.anchor = GridBagConstraints.CENTER;
    panel.add(buttons, gbc);
    
    dialog.add(panel);
    dialog.setVisible(true);
}

// Méthode utilitaire pour générer un mot de passe aléatoire
private String generateRandomPassword() {
    String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    StringBuilder password = new StringBuilder();
    java.util.Random random = new java.util.Random();
    
    for (int i = 0; i < 12; i++) {
        password.append(chars.charAt(random.nextInt(chars.length())));
    }
    
    return password.toString();
}
    
    private void logout() {
        if (server != null && currentSessionToken != null) {
            SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
                @Override
                protected Void doInBackground() throws Exception {
                    try {
                        server.logout(currentSessionToken);
                        log("Déconnexion réussie");
                    } catch (Exception ex) {
                        log("Erreur lors de la déconnexion: " + ex.getMessage());
                    }
                    return null;
                }
                
                @Override
                protected void done() {
                    returnToAuth();
                }
            };
            worker.execute();
        } else {
            returnToAuth();
        }
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

            } catch (Exception e) {
                // Ignorer
            }
            new PasswordManagerClient().setVisible(true);
        });
    }
}
