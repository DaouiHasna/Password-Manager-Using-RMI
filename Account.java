import java.io.Serializable;

public class Account implements Serializable {
    private static final long serialVersionUID = 1L;

    public final int id;
    public final String compte;
    public final String accountUsername;
    public final String notes;

    public Account(int id, String compte, String accountUsername, String notes) {
        this.id = id;
        this.compte = compte;
        this.accountUsername = accountUsername;
        this.notes = notes;
    }
}
