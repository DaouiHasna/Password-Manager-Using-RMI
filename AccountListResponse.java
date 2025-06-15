import java.util.List;

public class AccountListResponse extends BasicResponse {
    private static final long serialVersionUID = 1L;

    public final List<Account> accounts;

    public AccountListResponse(boolean success, String message, List<Account> accounts) {
        super(success, message);
        this.accounts = accounts;
    }

    public AccountListResponse(boolean success, String message) {
        this(success, message, null);
    }
}
