public class PasswordResponse extends BasicResponse {
    private static final long serialVersionUID = 1L;

    public final String password;

    public PasswordResponse(boolean success, String message, String password) {
        super(success, message);
        this.password = password;
    }

    public PasswordResponse(boolean success, String message) {
        this(success, message, null);
    }
}
