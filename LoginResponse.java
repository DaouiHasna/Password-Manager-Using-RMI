public class LoginResponse extends BasicResponse {
    private static final long serialVersionUID = 1L;

    public final String sessionToken;

    public LoginResponse(boolean success, String message, String sessionToken) {
        super(success, message);
        this.sessionToken = sessionToken;
    }

    public LoginResponse(boolean success, String message) {
        this(success, message, null);
    }
}
