import java.io.Serializable;

public class BasicResponse implements Serializable {
    private static final long serialVersionUID = 1L;
    
    public final boolean success;
    public final String message;
    
    public BasicResponse(boolean success, String message) {
        this.success = success;
        this.message = message;
    }
}
