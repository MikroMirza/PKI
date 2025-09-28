package rs.tim33.PKI.Utils;

public enum RevocationReason {
    UNSPECIFIED(0),
    KEY_COMPROMISE(1),
    CA_COMPROMISE(2),
    AFFILIATION_CHANGED(3),
    SUPERSEDED(4),
    CESSATION_OF_OPERATION(5),
    CERTIFICATE_HOLD(6),
    REMOVE_FROM_CRL(8),
    PRIVILEGE_WITHDRAWN(9),
    AA_COMPROMISE(10);

    private final int code;

    RevocationReason(int code) { this.code = code; }
    public int getCode() { return code; }

    public static RevocationReason fromCode(int code) {
        for (RevocationReason r : values()) {
            if (r.code == code) return r;
        }
        throw new IllegalArgumentException("Unknown reason code: " + code);
    }
}
