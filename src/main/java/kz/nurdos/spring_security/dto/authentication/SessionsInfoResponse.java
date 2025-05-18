package kz.nurdos.spring_security.dto.authentication;

import kz.nurdos.spring_security.dto.ApiResponse;

import java.time.Instant;
import java.util.List;

public class SessionsInfoResponse extends ApiResponse {
    private final List<Info> sessionsInfo;

    public SessionsInfoResponse(boolean success, String message, List<Info> sessionsInfo) {
        super(success, message);
        this.sessionsInfo = sessionsInfo;
    }

    public List<Info> getSessionsInfo() {
        return sessionsInfo;
    }

    //Point B: Should finally decide - Id or token? Data type?
    public record Info(String refreshTokenId, String deviceName, String ipAddress, String userAgent,
                       Instant createdAt, Instant lastUsedAt, Instant expiryDate, boolean isCurrentSession) {}
}
