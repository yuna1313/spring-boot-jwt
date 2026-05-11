package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.cos.jwt.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Date;

@Component
public class JwtTokenProvider {

    public static final String ACCESS_HEADER = "Authorization";
    public static final String REFRESH_COOKIE_NAME = "refreshToken";
    public static final String TOKEN_PREFIX = "Bearer ";

    private static final String ACCESS_TOKEN_SUBJECT = "accessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "refreshToken";

    private final String secret;
    private final Duration accessTokenExpirationTime;
    private final Duration refreshTokenExpirationTime;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiration-time}") Duration accessTokenExpirationTime,
            @Value("${jwt.refresh-token-expiration-time}") Duration refreshTokenExpirationTime
    ) {
        this.secret = secret;
        this.accessTokenExpirationTime = accessTokenExpirationTime;
        this.refreshTokenExpirationTime = refreshTokenExpirationTime;
    }

    // Access Token 생성
    public String createAccessToken(User user) {
        return JWT.create()
                .withSubject(ACCESS_TOKEN_SUBJECT)
                .withExpiresAt(new Date(System.currentTimeMillis() + accessTokenExpirationTime.toMillis()))
                .withClaim("id", user.getId())
                .withClaim("username", user.getUsername())
                .sign(Algorithm.HMAC512(secret));
    }

    // Refresh Token 생성
    public String createRefreshToken(User user) {
        return JWT.create()
                .withSubject(REFRESH_TOKEN_SUBJECT)
                .withExpiresAt(new Date(System.currentTimeMillis() + refreshTokenExpirationTime.toMillis()))
                .withClaim("id", user.getId())
                .withClaim("username", user.getUsername())
                .sign(Algorithm.HMAC512(secret));
    }

    // refresh token을 HttpOnly Cookie로 만들어 응답에 내려준다.
    public ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from(REFRESH_COOKIE_NAME, refreshToken)
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/api/v1/token")
                .maxAge(refreshTokenExpirationTime)
                .build();
    }

    // JWT 토큰 서명과 만료 시간을 검증한다.
    public DecodedJWT verify(String token) {
        return JWT.require(Algorithm.HMAC512(secret)).build().verify(token);
    }

    // 토큰에 담긴 username claim을 꺼낸다.
    public String getUsername(String token) {
        return verify(token).getClaim("username").asString();
    }

    // refresh token인지 subject 값으로 확인한다.
    public boolean isRefreshToken(String token) {
        return REFRESH_TOKEN_SUBJECT.equals(verify(token).getSubject());
    }

    // access token인지 subject 값으로 확인한다.
    public boolean isAccessToken(String token) {
        return ACCESS_TOKEN_SUBJECT.equals(verify(token).getSubject());
    }

    // Bearer 인증 헤더에서 실제 JWT 토큰 문자열만 추출한다.
    public static String resolveToken(String header) {
        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            return null;
        }

        return header.replace(TOKEN_PREFIX, "");
    }
}
