package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

// POST /login을 요청하여 id, pw 전달하면 UsernamePasswordAuthenticationFilter가 동작을 함
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("[JwtAuthenticationFilter] 로그인 시도 중");

        // 1. username, password 받기
        try {
//            BufferedReader bufferedReader = request.getReader();
//
//            String input;
//            while((input = bufferedReader.readLine()) != null) {
//                System.out.println(input);
//            }
            ObjectMapper objectMapper = new ObjectMapper();
            User user = objectMapper.readValue(request.getInputStream(), User.class);
            log.info("[JwtAuthenticationFilter] User: {}", user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication에 로그인 정보가 담김
            // DB에 있는 username과 password가 일치
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 로그인이 되었다는 것을 의미
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            log.info("[JwtAuthenticationFilter] principalDetails: {}", principalDetails.getUser().getUsername());

            // authentication 객체가 session 영역에 저장
            // authentication return의 이유는 권한 관리를 security가 대신 해주기 때문
            return authentication;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되면, successfulAuthentication 함수 실행
    // JWT 토큰을 만들어서 사용자에게 response
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos토큰") // 크게 의미는 없음
                .withExpiresAt(new Date(System.currentTimeMillis() + (1000 * 10 * 6 * 10))) // 만료 시간 (10분)
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos")); // 고유한 secret 값

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
