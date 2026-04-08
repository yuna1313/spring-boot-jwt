package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true); // 서버가 응답을 할 때, json을 자바스크립트에서 처리할 수 있게 하는 지 여부 (ex. ajax)
        config.setAllowedOriginPatterns(List.of("*")); // 모든 IP의 응답을 허용
        config.setAllowedHeaders(List.of("*")); // 모든 header의 응답을 허용
        config.setAllowedMethods(List.of("*")); // 모든 메소드 (get, post, put, patch, delete)의 요청을 허용

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);

        return source;
    }
}
