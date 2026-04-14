package com.cos.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // id, pw의 값이 정상적으로 들어와서 로그인이 완료되면, 토큰을 만들어주고 해당 토큰을 전달한다.
        // 요청할 때마다 header -> Authorization의 value 값으로 토큰을 전달받는다.
        // 토큰이 넘어오면 검증을 진행한다. (RSA, HS256)
        if(request.getMethod().equals("POST")) {
            String headerAuth = request.getHeader("Authorization");
            System.out.println(headerAuth);

            // 임의로 토큰값을 cos라고 지정
            if(headerAuth.equals("cos")) {
                filterChain.doFilter(request, response);
            } else {
                // 인증되지 않을 경우, 해당 문구 return
                PrintWriter printWriter = response.getWriter();
                printWriter.println("인증되지 않음");
            }
        }

        System.out.println("필터3");
    }
}
