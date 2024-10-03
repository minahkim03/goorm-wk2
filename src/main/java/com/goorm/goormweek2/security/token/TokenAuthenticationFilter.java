package com.goorm.goormweek2.security.token;

import com.goorm.goormweek2.security.config.CookieUtils;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {
    private final TokenProvider tokenProvider;
    private final RedisTemplate redisTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {

        Optional<Cookie> accessToken = CookieUtils.getCookie((HttpServletRequest) request,"accessToken" );
        validBlackToken(String.valueOf(accessToken));
        if(accessToken.isPresent()) {
            boolean isValid = tokenProvider.validateToken(String.valueOf(accessToken.get().getValue()));
            UsernamePasswordAuthenticationToken authentication;
            if (isValid) {
                authentication = (UsernamePasswordAuthenticationToken) tokenProvider.getAuthentication(accessToken.get().getValue());
            }
        }

        filterChain.doFilter(request, response);
    }

    private void validBlackToken(String accessToken) {

        String blackToken = (String) redisTemplate.opsForValue().get(accessToken);
        if(StringUtils.hasText(blackToken))
            throw new Error("로그아웃 처리된 엑세스 토큰입니다.");
    }

}
