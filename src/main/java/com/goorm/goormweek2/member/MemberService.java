package com.goorm.goormweek2.member;

import com.goorm.goormweek2.security.token.TokenDTO;
import com.goorm.goormweek2.security.token.TokenProvider;
import com.goorm.goormweek2.security.token.TokenRedis;
import com.goorm.goormweek2.security.token.TokenRedisRepository;
import jakarta.transaction.Transactional;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
@Transactional
public class MemberService {
    private final BCryptPasswordEncoder encoder;
    private final MemberRepository memberRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenProvider tokenProvider;
    private final TokenRedisRepository tokenRedisRepository;
    private final RedisTemplate redisTemplate;

    //회원가입
    public void register(String email, String password) {
        String encryptedPassword = encoder.encode(password);
        Member member = Member.builder()
            .email(email)
            .password(encryptedPassword)
            .build();
        memberRepository.save(member);
    }

    //로그인
    @Transactional
    public TokenDTO login(String email, String password) {
        Member member = memberRepository.findByEmail(email)
            .orElseThrow(() -> new NoSuchElementException("Member with email " + email + " not found"));
        if (!encoder.matches(password, member.getPassword())) {
            throw new IllegalArgumentException("Invalid password");
        } else {
            UsernamePasswordAuthenticationToken token
                = new UsernamePasswordAuthenticationToken(email, password);
            Authentication authentication
                = authenticationManager.authenticate(token);
            TokenDTO jwtToken = tokenProvider.generateToken(authentication);
            tokenRedisRepository.save(
                new TokenRedis(authentication.getName(), jwtToken.getAccessToken(), jwtToken.getRefreshToken()));
            return jwtToken;
        }
    }

    //로그아웃
    public void logout(String token) {
        TokenRedis tokenRedis = tokenRedisRepository.findByAccessToken(token)
            .orElseThrow();
        Long expirationTime = tokenProvider.getRemainingExpirationTime(token);
        redisTemplate.opsForValue().set(token, "logout", expirationTime, TimeUnit.MILLISECONDS);
        tokenRedisRepository.delete(tokenRedis);
    }
}
