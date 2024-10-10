package com.goorm.goormweek2.member;

import com.goorm.goormweek2.member.MemberDTO.GeneralDto;
import com.goorm.goormweek2.security.config.CookieUtils;
import com.goorm.goormweek2.security.token.TokenDTO;
import com.goorm.goormweek2.security.token.TokenProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class MemberController {

    private final TokenProvider tokenProvider;
    MemberService memberService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody GeneralDto memberDto) {
        memberService.register(memberDto.getEmail(), memberDto.getPassword());
        return ResponseEntity.ok("회원가입 성공");
    }

    @PostMapping("/login")
    public ResponseEntity<Cookie> login(@RequestBody GeneralDto generalDto, HttpServletResponse response) {
        TokenDTO token = memberService.login(generalDto.getEmail(), generalDto.getPassword());
        Cookie cookie = new Cookie("access_token", token.getAccessToken());
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(60 * 30);
        response.addCookie(cookie);
        return ResponseEntity.ok(cookie);
    }

    @DeleteMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
        TokenDTO token = tokenProvider.resolveToken(request);
        memberService.logout(token.getAccessToken());
        CookieUtils.deleteCookie(request, response, "accessToken" );
        return ResponseEntity.ok("로그아웃 성공");
    }

    @GetMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
        TokenDTO token = tokenProvider.resolveToken(request);
        TokenDTO newToken = tokenProvider.reissueToken(token.getAccessToken(), request, response);
        Cookie cookie = new Cookie("access_token", newToken.getAccessToken());
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(60 * 30);
        response.addCookie(cookie);
        return ResponseEntity.ok(null);
    }

}