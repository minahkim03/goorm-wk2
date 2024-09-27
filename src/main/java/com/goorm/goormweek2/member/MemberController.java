package com.goorm.goormweek2.member;

import com.goorm.goormweek2.member.MemberDTO.GeneralDto;
import com.goorm.goormweek2.security.token.TokenDTO;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
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

    MemberService memberService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody GeneralDto memberDto) {
        memberService.register(memberDto.getEmail(), memberDto.getPassword());
        return ResponseEntity.ok("회원가입 성공");
    }

    @PostMapping("/login")
    public ResponseEntity<Cookie> login(@RequestBody GeneralDto generalDto) {
        TokenDTO token = memberService.login(generalDto.getEmail(), generalDto.getPassword());
        //쿠키로 변환해서 응답
        return ResponseEntity.ok();
    }

    @DeleteMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        //구현
        return ResponseEntity.ok("로그아웃 성공");
    }

    @GetMapping("/reissue")
    public ResponseEntity<Cookie> reissue(HttpServletRequest request) {
        //구현
        return ResponseEntity.ok();
    }

}