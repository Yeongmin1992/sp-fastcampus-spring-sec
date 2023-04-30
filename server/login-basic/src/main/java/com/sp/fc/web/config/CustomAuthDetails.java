package com.sp.fc.web.config;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;

@Component
public class CustomAuthDetails implements AuthenticationDetailsSource<HttpServletRequest, RequestInfo> {

    // 로그인시 request에서 RequestInfo의 정보를 얻을 수 있도록(ex. ip, login 시간 등)
    @Override
    public RequestInfo buildDetails(HttpServletRequest request) {
        return RequestInfo.builder()
                // ip의 경우 proxy를 타면 변경될 수 있어 추가 조작 필요
                .remoteIp(request.getRemoteAddr())
                .sessionId(request.getSession().getId())
                .loginTime(LocalDateTime.now())
                .build();
    }
}
