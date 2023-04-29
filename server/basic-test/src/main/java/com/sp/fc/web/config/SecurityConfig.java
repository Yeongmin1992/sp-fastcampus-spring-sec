package com.sp.fc.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter;

// security filter chain은 순서가 중요하여 여러개 사용할 경우라면 Order 머노테이션으로 순서 지정
// @Order(1)
@EnableWebSecurity(debug = true)
//prepost로 권한 체크를 하겠다
@EnableGlobalMethodSecurity(prePostEnabled = true)
// WebSecurityConfigurerAdapter가 어떤 security filter를 사용하여 chain을 구성할지 결정
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    DefaultLoginPageGeneratingFilter loginPageFilter;
    DefaultLogoutPageGeneratingFilter logoutPageFilter;

    // yaml파일에 작성 없이 user 생성
    // user에 대한 authentication provider를 추가하면 yaml 파일에 작성한 user 세팅은 먹지 않음
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser(User.builder()
                .username("user2")
                .password(passwordEncoder().encode("2222"))
                .roles("USER")
                ).withUser(User.builder()
                .username("admin")
                .password(passwordEncoder().encode("3333"))
                .roles("ADMIN")
        );
    }

    // password를 encoding 하지 않으면 오류남
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Spring security는 기본적으로 모든 접근을 막기 때문에
    // 홈페이지("/" 경로)와 같이 모든 접근을 우선 열어주고 싶을 때는 HttpSecurity를 사용
    protected void configure(HttpSecurity http) throws Exception {
        // 모든 request에 적용
        // http.antMatcher("/**")
        // 특정 api 하위에만 적용
        // http.antMatcher("api/**")
        http.authorizeRequests((requests) ->
                requests.antMatchers("/").permitAll()
                .anyRequest().authenticated()
        );
        http.formLogin();
        http.httpBasic();

        // form login
//        http
//                .headers().disable()
//                .csrf().disable()
//                .formLogin(login->
//                        // alwaysUse를 false로 주면 계속 루트 페이지로 가기 때문에 불편을 초래하게 됨
//                        login.defaultSuccessUrl("/", false)
//                        )
//                .logout().disable()
//                .requestCache().disable()
//                ;
    }
}
