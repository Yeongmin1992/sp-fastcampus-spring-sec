package com.sp.fc.web.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;

@EnableWebSecurity(debug = true)
// conroller에서 PreAuthorize로 정해준 role에 따라 화면이 보임
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomAuthDetails customAuthDetails;

    public SecurityConfig(CustomAuthDetails customAuthDetails) {
        this.customAuthDetails = customAuthDetails;
    }
    // 로그인이 튕기거나 잘 안될 때는 아래와 같이 username password를 직접 디버깅해보는 것이 좋음
    // 아래 클래스에서 username 디버깅
    UsernamePasswordAuthenticationFilter filter;
    // csrf filter에 걸려 위의 username에 들어가지 못한다 -> csrf filter 디버깅
    // csrfToken이 null이어서 문제 발생
    // resources -> templates -> loginFrom.html에서 thymleaf의 action을 아래와 같이 변경해주면
    // 자동으로 scrf토큰 생성
    // th:action="@{/login}"
    CsrfFilter csrfFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser(
                        User.withDefaultPasswordEncoder()
                            .username("user1")
                            .password("1111")
                            .roles("USER")
                ).withUser(
                        User.withDefaultPasswordEncoder()
                            .username("admin")
                            .password("2222")
                            .roles("ADMIN")
        );
    }

    // admin이 user 페이지도 접근 가능하게
   @Bean
   RoleHierarchy roleHierarchy(){
       RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
       roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
       return roleHierarchy;
   }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(request->{
                    request
                            // 루트 페이지는 모두 접근 가능
                            .antMatchers("/").permitAll()
                            // 어떤 요청이던 허락을 받은 자만 가능
                            .anyRequest().authenticated()
                            ;
                })
                /*
                 Username filter는 form login을 설정해주면 적용 됨
                 form login에서 login 설정을 따로 해주지 않으면,
                 DefaultLoginPageGeneratingFilter, DefaultLogoutPageGeneratingFilter
                 가 동작하게 되어 작성한 css가 적용되지 않고 default 로그인 화면 띄움
                 */
                .formLogin(
                        login->login.loginPage("/login")
                        // 로그인 무한 루프에 빠지지 않기 위함!!
                        .permitAll()
                        .defaultSuccessUrl("/", false)
                        .failureUrl("/login-error")
                        .authenticationDetailsSource(customAuthDetails)
                )
                // 로그아웃 하더라도 로그인 페이지가 아닌 메인페이지에 있기
                .logout(logout -> logout.logoutSuccessUrl("/"))
                // 권한 오류 발생시 403 페이지 대신 원하는 페이지로 보내기
                .exceptionHandling(exception -> exception.accessDeniedPage("/access-denied"))
                ;
    }

    // css와 같은 web resource에는 security filter가 적용되지 않도록
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .requestMatchers(
                        // debug 한 후 Evaluate Expression 버튼 누르고, 아랫줄 그대로 입력하면
                        // result -> location에 아래 명령어에 어떤 것들이 포함되는지 확인 가능
                        PathRequest.toStaticResources().atCommonLocations()
                );
    }
}
