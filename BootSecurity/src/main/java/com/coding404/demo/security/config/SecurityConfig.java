package com.coding404.demo.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.coding404.demo.user.MyUserDetailService;

@Configuration // 설정파일
@EnableWebSecurity // 이 설정파일을 시큐리티 필터에 추가
@EnableMethodSecurity(prePostEnabled = true) // 어노테이션으로 권한을 지정할 수 있게 함
public class SecurityConfig {

	// rememberMe에서 사용 할 UserDetailService
	@Autowired
	private MyUserDetailService myUserDetailService;
	
	
	// 가입 시도 - 비밀번호 암호화(단방향) -> 복호화 안됨 무조건 초기화 해야됨
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	
	@Bean
	public SecurityFilterChain securityFilter(HttpSecurity http) throws Exception{
		
		// csrf토큰 사용X => 
		http.csrf().disable();
			
		
		// 권한설정 - 모든 요청에 대해서 권한없이 허가
		//http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());
		
		// 모든 페이지에 대해서 거부
		//http.authorizeHttpRequests(authorize -> authorize.anyRequest().denyAll());
		
		// user페이지에 대해서 인증이 필요하기 떄문에 user/mypage로 접근이 안되고 login으로 된다		
	//		http.authorizeHttpRequests(authorize -> authorize.
	//												antMatchers("/user/**").
	//												authenticated());
		
		
		 
		//http.authorizeHttpRequests(authorize -> authorize.antMatchers("/user/**").hasRole("USER") );
		
		// user페이지는 user권한이 필요, admin페이지는 admin권한이 필요
//		http.authorizeHttpRequests(authorize -> authorize.antMatchers("/user/**").hasRole("USER") 
//														 .antMatchers("/admin/**").hasRole("ADMIN"));
			
		
//		http.authorizeHttpRequests(authorize -> authorize.antMatchers("/all").authenticated() // all페이지는 인증 된 사람만
//				 										 .antMatchers("/user/**").hasRole("user") // user페이지는 user권한이 필요
//				 										 .antMatchers("/admin/**").hasRole("ADMIN") // admin페이지는 admin권한이 필요
//				 										 .anyRequest().permitAll()); // 그 외에는 접근 가능

		// 권한 앞에는 ROLE_가 자동으로 생략 됨
		http.authorizeHttpRequests(authorize -> authorize.antMatchers("/all").authenticated() // all페이지는 인증 된 사람만
																			 .antMatchers("/user/**").hasAnyRole("USER", "ADMIN", "TESTER") // user페이지는 셋중 1개의 권한을 가지면 된다ㅣ
																			 .antMatchers("/admin/**").hasRole("ADMIN") // admin페이지는 admin권한이 필요
																			 .anyRequest().permitAll()); // 그 외에는 접근 가능
												
		// 시큐리티 설정파일 만들면, 시큐리티가 제공하는 기본 로그인 페이지가 보이지 않게 된다
		// 시큐리티가 사용하는 기본 로그인 피이지를 사용함
		// 권한 or 인증이 되지 않으면 기본으로 선언 도니 로그인 페이지를 보여주게 된다
		//http.formLogin(Customizer.withDefaults()); // 기본 로그인 페이지 사용 하겠다
		
		// 사용자가 저공하는 폼 기반 로그인 기능을 사용할 수 있다
		
		http.formLogin()
			.loginPage("/login") // 로그인 화면
			.loginProcessingUrl("/loginForm") //로그인 페이지를 가로채 시큐리티가 제공하는 클래스로 로그인을 연결합니다.
			.defaultSuccessUrl("/all") //로그인 성공시 이동될 URL을 적습니다; // 로그인 시도 요청 경로 -> 스프링이 로그인 시도를 낚아채서 UserDetailService객체로 연결;
			.failureUrl("/login?err=true") // 로그인 실패시 이동할 url
			.and()
			.exceptionHandling().accessDeniedPage("/deny") // 권한이 없을 떄 이동 할 리다이렉트 경로
			.and()
			.logout().logoutUrl("/logout").logoutSuccessUrl("/hello"); // default 로그아웃 경로 /logout, /logout주소를 직접 작성할 수 있고, 로그아웃 성공 시 리다이렉트 할 경로
		
		// rememberMe
		http.rememberMe()
			.key("coding404") // 토큰(쿠키)를 만들 비밀 키 (필수)
			.rememberMeParameter("remember-me") // 화면에서 전달받는 checked name명 이다 (필수)
			.tokenValiditySeconds(60) // 쿠키(토큰)의 유효시간 (필수)
			.userDetailsService(myUserDetailService) // 토큰이 있을 때 실행시킬 userDetailService객체 (필수)
			.authenticationSuccessHandler(customRememberMe()); // rememberme가 동작할 때, 실행할 핸들러객체를 넣는다 
			
		
		return http.build();
		
	}
	
	// customRememberMe
	@Bean
	public CustomRememberMe customRememberMe() {
		CustomRememberMe me = new CustomRememberMe("/all"); // 리멤버미 성송 시 실행시킬 리다이렉트 주소
		
		return me;
	}
	
}
