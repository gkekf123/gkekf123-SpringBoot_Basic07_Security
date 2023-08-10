package com.coding404.demo.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // 설정파일
@EnableWebSecurity // 이 설정파일을 시큐리티 필터에 추가
public class SecurityConfig {

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

		http.authorizeHttpRequests(authorize -> authorize.antMatchers("/all").authenticated() // all페이지는 인증 된 사람만
																			 .antMatchers("/user/**").hasAnyRole("USER", "ADMIN", "TESTER") // user페이지는 셋중 1개의 권한을 가지면 된다ㅣ
																			 .antMatchers("/admin/**").hasRole("ADMIN") // admin페이지는 admin권한이 필요
																			 .anyRequest().permitAll()); // 그 외에는 접근 가능
												
		// 시큐리티 설정파일 만들면, 시큐리티가 제공하는 기본 로그인 페이지가 보이지 않게 된다
		// 시큐리티가 사용하는 기본 로그인 피이지를 사용함
		// 권한 or 인증이 되지 않으면 기본으로 선언 도니 로그인 페이지를 보여주게 된다
		//http.formLogin(Customizer.withDefaults()); // 기본 로그인 페이지 사용 하겠다
		
		// 사용자가 저공하는 폼 기반 로그인 기능을 사용할 수 있다
		
		http.formLogin().loginPage("/login");
		
		return http.build();
		
	}
	
}
