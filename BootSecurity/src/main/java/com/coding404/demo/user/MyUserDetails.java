package com.coding404.demo.user;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.coding404.demo.command.UserVO;

// 이 객체는 화면에 전달이 되는데, 화면에서 사용 할 값들은 getter로 생성
public class MyUserDetails implements UserDetails{

	// 멤버변수로 UserVO객체를 받는다
	private UserVO uservo;
	
	public MyUserDetails(UserVO vo) {
		this.uservo = vo;
	}
	
	// 화면에서 권한도 사용할 수 있게 해주고 싶다면 getter를 만들어라
	public String getRole() {
		return uservo.getRole();
	}
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {

		// Collection은 list의 최고 부모
		// UserVO가 가지고 있는 권한을 리스트에 담아서 반환시키면, 스프링 시큐리티가 참조해서 사용한다
		List<GrantedAuthority> list = new ArrayList<>();
		
		list.add(new GrantedAuthority() {
			
			@Override
			public String getAuthority() {
				return uservo.getRole();
			}
		});
		
		return list;
	}

	// password
	@Override
	public String getPassword() {
		return uservo.getPassword();
	}

	// username
	@Override
	public String getUsername() {
		return uservo.getUsername();
	}

	// 계정의 만료 여부를 화면에 반환
	@Override
	public boolean isAccountNonExpired() {
		return true; // 계정이 만료되지 않았습니까? true -> yes
	}

	// 계정의 락 여부를 화면에 반환
	@Override
	public boolean isAccountNonLocked() {
		return true; // 계정의 락 걸리지 않았습니까?
	}

	// 비밀번호 만료 여부를 화면에 반환
	@Override
	public boolean isCredentialsNonExpired() {
		return true; // 사용할 수 있는 비밀번호 입니까?
	}

	// 사용할 수 있는 계정 여부를 화면에 반환
	@Override
	public boolean isEnabled() {
		return true; // 사용할 수 있는 계정입니까?
	}

	
	
}
