package com.coding404.demo.user;

import org.apache.ibatis.annotations.Mapper;

import com.coding404.demo.command.UserVO;

@Mapper
public interface UserMapper {

	//가입
	public void join(UserVO vo);
	
	//로그인(password는 제외됨)
	public UserVO login(String username);
	
}
