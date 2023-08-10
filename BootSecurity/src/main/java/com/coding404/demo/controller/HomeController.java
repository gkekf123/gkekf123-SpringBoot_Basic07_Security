package com.coding404.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HomeController {

	// 홈
	@GetMapping("/hello")
	public String hello() {
		return "hello";
	}
	
	// 회원가입
	@GetMapping("/join")
	public String join() {
		return "join";
	}
	
	@GetMapping("/all")
	public String all() {
		return "all";
	}

	//  커스터마이징 로그인 페이지
	@GetMapping("/login")
	public String login() {
		return "login";
	}
	
	/* REST API - 화면필요 없다 */
	@GetMapping("/admin/mypage")
	public @ResponseBody String mypage() {
		return "REST API admin 마이페이지";
	}
	
	@GetMapping("/user/mypage")
	public @ResponseBody String usermypage() {
		return "REST API user 마이페이지";
	}
	
}
