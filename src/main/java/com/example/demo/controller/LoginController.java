package com.example.demo.controller;

import com.example.demo.bean.ResultMap;
import com.example.demo.domain.UserDo;
import com.example.demo.domain.UserDoRepository;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class LoginController
{
    @Autowired
    private UserDoRepository userDoRepository;

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public ResultMap logout()
    {
        Subject subject = SecurityUtils.getSubject();
        //注销
        subject.logout();
        return new ResultMap().success().message("成功注销！");
    }

    /**
     * 登陆
     *
     * @param username 用户名
     * @param password 密码
     */
    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public ResultMap login(@RequestParam("userName") String username, @RequestParam("password") String password)
    {
        // 从SecurityUtils里边创建一个 subject
        Subject subject = SecurityUtils.getSubject();
        // 在认证提交前准备 token（令牌）
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        // 执行认证登陆
        subject.login(token);

        UserDo role = userDoRepository.findByUserName(username);
        String roles = role.getRoles();
        String[] split = roles.split(",");
        List<String> strings = Arrays.asList(split);
        if (strings.contains("user"))
        {
            return new ResultMap().success().message("欢迎登陆");
        }
        if (strings.contains("admin"))
        {
            return new ResultMap().success().message("欢迎来到管理员页面");
        }
        return new ResultMap().fail().message("权限错误！");
    }
}