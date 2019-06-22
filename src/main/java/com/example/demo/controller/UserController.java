package com.example.demo.controller;


import com.example.demo.bean.ResultMap;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController
{

    @RequestMapping(value = "/getMessage", method = RequestMethod.GET)
    @RequiresPermissions(value = {"user:create"})
    public ResultMap getMessage()
    {
        return new ResultMap().success().message("您拥有用户权限，可以获得该接口的信息！");
    }
}