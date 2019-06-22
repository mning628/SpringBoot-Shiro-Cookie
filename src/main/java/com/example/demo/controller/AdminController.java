package com.example.demo.controller;

import com.example.demo.bean.ResultMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController
{

    @RequestMapping(value = "/getMessage", method = RequestMethod.GET)
    public ResultMap getMessage()
    {
        return new ResultMap().success().message("您拥有管理员权限，可以获得该接口的信息！");
    }
}