package com.example.demo.config;

import com.example.demo.domain.UserDo;
import com.example.demo.domain.UserDoRepository;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Component
public class CustomRealm extends AuthorizingRealm
{

    private static final Logger log = LoggerFactory.getLogger(CustomRealm.class);
    @Autowired
    UserDoRepository userDoRepository;


    /**
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection)
    {
        log.debug("user auth confirm.");
        String userName = (String) SecurityUtils.getSubject().getPrincipal();
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        UserDo userDo = userDoRepository.findByUserName(userName);

        String roles = userDo.getRoles();
        String[] split = roles.split(",");
        Set<String> roleSet = new HashSet<>(Arrays.asList(split));
        authorizationInfo.setRoles(roleSet);

        String permissions = userDo.getPermissions();
        String[] permissionArray = permissions.split(",");
        for (String permission : permissionArray)
        {
            authorizationInfo.addStringPermission(permission);
        }
        return authorizationInfo;
    }

    /**
     * 获取身份验证信息,Shiro中，最终是通过 Realm 来获取应用程序中的用户、角色及权限信息的。
     *
     * @param authenticationToken 用户身份信息 token
     * @return 返回封装了用户信息的 AuthenticationInfo 实例
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException
    {
        log.debug("user authentication...");
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        String username = token.getUsername();
        UserDo userDo = userDoRepository.findByUserName(username);
        String password = userDo.getPassword();
        if (StringUtils.isEmpty(password))
        {
            throw new AccountException("password is empty.");
        }
        if (!password.equals(new String((char[]) token.getPassword())))
        {
            throw new AccountException("password is wrong..");
        }
        return new SimpleAuthenticationInfo(token.getUsername(), password, getName());
    }
}
