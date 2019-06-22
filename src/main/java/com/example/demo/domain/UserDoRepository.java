package com.example.demo.domain;


import org.springframework.data.jpa.repository.JpaRepository;

public interface UserDoRepository extends JpaRepository<UserDo, Integer>
{

    UserDo findByUserName(String userName);

}
