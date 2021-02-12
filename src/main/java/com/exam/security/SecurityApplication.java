package com.exam.security;

import com.exam.security.Entities.AppRole;
import com.exam.security.Entities.AppUser;
import com.exam.security.Service.IService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
//to allow annotation using for authorities :
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner start(IService iService) {
        return args -> {
            iService.addRole(new AppRole(null, "USER"));
            iService.addRole(new AppRole(null, "ADMIN"));

            iService.addUser(new AppUser(null, "Armane", "armane", new ArrayList<>()));
            iService.addUser(new AppUser(null, "guest", "123", new ArrayList<>()));

            iService.addRoleToUser("Armane", "ADMIN");
            iService.addRoleToUser("guest", "USER");
        };
    }
}
