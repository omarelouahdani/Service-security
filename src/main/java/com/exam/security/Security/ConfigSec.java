package com.exam.security.Security;


import com.exam.security.Entities.AppUser;
import com.exam.security.Security.Filter.JwtAuthFilter;
import com.exam.security.Security.Filter.JwtAutorisation;
import com.exam.security.Service.IService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Collection;

@Configuration
@EnableWebSecurity
public class ConfigSec extends WebSecurityConfigurerAdapter {
    private IService iService;

    public ConfigSec(IService iService) {
        this.iService = iService;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.formLogin();
        http.authorizeRequests().antMatchers("/h2-console/**", "/refreshToken/**").permitAll();
        http.headers().frameOptions().disable();

        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(new JwtAuthFilter(authenticationManager()));
        http.addFilterBefore(new JwtAutorisation(), UsernamePasswordAuthenticationFilter.class);

    }

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Auth StateFULL
        // to look for the user in the service
        auth.userDetailsService(username -> {
            AppUser appUser = iService.findUserByUsername(username);
            Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();
            //Soit on parcours et on ajoute chaque role dans la collection soit on le fait dans une class
            appUser.getAppRoles().stream().forEach(r -> {
                grantedAuthorities.add(new SimpleGrantedAuthority(r.getRoleName()));
            });
            // On retourne un objet de type User de spring
            return new User(appUser.getUsername(), appUser.getPassword(), grantedAuthorities);
        });

    }
}
