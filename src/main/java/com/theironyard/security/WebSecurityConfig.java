package com.theironyard.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                // Don't create sessions
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // Set permissions for URLS
                .authorizeRequests()
                // Allow registration without being logged in
                .antMatchers(HttpMethod.POST, "/users").permitAll()
                // Allow login without being logged in
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                // Allow item search without being logged in
                .antMatchers(HttpMethod.GET, "/items/**/**").permitAll()
                // Allow recall search without being logged in
                .antMatchers(HttpMethod.GET, "/recalls").permitAll()
                // All other requests must be authenticated
                .anyRequest().authenticated().and()
                // Allow CORS
                .cors().and()
                // Adds login route
                .addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                // Checks for Authorization token JWT
                .addFilterBefore(new JWTAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                // Use our UserDetailsService to lookup user by username
                .userDetailsService(userDetailsService)
                // Use bcrypt to check passwords
                .passwordEncoder(bCryptPasswordEncoder());
    }
}
