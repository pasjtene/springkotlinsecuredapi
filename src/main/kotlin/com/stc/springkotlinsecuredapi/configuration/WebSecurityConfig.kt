package com.stc.springkotlinsecuredapi.configuration

import com.stc.springkotlinsecuredapi.jwtutils.JwtRequestFilter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.web.servlet.config.annotation.CorsRegistry
import org.springframework.web.servlet.config.annotation.EnableWebMvc
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.cors.CorsConfiguration
import java.lang.Exception
import java.util.List
import javax.servlet.http.HttpServletRequest


@Configuration
@EnableWebMvc
class WebSecurityConfig: WebMvcConfigurer {

    override fun addCorsMappings(registry: CorsRegistry) {
        registry.addMapping("/**")

            .allowedOrigins("http://localhost:3000",
                "http://localhost:4200",
                "http://localhost:8080")
            .allowCredentials(true)
    }
}


@Configuration
@EnableWebMvc
@EnableGlobalMethodSecurity(prePostEnabled = true)
class WebSecurityConfig2: WebSecurityConfigurerAdapter() {
   // @Throws(Exception::class)




    @Autowired
    private val jwtRequestFilter: JwtRequestFilter? = null

    override fun configure(http: HttpSecurity) {


        val corsConfiguration = CorsConfiguration()
        corsConfiguration.allowedHeaders = List.of("Authorization", "Cache-Control", "Content-Type")
        corsConfiguration.allowedOrigins = List.of("http://localhost:3000", "http://51.68.196.188")
        corsConfiguration.allowedMethods =
            List.of("GET", "POST", "PUT", "DELETE", "PUT", "OPTIONS", "PATCH", "DELETE")
        corsConfiguration.allowCredentials = true
        corsConfiguration.exposedHeaders = List.of("Authorization")
        http.csrf().disable()


        http.cors().configurationSource { request: HttpServletRequest? -> corsConfiguration }
            .and().authorizeRequests()
            .antMatchers(HttpMethod.POST, "/api/register").permitAll()
            .antMatchers(HttpMethod.POST, "/api/login").permitAll()
            .antMatchers(HttpMethod.POST, "/talodu/api/register").permitAll()
            .antMatchers(HttpMethod.GET, "/api/token/refresh").permitAll()
            //.antMatchers(HttpMethod.GET, "/api/user").hasAnyAuthority("ROLE_SUPER_ADMIN")
           // .antMatchers(HttpMethod.GET, "/api/user").hasAnyAuthority("ROLE_SUPER_ADMIN")
            .anyRequest().authenticated()

        http.sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter::class.java)

    }


    @Bean
    fun passwordEncoder(): PasswordEncoder? {
        //return PlainTextPasswordEncoder.getInstance();
        //return
        return BCryptPasswordEncoder()
    }

    @Bean
    @Throws(Exception::class)
    override fun authenticationManagerBean(): AuthenticationManager? {
        return super.authenticationManagerBean()
        //return configuration.getAuthenticationManager();
    }


}
