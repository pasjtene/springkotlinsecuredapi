package com.stc.springkotlinsecuredapi.models

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.util.stream.Collectors

class MyUserDetails : UserDetails {
    private var userName: String
    private var password: String? = null
    private var isActive = false
    private var authorities: List<GrantedAuthority>? = null

    constructor(user: User) {
        userName = user.email
        //userName = user.getEmail()
        password = user.password
        isActive = true
        authorities = user.roles.stream().map { role -> SimpleGrantedAuthority(role.name) }.collect(Collectors.toList())
           // user.getRoles().stream().map { role -> SimpleGrantedAuthority(role.getName()) }.collect(Collectors.toList())
        //user.getRoles().stream().map { role -> SimpleGrantedAuthority(role.getName()) }.collect(Collectors.toList())
    }

    constructor(username: String) {
        userName = username
    }

    override fun getAuthorities(): Collection<GrantedAuthority> {
        return authorities!!
    }

    override fun getPassword(): String {
        return password!!
    }

    override fun getUsername(): String {
        return userName
    }

    override fun isAccountNonExpired(): Boolean {
        return true
    }

    override fun isAccountNonLocked(): Boolean {
        return true
    }

    override fun isCredentialsNonExpired(): Boolean {
        return true
    }

    override fun isEnabled(): Boolean {
        return true
    }
}
