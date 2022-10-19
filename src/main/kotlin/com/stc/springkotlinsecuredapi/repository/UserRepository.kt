package com.stc.springkotlinsecuredapi.repository

import com.stc.springkotlinsecuredapi.models.User
import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository: JpaRepository<User, Long> {
    fun findByEmail(email:String):User?
}