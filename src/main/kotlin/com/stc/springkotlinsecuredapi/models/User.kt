package com.stc.springkotlinsecuredapi.models

import com.fasterxml.jackson.annotation.JsonIgnore
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.util.ArrayList
import javax.persistence.*

@Entity
class User {
    //
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    var id: Long = 0

    @Column
    var firstName: String = ""
    @Column
    var lastName: String? = null

    @Column(unique = true)
    var email: String = ""
    //var username: String? = null
    @Column
    var password: String = ""
        @JsonIgnore
        get() = field
        set(value) {
         val passwordEncoder = BCryptPasswordEncoder()
            field = passwordEncoder.encode(value)
        }

    @ManyToMany(fetch = FetchType.EAGER)
    val roles: Collection<Role> = ArrayList<Role>()

    fun comparePassword(password: String):Boolean {
        return BCryptPasswordEncoder().matches(password, this.password)
    }

    fun removePassword():User {
        this.password = "";
        var u:User = this
        u.email = email
        u.password = ""
        return u
    }

    override fun toString(): String {
        return "User(id=$id, firstName='$firstName', lastName=$lastName, email='$email', password='$password')"
    }


}