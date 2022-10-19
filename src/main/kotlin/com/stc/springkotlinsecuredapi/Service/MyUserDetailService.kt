package com.stc.springkotlinsecuredapi.Service

import com.stc.springkotlinsecuredapi.models.MyUserDetails
import com.stc.springkotlinsecuredapi.models.User
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service //@Slf4j
class MyUserDetailService : UserDetailsService {
   // @Autowired
    //private val userRepository: UserRepository? = null

    @Autowired
    private val userService: UserService? = null

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String): UserDetails? {
        val user: User = userService?.findByEmail(username)
            ?: throw UsernameNotFoundException("Not found: $username")
        return MyUserDetails(user)
    }
}
