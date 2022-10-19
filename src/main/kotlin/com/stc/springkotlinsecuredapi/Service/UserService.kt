package com.stc.springkotlinsecuredapi.Service

import com.stc.springkotlinsecuredapi.models.User
import com.stc.springkotlinsecuredapi.repository.UserRepository
import org.springframework.stereotype.Service
import java.util.HashMap

@Service
class UserService(private val userRepository: UserRepository) {

    fun save(user: User):User {
        return this.userRepository.save(user)
    }

    fun findByEmail(email:String):User? {
        return this.userRepository.findByEmail(email);
    }

    fun getSafeUser(user:User): HashMap<String, Any?>{
        val us : HashMap<String, Any?> = HashMap<String, Any?>();

        us.put("id", user.id)
        us.put("email", user.email)
        us.put("firstName", user.firstName)
        us.put("lastName", user.lastName)

        return us;
    }


}