package com.stc.springkotlinsecuredapi.dto

import javax.persistence.Column

class RegisterUserDTO {
    var firstName: String = ""
    var lastName: String = ""
    var email: String = ""
    //var username: String? = null
    var password: String = ""
}