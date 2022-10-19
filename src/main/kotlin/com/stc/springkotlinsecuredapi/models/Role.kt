package com.stc.springkotlinsecuredapi.models

import net.bytebuddy.dynamic.loading.InjectionClassLoader
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id

@Entity
class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    var id: Long = 0
    var name: String = ""
}