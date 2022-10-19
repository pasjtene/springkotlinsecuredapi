package com.stc.springkotlinsecuredapi

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration
import org.springframework.boot.runApplication

@SpringBootApplication
	//(exclude = [SecurityAutoConfiguration::class])
class SpringkotlinsecuredapiApplication

fun main(args: Array<String>) {
	runApplication<SpringkotlinsecuredapiApplication>(*args)
}
