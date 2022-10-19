package com.stc.springkotlinsecuredapi.jwtutils

import com.stc.springkotlinsecuredapi.models.MyUserDetails
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.stereotype.Service
import java.util.*
import java.util.function.Function
import kotlin.collections.HashMap

@Service
class JwtUtil {

    private val SECRET_KEY = "jtjwtsecret"

    fun extractUsername(token: String): String {
        println("Extracting username...$token")
        return extractClaim(token) { obj: Claims -> obj.subject }
    }

    fun <T> extractClaim(token: String, claimsResolver: Function<Claims, T>): T {
        val claims = extractAllClaims(token)
        return claimsResolver.apply(claims)
    }

    private fun extractAllClaims(token: String): Claims {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).body
    }

    private fun isTokenExpired(token: String?): Boolean? {
        return false
    }

    fun generateToken(userDetails: MyUserDetails, duration_minutes: Int): String? {
        val claims: Map<String, Any> = java.util.HashMap()
        return createToken(claims, userDetails.getUsername(), duration_minutes)
    }

    private fun createToken(claims: Map<String, Any>, subject: String, duration_minutes: Int): String? {
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() + 1000 * 60 * 60 * duration_minutes))
            .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact()
    }

    fun validateToken(token: String, userDetails: MyUserDetails): Boolean? {
        val username = extractUsername(token)
        return username == userDetails.getUsername() && !isTokenExpired(token)!!
    }


}