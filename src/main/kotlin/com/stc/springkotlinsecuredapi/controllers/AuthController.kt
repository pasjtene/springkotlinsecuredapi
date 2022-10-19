package com.stc.springkotlinsecuredapi.controllers

import com.stc.springkotlinsecuredapi.Service.MyUserDetailService
import com.stc.springkotlinsecuredapi.Service.UserService
import com.stc.springkotlinsecuredapi.dto.LoginDTO
import com.stc.springkotlinsecuredapi.dto.RegisterUserDTO
import com.stc.springkotlinsecuredapi.dto.Response
import com.stc.springkotlinsecuredapi.jwtutils.JwtUtil
import com.stc.springkotlinsecuredapi.models.MyUserDetails
import com.stc.springkotlinsecuredapi.models.User
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.bind.annotation.*
import java.util.*
import java.util.Map
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@RestController
@RequestMapping("/api")
class AuthController(private val userService: UserService) {
    // private val passwordEncoder= BCryptPasswordEncoder ()
    @PostMapping("register")
    fun register(@RequestBody body: RegisterUserDTO): ResponseEntity<Any> {

        val userexist: User? = this.userService.findByEmail(body.email)

        if(userexist!=null) {
            return ResponseEntity.ok(
                Response("A user is already registered with ${body.email}"))
        }

        val user = User()
        user.email = body.email
        user.firstName = body.firstName
        user.lastName = body.lastName
        user.password = body.password
        var err:String? = null
        var u:User? = null
        try {
            u = this.userService.save(user)

        } catch (e:Exception) {
            err = e.stackTraceToString()
        }



        return ResponseEntity.ok( err?:Response(
                                            message = "user created",
                                            data = Map.of("user", this.userService.getSafeUser(u?:user))
                                            )
                                    )

    }

    @Autowired
    var authenticationManager: AuthenticationManager? = null

    @Autowired
    private val myUserDetailService: MyUserDetailService? = null

    @Autowired
    private val jwtTokenUtil: JwtUtil? = null



    @PostMapping("login")
    fun login(@RequestBody body: LoginDTO,
              responseCookie: HttpServletResponse,request: HttpServletRequest): ResponseEntity<Any> {
        val user = this.userService.findByEmail(body.email)
           ?:return ResponseEntity.ok(Response("user not found"))

        if(!user.comparePassword(body.password)) {
            return ResponseEntity.ok(Response("Username or Password not valid"))
        }

        println("The user is.. ${user.email}")


        //log.info("Authenticating user {}", user);
        try {
            val authentication = authenticationManager!!.authenticate(
                UsernamePasswordAuthenticationToken(user.email, body.password)

            )
            print("The authentication is $authentication")
        } catch (e: BadCredentialsException) {
            throw java.lang.Exception("Incorect username or password", e)
        }

       // val myUserDetails = myUserDetailService!!.loadUserByUsername(user.email) as? MyUserDetails

        println("The user is  ${user.email}")





        val myUserDetails = myUserDetailService?.loadUserByUsername(user.email) as MyUserDetails

        println("My user details are $myUserDetails")

        if (myUserDetails != null) {
            println("My user details are ${myUserDetails.username}")
        } else {
            println("My user details is null....")
        }


        val jwt_token = jwtTokenUtil!!.generateToken(myUserDetails, 10)



       // val jwt_token = myUserDetails?.let { jwtTokenUtil!!.generateToken(it, 10) }
        val refresh_token = myUserDetails?.let { jwtTokenUtil?.generateToken(it, 30) }
        val access_token = myUserDetails?.let { jwtTokenUtil?.generateToken(it, 10) }


        //begin set cookie
        /**
        if the user is idle or does not use an authenticated link for more that maxAge (in seconds), the access token will
        expire. When the user tries to login again, if the refresh token is still valid, a new access token is assued in jwtrequestFilter
         */

        //begin set cookie
        /**
         * if the user is idle or does not use an authenticated link for more that maxAge (in seconds), the access token will
         * expire. When the user tries to login again, if the refresh token is still valid, a new access token is assued in jwtrequestFilter
         */


        // log.error("The myUserdetails is in authenticate controleur is: {}",myUserDetails.getAuthorities());
        val host: String? = request.getHeader("host")
        val serverName: String = request.getServerName()
        val responseCookie = ResponseCookie.from("uid", jwt_token!!)
            .httpOnly(true)
            .secure(false)
            .path("/")
            .maxAge(600) //.domain("localhost")
            .domain(serverName) //.sameSite("Lax")
            .build()

        val refresh_token_cookie = ResponseCookie.from("refresh_t", refresh_token!!)
            .httpOnly(true)
            .secure(false)
            .path("/")
            .maxAge(1800) //.domain("localhost")
            .domain(serverName) //.sameSite("Lax")
            .build()
//isUserAuth cookie should have the same age or even longer as refresh_Token, and will be checked. if the access token has expired.
// IF it is available, then reflech token is checked, If reflesh token is valid and not expired, then all new tokens are generated

        //isUserAuth cookie should have the same age or even longer as refresh_Token, and will be checked. if the access token has expired.
// IF it is available, then reflech token is checked, If reflesh token is valid and not expired, then all new tokens are generated
        val auth_cookie = ResponseCookie.from("isUserAuth", "true")
            .secure(false)
            .path("/")
            .maxAge(600) //.domain("localhost")
            .domain(serverName) //.sameSite("Lax")
            .build()


       // val auth_user: User = userService.findByEmail(user)

        //auth_user.setPassword("")


        val user_name = ResponseCookie.from("un", user.email)
            .secure(false)
            .path("/")
            .maxAge(1800) //.domain("localhost")
            .domain(serverName) //.sameSite("Lax")
            .build()


        /**
        val issuer = user.email.toString()
        val jwt1 = Jwts.builder()
            .setIssuer(issuer)
            .setExpiration(Date(System.currentTimeMillis()+ 60 * 24 * 1000 )) // 24 hours
            .signWith(SignatureAlgorithm.HS256, "secretkey").compact()

        */



        /**
        val claims : HashMap<String, Any?> = HashMap<String, Any?>();

        claims.put("iss", "appId");
        claims.put("sub", "LoginRequest");
        claims.put("userName", user.email);
        claims.put("password", user.password);

        // make a jwt out of the claims
        // using the jjwt/jwtk library
        val jwt : String = Jwts.builder()
            .setClaims(claims)
            .signWith(SignatureAlgorithm.HS256, "appSecret")
            .compact();
        */


        /*
        var cookie = Cookie("jwt",jwt1)
        cookie.isHttpOnly = true

        responseCookie.addCookie(cookie)
        */

        //return ResponseEntity.ok(this.userService.getSafeUser(user))


        // log.error("Sending refresh response is in authenticate controleur is: {}",myUserDetails.getAuthorities());
        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
            .header(HttpHeaders.SET_COOKIE, auth_cookie.toString())
            .header(HttpHeaders.SET_COOKIE, user_name.toString())
            .header(HttpHeaders.SET_COOKIE, refresh_token_cookie.toString())
            .body(user)

    }

    @GetMapping("user")
    fun getAuthuser(@CookieValue("uid") jwt: String?, jwtUtil: JwtUtil):ResponseEntity<Any> {
        if(jwt == null) {
            return ResponseEntity.status(401).body("user not authenticated")
        }
         //val jwtUtil: JwtUtil
        var username: String? = null



        try{
           // val body =  Jwts.parser().setSigningKey("secretkey").parseClaimsJws(jwt).body.issuer.toString()
            username = jwtUtil.extractUsername(jwt)
            //return ResponseEntity.ok().body(this.userService.findByEmail(body))
            return ResponseEntity.ok().body(this.userService.findByEmail(username))


        }catch (e:Exception) {
            return ResponseEntity.status(401).body("user not authenticated")
        }

    }

    @PostMapping("logout")
    fun logout(response: HttpServletResponse):ResponseEntity<Any> {
        val cookie = Cookie("jwt","")
        cookie.maxAge = 0
        response.addCookie(cookie)
        return  ResponseEntity.ok().body("Loged ou successfully")

    }


}