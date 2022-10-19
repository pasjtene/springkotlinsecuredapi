package com.stc.springkotlinsecuredapi.jwtutils

import com.fasterxml.jackson.databind.ObjectMapper
import com.stc.springkotlinsecuredapi.Service.MyUserDetailService
import com.stc.springkotlinsecuredapi.models.MyUserDetails
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.CookieValue
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import java.lang.Exception
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import kotlin.collections.HashMap


@Service //@Slf4j
class JwtRequestFilter : OncePerRequestFilter() {
    @Autowired
    private val jwtUtil: JwtUtil? = null
     //val jwtUtil: JwtUtil

    @Autowired
    private val myUserDetailService: MyUserDetailService? = null

    private fun getCookieValue(req: HttpServletRequest, cookieName: String): String? {
        return if (req.cookies == null) null else Arrays.stream(req.cookies)
            .filter { c: Cookie -> c.name == cookieName }
            .findFirst()
            .map { obj: Cookie -> obj.value }
            .orElse(null)
    }

    @Throws(IOException::class)
    private fun refreshCookies(
        request: HttpServletRequest, response: HttpServletResponse, refresh_t: String?,
        access_t: String?, duration_second: Int, isHttpOnly: Boolean
    ) {

        //log.error("Refreshing cookies...{}",access_t);
        val rcookie = Cookie("uid", access_t)
        val refresh_cookie = Cookie("refresh_t", refresh_t)
        val user_auth = Cookie("isUserAuth", "true")
        val serverName = request.serverName
        rcookie.maxAge = 600
        rcookie.secure = false
        rcookie.isHttpOnly = isHttpOnly
        rcookie.path = "/"
        rcookie.domain = serverName
        refresh_cookie.maxAge = 3600
        refresh_cookie.secure = false
        refresh_cookie.isHttpOnly = isHttpOnly
        refresh_cookie.path = "/"
        refresh_cookie.domain = serverName
        user_auth.maxAge = 3600
        user_auth.secure = false
        // user_auth.setHttpOnly(isHttpOnly);
        user_auth.path = "/"
        user_auth.domain = serverName

        //log.error("Exeption during auth {}", e.getMessage());
        //response.setHeader("error auth failled", e.getMessage());
        response.status = HttpServletResponse.SC_ACCEPTED
        val error: MutableMap<String, String> = HashMap()
        error["Refreshing cookie"] = "refresh_t"
        response.contentType = "application/json"
        response.addCookie(rcookie)
        response.addCookie(refresh_cookie)
        response.addCookie(user_auth)
        ObjectMapper().writeValue(response.outputStream, error)
    }

    @Throws(ServletException::class, IOException::class)
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {


        //log.info("does user-id, access_token  cookie exist...{} ",getCookieValue(request,"user-id"));
        //log.info("does the refresh_t cookie exist...{} ",getCookieValue(request,"refresh_t"));
        var username: String? = null
      var jwt: String? = null
       // var jwt: String? = getCookieValue(request, "user-id")
        if (getCookieValue(request, "uid") != null) {
            //We have a cookie
            jwt = getCookieValue(request, "uid")


           if (jwtUtil != null) {

               if(jwt != null){
                   println("Just trying...2 $jwt")
                   username = jwtUtil.extractUsername(jwt)
               } else {
                   println("The Jwt is null..11")
               }

           }

        } else {
            // The access token has expired. We can renew all tokens, if the refresh token is still valid
            if (getCookieValue(request, "refresh_t") != null) {
                // log.error("No access token, but refresh token exist..{}",getCookieValue(request,"refresh_t"));
                //log.info("Sending a redirect now....");
                //We have a cookie
                jwt = getCookieValue(request, "refresh_t")

                if (jwtUtil != null) {
                    if(jwt != null){
                        username = jwtUtil.extractUsername(jwt)
                        print("The refresh cookie is here ... $username")
                    }

                }



                //log.info("The username....{}",username);

                //generate new tokens here
                //val myUserDetails: MyUserDetails = username?.let { myUserDetailService?.loadUserByUsername(it) } as? MyUserDetails

                try {
                    val myUserDetails = username?.let { myUserDetailService?.loadUserByUsername(it) } as? MyUserDetails
                    val access_token = myUserDetails?.let { jwtUtil?.generateToken(it, 2) }
                    val refresh_token = myUserDetails?.let { jwtUtil?.generateToken(it, 5) }
                    refreshCookies(request, response, refresh_token, access_token, 90, true)
                } catch(e:Exception) {

                    val rcookie = Cookie("user-id", "")
                    val acookie = Cookie("isUserAuth", "false")
                    val rrcookie = Cookie("refresh_t", "")


                    val serverName = request.serverName

                    rcookie.maxAge = 0
                    rcookie.secure = false
                    rcookie.isHttpOnly = true
                    rcookie.path = "/"
                    rcookie.domain = serverName

                    rrcookie.maxAge = 0
                    rrcookie.secure = false
                    rrcookie.isHttpOnly = true
                    rrcookie.path = "/"
                    rrcookie.domain = serverName





                    acookie.maxAge = 300
                    acookie.secure = false
                    //acookie.setHttpOnly(false);
                    acookie.path = "/"
                    acookie.domain = serverName


                    //  log.error("Exeption during auth {}", e.getMessage());
                    response.setHeader("error auth failled", e.message)
                    response.status = HttpServletResponse.SC_FORBIDDEN
                    val error: MutableMap<String, String?> = HashMap()
                    error["Error message"] = e.message
                    response.contentType = "application/json"




                    response.addCookie(rcookie)
                    response.addCookie(acookie)
                    response.addCookie(rrcookie)
                    ObjectMapper().writeValue(response.outputStream, error)
                }



                //log.info("The username....{}",username);
                //log.info("The userdetail....{}",myUserDetails);

            }
        }

        //username = uname;
        if (username != null && jwt != null && SecurityContextHolder.getContext().authentication == null) {

            println("The user name 400... is $username")

            try {
                //MyUserDetails myUserDetails = (MyUserDetails) this.myUserDetailService.loadUserByUsername(username);
                //val myUserDetails: MyUserDetails = myUserDetailService?.loadUserByUsername(username) as MyUserDetails
                val myUserDetails = myUserDetailService!!.loadUserByUsername(username) as? MyUserDetails

                if (myUserDetails?.let { jwtUtil!!.validateToken(jwt, it) }!!) {
                    // log.error("The jwt token is validated....");
                    val usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken(
                        myUserDetails, null, myUserDetails.getAuthorities()
                    )
                    //log.error("The authorities are...{}",myUserDetails.getAuthorities());
                    usernamePasswordAuthenticationToken.details = WebAuthenticationDetailsSource()
                        .buildDetails(request)
                    SecurityContextHolder.getContext().authentication = usernamePasswordAuthenticationToken
                }
            } catch (e: Exception) {
                val rcookie = Cookie("uid", "")
                val acookie = Cookie("isUserAuth", "false")
                val rrcookie = Cookie("refresh_t", "")


                val serverName = request.serverName

                rcookie.maxAge = 0
                rcookie.secure = false
                rcookie.isHttpOnly = true
                rcookie.path = "/"
                rcookie.domain = serverName

                rrcookie.maxAge = 0
                rrcookie.secure = false
                rrcookie.isHttpOnly = true
                rrcookie.path = "/"
                rrcookie.domain = serverName

                acookie.maxAge = 300
                acookie.secure = false
                //acookie.setHttpOnly(false);
                acookie.path = "/"
                acookie.domain = serverName


                //  log.error("Exeption during auth {}", e.getMessage());
                response.setHeader("error auth failled", e.message)
                response.status = HttpServletResponse.SC_FORBIDDEN
                val error: MutableMap<String, String?> = HashMap()
                error["Error message"] = e.message
                response.contentType = "application/json"




                response.addCookie(rcookie)
                response.addCookie(acookie)
                response.addCookie(rrcookie)
                ObjectMapper().writeValue(response.outputStream, error)
            }
        } else {
            println("The user auth failed 2.. The user name is $username")
            println("The user auth failed 2.1. The jwt isis $jwt")
        }

            filterChain.doFilter(request, response)


    }
}


