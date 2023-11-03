package org.xapps.services.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.fasterxml.jackson.databind.ObjectMapper
import org.xapps.services.dtos.User
import org.xapps.services.services.PropertiesService

class JwtVerifier(
    private val propertiesService: PropertiesService
) {

    private val objectMapper = ObjectMapper()

    fun verifyToken(token: String): User? {
        val verifier = JWT
            .require(Algorithm.HMAC256(propertiesService.securitySecret))
            .withAudience(propertiesService.securityAudience)
            .withIssuer(propertiesService.securityIssuer)
            .build()
        val decodedJWT = verifier.verify(token)
        return objectMapper.readValue(decodedJWT.subject, User::class.java)
    }

}