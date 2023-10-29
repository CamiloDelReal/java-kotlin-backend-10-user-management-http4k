package org.xapps.services.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.fasterxml.jackson.databind.ObjectMapper
import org.xapps.services.dtos.Authentication
import org.xapps.services.dtos.User
import org.xapps.services.services.PropertiesService
import java.time.Instant
import java.util.*

class JwtGenerator(
    private val propertiesService: PropertiesService
) {

    private val objectMapper = ObjectMapper()

    fun createToken(
        user: User
    ): Authentication {
        val expiration = Instant.now().toEpochMilli() + propertiesService.securityValidity
        val token = JWT.create()
            .withAudience(propertiesService.securityAudience)
            .withIssuer(propertiesService.securityIssuer)
            .withSubject(objectMapper.writeValueAsString(user))
            .withExpiresAt(Date(expiration))
            .sign(Algorithm.HMAC256(propertiesService.securitySecret))
        return Authentication(
            token = token,
            type = propertiesService.securityTokenType,
            expiration = expiration
        )
    }

}