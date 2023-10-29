package org.xapps.services.dtos

import com.fasterxml.jackson.annotation.JsonProperty
import org.http4k.core.Body
import org.http4k.format.Jackson.auto

data class User(
    var id: Long = 0,
    var firstName: String = "",
    var lastName: String = "",
    var email: String = "",
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    var password: String? = null,
    var roles: List<Role>? = null
) {

    companion object {
        val messageLens by lazy { Body.auto<User>().toLens() }
        val arrayMessageLens by lazy { Body.auto<List<User>>().toLens() }
    }

}