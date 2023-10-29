package org.xapps.services.dtos

import org.http4k.core.Body
import org.http4k.format.Jackson.auto

data class Login(
    val email: String,
    val password: String
) {

    companion object {
        val messageLens by lazy { Body.auto<Login>().toLens() }
    }

}