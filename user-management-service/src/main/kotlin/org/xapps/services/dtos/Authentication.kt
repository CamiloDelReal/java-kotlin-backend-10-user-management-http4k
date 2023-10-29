package org.xapps.services.dtos

import org.http4k.core.Body
import org.http4k.format.Jackson.auto

data class Authentication(
    val token: String,
    val type: String,
    val expiration: Long
) {

    companion object {
        val messageLens by lazy { Body.auto<Authentication>().toLens() }
    }

}