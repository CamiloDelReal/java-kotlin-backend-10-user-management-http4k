package org.xapps.services.dtos

import org.http4k.core.Body
import org.http4k.format.Jackson.auto

data class Role(
    var id: Long? = 0,
    var name: String = ""
) {

    companion object {
        const val ADMINISTRATOR = "Administrator"
        const val GUEST = "Guest"

        val messageLens by lazy { Body.auto<Role>().toLens() }
    }

}