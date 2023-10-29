package org.xapps.services

import org.apache.hc.core5.http.HttpHeaders
import org.http4k.core.ContentType
import org.http4k.core.Method
import org.http4k.core.Request
import org.http4k.core.Status.Companion.OK
import org.http4k.core.with
import org.http4k.kotest.shouldHaveStatus
import org.junit.jupiter.api.Test
import org.xapps.services.dtos.Login

class UserManagementApplicationTest {

    val app = initializeApp()

    @Test
    fun `Login successful`() {
        val request = Request(Method.POST, "/login")
            .header(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.value)
            .with(Login.messageLens of Login(email = "root@gmail.com", password = "123456"))

        val response = app(request)

        response shouldHaveStatus OK
    }

}
