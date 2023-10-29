package org.xapps.services

import org.apache.hc.core5.http.HttpHeaders
import org.http4k.core.*
import org.http4k.core.Method.*
import org.http4k.core.Status.Companion.BAD_REQUEST
import org.http4k.core.Status.Companion.FORBIDDEN
import org.http4k.core.Status.Companion.INTERNAL_SERVER_ERROR
import org.http4k.core.Status.Companion.NOT_FOUND
import org.http4k.core.Status.Companion.OK
import org.http4k.core.Status.Companion.UNAUTHORIZED
import org.http4k.filter.ServerFilters
import org.http4k.lens.RequestContextKey
import org.http4k.routing.bind
import org.http4k.routing.path
import org.http4k.routing.routes
import org.http4k.server.ApacheServer
import org.http4k.server.asServer
import org.jetbrains.exposed.sql.Database
import org.xapps.services.dtos.Authentication
import org.xapps.services.dtos.Login
import org.xapps.services.dtos.User
import org.xapps.services.exceptions.EmailNotAvailable
import org.xapps.services.exceptions.InvalidCredentialsException
import org.xapps.services.exceptions.NotFoundException
import org.xapps.services.security.JwtGenerator
import org.xapps.services.security.JwtVerifier
import org.xapps.services.services.*

fun initializeApp(): HttpHandler {
    val propertiesService = PropertiesService()
    val database = Database.connect(
        url = propertiesService.databaseUrl,
        driver = propertiesService.databaseDriver,
        user = propertiesService.databaseUser,
        password = propertiesService.databasePassword
    )
    val roleService = RoleService(
        database = database
    )
    val userService = UserService(
        database = database,
        propertiesService = propertiesService,
        roleService = roleService
    )
    val userRoleService = UserRoleService(
        database = database
    )
    val seederService = SeederService(
        roleService = roleService,
        userService = userService,
        userRoleService = userRoleService
    )

    seederService.seed()

    val jwtGenerator = JwtGenerator(
        propertiesService = propertiesService
    )
    val jwtVerifier = JwtVerifier(propertiesService)

    val requestContexts = RequestContexts()
    val optionalAuthorizationLens = RequestContextKey.optional<User>(requestContexts)
    val authorizationLens = RequestContextKey.required<User>(requestContexts)

    val optionalBearerFilter = Filter { next ->
        { request ->
            val token = request.header("Authorization")
            if (token != null && token.startsWith("Bearer ")) {
                val tokenValue = token.removePrefix("Bearer ").trim()
                jwtVerifier.verifyToken(tokenValue)?.let { user ->
                    next(request.with(optionalAuthorizationLens of user))
                } ?: run {
                    next(request)
                }
            } else {
                next(request)
            }
        }
    }

    val authorizationAdminForCreate = Filter { next ->
        { request ->
            val authenticatedUser = optionalAuthorizationLens.extract(request)
            authenticatedUser?.let {
                if (userService.isAdministrator(authenticatedUser) || !userService.hasAdministratorRole(User.messageLens(request))) {
                    next(request)
                } else {
                    Response(FORBIDDEN)
                }
            } ?: run {
                if (!userService.hasAdministratorRole(User.messageLens(request))) {
                    next(request)
                } else {
                    Response(FORBIDDEN)
                }
            }
        }
    }

    val authorizationAdminOrOwnerForReadUpdateDelete = Filter { next ->
        { request ->
            val id = request.path("id")!!.toLong()
            val authenticatedUser = authorizationLens.extract(request)
            if (userService.isAdministrator(authenticatedUser)) {
                next(request)
            } else if ((request.method == GET || request.method == DELETE) && authenticatedUser.id == id) {
                next(request)
            } else if(request.method == PUT && authenticatedUser.id == id && !userService.hasAdministratorRole(User.messageLens(request))) {
                next(request)
            } else {
                Response(FORBIDDEN)
            }
        }
    }

    val unprotectedRoutes = routes(
        "login" bind POST to {
            val login = Login.messageLens(it)
            val user = userService.validateLogin(login)
            val authentication = jwtGenerator.createToken(user)
            Response(OK)
                .header(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.value)
                .with(Authentication.messageLens of authentication)
        }
    )

    val optionalProtectedRoutes = optionalBearerFilter.then(
        routes(
            "users" bind routes(
                "" bind POST to authorizationAdminForCreate {
                    val userCreateRequest = User.messageLens(it)
                    val userCreated = userService.create(userCreateRequest)
                    Response(OK)
                        .header(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.value)
                        .with(User.messageLens of userCreated)
                }
            )
        )
    )

    val protectedRoutes = ServerFilters.BearerAuth(authorizationLens, jwtVerifier::verifyToken).then(
        routes(
            "users" bind routes(
                "" bind GET to {
                    val users = userService.readAll()
                    Response(OK)
                        .header(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.value)
                        .with(User.arrayMessageLens of users)
                },
                "/{id}" bind GET to authorizationAdminOrOwnerForReadUpdateDelete {
                    val userId = it.path("id")!!.toLong()
                    val user = userService.read(userId)
                    Response(OK)
                        .header(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.value)
                        .with(User.messageLens of user)
                },
                "/{id}" bind PUT to authorizationAdminOrOwnerForReadUpdateDelete {
                    val userId = it.path("id")!!.toLong()
                    val userUpdateRequest = User.messageLens(it)
                    val userUpdated = userService.update(userId, userUpdateRequest)
                    Response(OK)
                        .header(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.value)
                        .with(User.messageLens of userUpdated)
                },
                "/{id}" bind DELETE to authorizationAdminOrOwnerForReadUpdateDelete {
                    val userId = it.path("id")!!.toLong()
                    userService.delete(userId)
                    Response(OK)
                }
            )
        )
    )

    return ServerFilters
        .InitialiseRequestContext(requestContexts)
        .then(
            routes(unprotectedRoutes, optionalProtectedRoutes, protectedRoutes)
        )
}

fun globalExceptionHandler() = Filter { next ->
    { request ->
        try {
            next(request)
        } catch (ex: InvalidCredentialsException) {
            Response(UNAUTHORIZED)
        } catch (ex: EmailNotAvailable) {
            Response(BAD_REQUEST).status(Status(BAD_REQUEST.code, ex.message))
        } catch (ex: NotFoundException) {
            Response(NOT_FOUND)
        } catch (ex: Exception) {
            ex.printStackTrace()
            Response(INTERNAL_SERVER_ERROR)
        }
    }
}

fun main() {
    val server = globalExceptionHandler().then(initializeApp()).asServer(ApacheServer(8080)).start()
    println("Server started on " + server.port())
}
