package org.xapps.services.services

import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.SchemaUtils
import org.jetbrains.exposed.sql.transactions.transaction
import org.xapps.services.daos.tables.UsersRoles

class UserRoleService(
    private val database: Database
) {

    fun init() = transaction(
        db = database
    ) {
        SchemaUtils.create(UsersRoles)
    }

}