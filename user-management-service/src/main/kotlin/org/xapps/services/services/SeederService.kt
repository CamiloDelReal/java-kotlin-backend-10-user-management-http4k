package org.xapps.services.services

class SeederService(
    private val roleService: RoleService,
    private val userService: UserService,
    private val userRoleService: UserRoleService
) {

    fun seed() {
        roleService.init()
        userService.init()
        userRoleService.init()
        roleService.seed()
        userService.seed()
    }

}