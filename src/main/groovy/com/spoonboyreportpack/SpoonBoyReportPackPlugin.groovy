/*
* Copyright 2022 the original author or authors.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package com.spoonboyreportpack

import com.morpheusdata.core.Plugin
import com.morpheusdata.model.Permission

class SpoonBoyReportPackPlugin extends Plugin {

    @Override
    String getCode() {
        return 'spoon-boy-report-pack'
    }

    @Override
    void initialize() {
        this.setName("Spoon Boy Report Pack")
        this.setDescription("A suite of additional reports for Morpheus")
        this.setAuthor("Ollie Phillips")

        // user reports
        // 2FA status
        this.registerProvider(new User2FAStatusReportProvider(this,this.morpheus))

        // disabled accounts
        this.registerProvider(new UserAccountDisabledReportProvider(this,this.morpheus))

        // password expired
        this.registerProvider(new UserPasswordExpiredReportProvider(this,this.morpheus))

        // account locked (too many login attempts)
        this.registerProvider(new UserAccountLockedReportProvider(this,this.morpheus))

        // users VM credentials
        //this.registerProvider(new UserVMCredentialsStatusReportProvider(this,this.morpheus))

        // failed logins
        this.registerProvider(new UserFailedLoginReportProvider(this,this.morpheus))

        // logged in users
        this.registerProvider(new UserLoggedInUsersReportProvider(this,this.morpheus)) //tenant
        //this.registerProvider(new UserLoggedInUsersApplianceReportProvider(this,this.morpheus)) //master only (appliance wide)


        // role reports
        // assigned roles
        //this.registerProvider(new RoleAssignedRoleReportProvider(this,this.morpheus))

        // provisioning inventory
        // Morpheus Agent installed versions
        this.registerProvider(new ProvisioningInventoryMorpheusAgentInstalledVersionReportProvider(this,this.morpheus))

        // cypher password access
        this.registerProvider(new CypherPasswordAccessReportProvider(this,this.morpheus))

    }

    /**
     * Called when a plugin is being removed from the plugin manager (aka Uninstalled)
     */
    @Override
    void onDestroy() {
        //nothing to do for now
    }
}
