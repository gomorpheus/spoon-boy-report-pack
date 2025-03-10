## Spoon Boy Report Pack

A suite of additional reports in a single plugin designed to extend the management information available in Morpheus.

This report pack is built for the post v1.0 plugin framework so requires Morpheus version later than 6.3.0.

### User Reports

#### 2FA Status Report

![2FAStatusOfUsersReport.png](samples%2F2FAStatusOfUsersReport.png)

#### Account Locked Report

![accountLockedReport.png](samples%2FaccountLockedReport.png)

#### Account Disabled Report

![disabledUserAccountsReport.png](samples%2FdisabledUserAccountsReport.png)

#### Password Expired Report

![passwordExpiredReport.png](samples%2FpasswordExpiredReport.png)

#### Failed Login Attempts Report

![failedLoginAttemptsReport.png](samples%2FfailedLoginAttemptsReport.png)

#### Logged in Users Report (Tenant)

![currentlyLoggedInUsersReportTenant.png](samples%2FcurrentlyLoggedInUsersReportTenant.png)

- Logged in Users Report (Appliance, master tenant only) - WIP
- VM Credential Status Report (WIP, SQL in provider)

### Provisioning Inventory Reports

#### Morpheus Agent Installed Version Report

![morpheusAgentInstalledVersionReport.png](samples%2FmorpheusAgentInstalledVersionReport.png)

### Role Reports

- Assigned Role Report (WIP)

### Policy Reports

- Enforcing Policies Report (WIP, SQL in provider)

### In the pipeline

- User Activity Report
- Role > Group Overview Report
- Appliance setup/healthcheck type Report

## Contributing

Contributions are welcome. As you probably know reports are provided via Morpheus plugins.
Each a plugin can comprise one report or many, this report pack is a single plugin. 
Each report is is implemented as a provider, which excutes an SQL statement and 
makes result available to a view, which itself is html and handlebars type variable interpolation.

If you want to build a report, you can folllow one of the included report providers and its view
all you will really need to devise for yourself is the SQL select query which will provide the data 
to your report provider.

When you have created your report provider, you need to register it in the plugin class (SpoonBoyReportPackPlugin.groovy).
Again, it should be simple to follow what has been done for the other report providers.

### Testing

Please test your report provider before making pull requests. Ideally:
- Format your code files
- Ensure the plugin builds
- Ensure the plugin installs into Morpheus
- Ensure it works as expected

### Building

If you know what you are doing you may have a Java and Gradle build environment locally. 
If not, and you have Java installed, you can use the Gradle build wrappers included with the project.
The third option is to use Docker and the command to build the project in a Docker container is included in the Makefile.
You may need to adapt it for Windows, but this approach does not require any local dependencies. I use this approach myself.

### License

TODO (probably MPL 2.0)

