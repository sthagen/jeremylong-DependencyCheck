Tasks
====================

Task                                                     | Description
---------------------------------------------------------|-----------------------
[dependencyCheckAnalyze](configuration.html)             | Runs dependency-check against the project and generates a report.
[dependencyCheckAggregate](configuration-aggregate.html) | Runs dependency-check against a multi-project build and generates a report.
dependencyCheckUpdate                                    | Updates the local cache of the NVD data from NIST.
[dependencyCheckPurge](configuration-purge.html)         | Deletes the local copy of the NVD. This is used to force a refresh of the data.

Configuration
====================

```groovy
buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath 'org.owasp:dependency-check-gradle:${project.version}'
    }
}
apply plugin: 'org.owasp.dependencycheck'

check.dependsOn dependencyCheckUpdate
```

Property             | Description                        | Default Value
---------------------|------------------------------------|------------------
failOnError          | Fails the build if an error occurs during the dependency-check analysis.                                           | true

#### Example
```groovy
dependencyCheck {
    failOnError=true
}
```

### Proxy Configuration

Config Group | Property          | Description                                | Default Value
-------------|-------------------|--------------------------------------------|------------------
proxy        | server            | The proxy server; see the [proxy configuration](../data/proxy.html) page for more information. | &nbsp;
proxy        | port              | The proxy port.                            | &nbsp;
proxy        | username          | Defines the proxy user name.               | &nbsp;
proxy        | password          | Defines the proxy password.                | &nbsp;
proxy        | nonProxyHosts     | The list of hosts that do not use a proxy. | &nbsp;

#### Example
```groovy
dependencyCheck {
    proxy {
        server=some.proxy.server
        port=8989
    }
}
```

### Advanced Configuration

The following properties can be configured in the dependencyCheck task. However, they are less frequently changed.

Config Group | Property          | Description                                                                                                  | Default Value                                                       |
-------------|-------------------|--------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------|
nvd          | apiKey            | The API Key to access the NVD API; obtained from https://nvd.nist.gov/developers/request-an-api-key          | &nbsp;                                                              |
nvd          | endpoint          | The NVD API endpoint URL; setting this is uncommon.                                                          | https://services.nvd.nist.gov/rest/json/cves/2.0                    |
nvd          | maxRetryCount     | The maximum number of retry requests for a single call to the NVD API.                                       | 10                                                                  |
nvd          | delay             | The number of milliseconds to wait between calls to the NVD API.                                             | 3500 with an NVD API Key or 8000 without an API Key .               |
nvd          | datafeedUrl       | The URL for the NVD API Data feed that can be generated using https://github.com/jeremylong/Open-Vulnerability-Project/tree/main/vulnz#caching-the-nvd-cve-data | &nbsp;           |
nvd          | datafeedUser      | Credentials used for basic authentication for the NVD API Data feed.                                         | &nbsp;                                                              |
nvd          | datafeedPassword  | Credentials used for basic authentication for the NVD API Data feed.                                         | &nbsp;                                                              |
nvd          | validForHours     | The number of hours to wait before checking for new updates from the NVD. The default is 4 hours.            | 4                                                                   |
data         | directory         | Sets the data directory to hold SQL CVEs contents. This should generally not be changed.                     | &nbsp;                                                              |
data         | driver            | The name of the database driver. Example: org.h2.Driver.                                                     | &nbsp;                                                              |
data         | driverPath        | The path to the database driver JAR file; only used if the driver is not in the class path.                  | &nbsp;                                                              |
data         | connectionString  | The connection string used to connect to the database. See using a [database server](../data/database.html). | &nbsp;                                                              |
data         | username          | The username used when connecting to the database.                                                           | &nbsp;                                                              |
data         | password          | The password used when connecting to the database.                                                           | &nbsp;                                                              |
hostedSuppressions | enabled         | Whether the hosted suppressions file will be used.                                                       | true                                                                |
hostedSuppressions | forceupdate     | Sets whether hosted suppressions file will update regardless of the `autoupdate` setting.                | false                                                               |
hostedSuppressions | url             | The URL to the Retire JS repository.                                                                     | https://jeremylong.github.io/DependencyCheck/suppressions/publishedSuppressions.xml |
hostedSuppressions | validForHours   | The number of hours to wait before checking for new updates of the hosted suppressions file .            | 2                                                                   |

#### Example
```groovy
dependencyCheck {
    data {
        directory='d:/nvd'
    }
}
```
