# issue-linker

This is a tool to link issues between SAST vendors and BrightSec DAST.
It also allows to run validation scan based on the SAST scan results.

## Installation

### From Source

1. [Install Crystal](https://crystal-lang.org/docs/installation/)
2. `git clone` this repo
3. `cd` into the repo
4. `shards build`

### From Releases

1. Download the latest release from the [releases page](https://github.com/NeuraLegion/issue-linker/releases)
2. Look for the binary for your OS and architecture
3. Download it to your working directory
4. execute with `./issue-linker`. You may need to `chmod +x` the binary first.

### From Docker

#### Docker Build Option

1. `git clone` this repo
2. `cd` into the repo
3. `docker build -t issue-linker .`
4. `docker run -it issue-linker --help`

#### Docker Pull Option

1. `docker pull neuralegion/issue-linker`
2. `docker run -it neuralegion/issue-linker --help`

## Usage

`issue-linker --help` to see the help menu

The tool has different options based on the relevant vendor, for Snyk you can use the following options:

`issue-linker Snyk --help`

This will show the help menu for the Snyk vendor.

```bash
Usage: issue-linker [subcommand] [arguments]
    -h, --help                       Show this help
    Link-Issues                      Link Snyk and Bright issues
    Verification-Scan                Run a verification scan based on Snyk Code findings
```

You can choose a different vendor as well, listing avialable vendors can be done with:

```bash
./issue-linker --help
Usage: issue-linker [subcommand] [arguments]
    Snyk                             Snyk Integration
    CX                               Checkmarx
    -h, --help                       Show this help
```

### Link-Issues

This command will link issues between Snyk and BrightSec.

```bash
Usage: issue-linker Snyk [arguments]
    -h, --help                       Show this help
    --snyk-token TOKEN               Api-Key for the snyk platform
    --snyk-org ORG                   Snyk org UUID
    --snyk-project PROJECT           Snyk project UUID
    --bright-token TOKEN             Api-Key for the Bright platform
    --bright-scan SCAN               Bright scan ID
    --output TYPE                    Type of Output, default: json. [json,markdown,ascii] (Optional)
    --update                         Update Bright issues with Snyk issue links

```

Example command can looks like the following for Checkmarx:

```bash
./issue-linker CX Link-Issues --bright-token XXX --cx-token XXX --cx-scan=UUID --bright-scan esmkpk584o2UHdad1s3mHj --update --output ascii
```

An Example of the possible markdown output:

```markdown
 ------------------------------------- --------- -------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------
| Issue name                          | CWE     | Snyk issue URL                                                                                                                             | Bright issue URL                                                                                         |
|-------------------------------------|---------|--------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| Cross-site Scripting (XSS)          | CWE-79  | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-b7dae014-653a-48da-b011-3cb61442d696) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/cHmgTrrXy8RWUxtxyD8Pk8) |
| Cross-site Scripting (XSS)          | CWE-79  | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-063a7c98-2225-48a2-893f-d973df45f039) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/trNW9XWMzXBmvQbng6oTEN) |
| Server-Side Request Forgery (SSRF)  | CWE-918 | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-3909e99d-c7b5-4a28-b8b9-e9386d3549e9) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/2CjaWdsEx89QojKc22iPiS) |
| Server-Side Request Forgery (SSRF)  | CWE-918 | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-876d02ab-7ddf-41bc-bd1e-bcbe96350d20) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/2JEsNQBg6anpX8SDKc5LuN) |
| Command Injection                   | CWE-78  | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-701b3fcf-5a73-431e-844b-e2efb043f0c4) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/gGnbb91pCYYSEPsf8xGT9c) |
| SQL Injection                       | CWE-89  | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-a06e7f8e-f93d-43c4-a2f2-d657251bb911) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/myayD5vcFrxz5FyWPQMn5Q) |
| Cross-site Scripting (XSS)          | CWE-79  | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-5dac60b3-5cce-4e57-97cc-cfa870313341) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/n5n5VkU3krbdaDhSVAxpMQ) |
| XML External Entity (XXE) Injection | CWE-611 | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-ff85e9d1-c896-4ac1-86a9-6fbeea37c442) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/qQMxUyZXvWw7XxiHAs5Cmr) |
| Open Redirect                       | CWE-601 | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-b36659b8-6e48-418f-bcea-50bf64d2b768) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/1dD8ht6WGrF6djkxSnrXyu) |
 -------------------------------------|---------|--------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------
```

Which will be parsed as a table:

 ------------------------------------- --------- -------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------
| Issue name                          | CWE     | Snyk issue URL                                                                                                                             | Bright issue URL                                                                                         |
|-------------------------------------|---------|--------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| Cross-site Scripting (XSS)          | CWE-79  | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-b7dae014-653a-48da-b011-3cb61442d696) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/cHmgTrrXy8RWUxtxyD8Pk8) |
| Cross-site Scripting (XSS)          | CWE-79  | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-063a7c98-2225-48a2-893f-d973df45f039) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/trNW9XWMzXBmvQbng6oTEN) |
| Server-Side Request Forgery (SSRF)  | CWE-918 | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-3909e99d-c7b5-4a28-b8b9-e9386d3549e9) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/2CjaWdsEx89QojKc22iPiS) |
| Server-Side Request Forgery (SSRF)  | CWE-918 | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-876d02ab-7ddf-41bc-bd1e-bcbe96350d20) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/2JEsNQBg6anpX8SDKc5LuN) |
| Command Injection                   | CWE-78  | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-701b3fcf-5a73-431e-844b-e2efb043f0c4) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/gGnbb91pCYYSEPsf8xGT9c) |
| SQL Injection                       | CWE-89  | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-a06e7f8e-f93d-43c4-a2f2-d657251bb911) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/myayD5vcFrxz5FyWPQMn5Q) |
| Cross-site Scripting (XSS)          | CWE-79  | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-5dac60b3-5cce-4e57-97cc-cfa870313341) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/n5n5VkU3krbdaDhSVAxpMQ) |
| XML External Entity (XXE) Injection | CWE-611 | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-ff85e9d1-c896-4ac1-86a9-6fbeea37c442) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/qQMxUyZXvWw7XxiHAs5Cmr) |
| Open Redirect                       | CWE-601 | [Snyk Issue URL](https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-b36659b8-6e48-418f-bcea-50bf64d2b768) | [Bright Issue URL](https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/1dD8ht6WGrF6djkxSnrXyu)

Or as JSON for automation purpose:

```json
[{"snyk_issue":{"id":"b7dae014-653a-48da-b011-3cb61442d696","title":"Cross-site Scripting (XSS)","cwe":["CWE-79"],"url":"https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-b7dae014-653a-48da-b011-3cb61442d696"},"bright_issue":{"id":"cHmgTrrXy8RWUxtxyD8Pk8","name":"Reflective Cross-site scripting (rXSS)","cwe":"CWE-79","url":"https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/cHmgTrrXy8RWUxtxyD8Pk8"}},{"snyk_issue":{"id":"063a7c98-2225-48a2-893f-d973df45f039","title":"Cross-site Scripting (XSS)","cwe":["CWE-79"],"url":"https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-063a7c98-2225-48a2-893f-d973df45f039"},"bright_issue":{"id":"trNW9XWMzXBmvQbng6oTEN","name":"Reflective Cross-site scripting (rXSS)","cwe":"CWE-79","url":"https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/trNW9XWMzXBmvQbng6oTEN"}},{"snyk_issue":{"id":"3909e99d-c7b5-4a28-b8b9-e9386d3549e9","title":"Server-Side Request Forgery (SSRF)","cwe":["CWE-918"],"url":"https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-3909e99d-c7b5-4a28-b8b9-e9386d3549e9"},"bright_issue":{"id":"2CjaWdsEx89QojKc22iPiS","name":"Server Side Request Forgery","cwe":"CWE-918","url":"https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/2CjaWdsEx89QojKc22iPiS"}},{"snyk_issue":{"id":"876d02ab-7ddf-41bc-bd1e-bcbe96350d20","title":"Server-Side Request Forgery (SSRF)","cwe":["CWE-918"],"url":"https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-876d02ab-7ddf-41bc-bd1e-bcbe96350d20"},"bright_issue":{"id":"2JEsNQBg6anpX8SDKc5LuN","name":"Server Side Request Forgery","cwe":"CWE-918","url":"https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/2JEsNQBg6anpX8SDKc5LuN"}},{"snyk_issue":{"id":"701b3fcf-5a73-431e-844b-e2efb043f0c4","title":"Command Injection","cwe":["CWE-78"],"url":"https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-701b3fcf-5a73-431e-844b-e2efb043f0c4"},"bright_issue":{"id":"gGnbb91pCYYSEPsf8xGT9c","name":"OS Command Injection","cwe":"CWE-78","url":"https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/gGnbb91pCYYSEPsf8xGT9c"}},{"snyk_issue":{"id":"a06e7f8e-f93d-43c4-a2f2-d657251bb911","title":"SQL Injection","cwe":["CWE-89"],"url":"https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-a06e7f8e-f93d-43c4-a2f2-d657251bb911"},"bright_issue":{"id":"myayD5vcFrxz5FyWPQMn5Q","name":"SQL DB Error Message In Response","cwe":"CWE-89","url":"https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/myayD5vcFrxz5FyWPQMn5Q"}},{"snyk_issue":{"id":"5dac60b3-5cce-4e57-97cc-cfa870313341","title":"Cross-site Scripting (XSS)","cwe":["CWE-79"],"url":"https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-5dac60b3-5cce-4e57-97cc-cfa870313341"},"bright_issue":{"id":"n5n5VkU3krbdaDhSVAxpMQ","name":"Reflective Cross-site scripting (rXSS)","cwe":"CWE-79","url":"https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/n5n5VkU3krbdaDhSVAxpMQ"}},{"snyk_issue":{"id":"ff85e9d1-c896-4ac1-86a9-6fbeea37c442","title":"XML External Entity (XXE) Injection","cwe":["CWE-611"],"url":"https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-ff85e9d1-c896-4ac1-86a9-6fbeea37c442"},"bright_issue":{"id":"qQMxUyZXvWw7XxiHAs5Cmr","name":"XML External Entity (XXE)","cwe":"CWE-611","url":"https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/qQMxUyZXvWw7XxiHAs5Cmr"}},{"snyk_issue":{"id":"b36659b8-6e48-418f-bcea-50bf64d2b768","title":"Open Redirect","cwe":["CWE-601"],"url":"https://app.snyk.io/org/bararchy/project/3f86c938-d091-403b-9d80-f3d62dbad9c5#issue-b36659b8-6e48-418f-bcea-50bf64d2b768"},"bright_issue":{"id":"1dD8ht6WGrF6djkxSnrXyu","name":"Unvalidated Redirect","cwe":"CWE-601","url":"https://app.brightsec.com/scans/tLyeJ6uBNW7GckD3Th7gv5/issues/1dD8ht6WGrF6djkxSnrXyu"}}]
```

> **Note**
> Using the `--update` option will allow to update Bright Issues with the relevant vendor input
![image](https://github.com/NeuraLegion/issue-linker/assets/1631073/5dcab9d2-d319-4445-994c-1f525d9a5be6)

### Verification-Scan

This command will allow you to run a verification scan based on a SAST scan that was previously run.

```bash
Usage: issue-linker [subcommand] [arguments]
    -h, --help                       Show this help
    --snyk-token TOKEN               Api-Key for the snyk platform
    --snyk-org ORG                   Snyk org UUID
    --snyk-project PROJECT           Snyk project UUID
    --bright-token TOKEN             Api-Key for the Bright platform
    -t TARGET, --target TARGET       Target to scan by bright DAST
    --output TYPE                    Type of Output, default: json. [json,markdown,ascii] (Optional)
```

> **Note**
> Target option (-t) should be provided in the following format: `https://www.example.com`.

## Contributing

1. Fork it (<https://github.com/NeuraLegion/issue-linker/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Bar Hofesh](https://github.com/bararchy) - creator and maintainer
