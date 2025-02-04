# varroa_tenable_example

Example application to query Tenable Cloud for security vulnerabilities and create alerts in Nectar Cloud

> :warning: This is just an example application and not-yet ready for production use

## Quickstart

Initialise the Python virtual environment:

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Change configurations in the `app/config.py` file, including:

- `TARGET_CIDRS`: Since Tenable can have a lot of findings, we can limit results to a specific list of CIDR ranges
- `SECURITY_RISK_TYPE_TARGET`: Select a specific risk type, based on the defined risk types already in Nectar Cloud (e.g., "password-ssh")

Set environment variables. Ensure you have the following credentials set in your environment variables. We use the [openstack-bash-creds-helper](https://github.com/NeCTAR-RC/openstack-bash-creds-helper) tool.

- Nectar Application Credentials:
  - `OS_AUTH_URL`
  - `OS_APPLICATION_CREDENTIAL_ID`
  - `OS_APPLICATION_CREDENTIAL_SECRET`
- Tenable Cloud Credentials:
  - `TIO_ACCESS_KEY`
  - `TIO_SECRET_KEY`

Run the main program:

```
cd app
python3 create_security_risks.py
```

## Varroa CLI Client Notes

### Get History of IP Ownership

Find who owned which ip at a specific time.

Old method of matching IP to cloud resource:

```
openstack port list --fixed-ip ip-address=134.245.141.111
openstack port show -c device_id a2226cec2-c778-448c6-b872-bd3222296d7d
```

Problems:

- Can only get current assignment
- No history `:(`

New method:

```
openstack ip history <IPADDRESS>
```

### Create Security Risk Types

- Used for storing information about generic security issues
- These are like templates
- For example:
  - *SSH is exposed to the Internet and has password authentication enabled*
  - *SQL database is exposed to the Internet*

```
openstack security risk type list
openstack security risk type show
openstack security risk type set 
openstack security risk type create
openstack security risk type delete
```

Example of a security risk type:

```
openstack security risk type show <PLACEHOLDER>
+--------------+-------------------------------------------------------+
| Field        | Value                                                 |
+--------------+-------------------------------------------------------+
| description  | Internet-accessible SSH using password authentication |
| display_name | None                                                  |
| help_url     | None                                                  |
| id           | 00232s3b-ej8k-sshj-9e7e-ea8ce6hgbsbb                  |
| name         | password-ssh                                          |
+--------------+-------------------------------------------------------+
```

### Create Security Risk

- Used to create a new security issue to send to a researcher
- They are attached to a Nectar instance
- Basic premise is create an *instance* of the Security Risk Type

```
openstack security risk list
openstack security risk show
openstack security risk create
openstack security risk delete
```

Example of listing all security risks:

```
openstack security risk list --all-projects
+--------------------------------------+----------------------------------+----------------+---------------------------+-----------------+------+-----------+
| id                                   | project_id                       | type           | time                      | ipaddress       | port | status    |
+--------------------------------------+----------------------------------+----------------+---------------------------+-----------------+------+-----------+
| 0023203b-e2d3-1ghj-9e7e-ea8ce56677bb | 764778cagbd1405d909a2699ff5dcc6a | password-ssh   | 2024-10-28 23:05:12+13:00 | <REDACTED> | 3389 | PROCESSED |
| 0054dbeb-ad0c-4c27-9765-f6fc566c1ca2 | 0a430575d09a4123235f383caa1f833e | password-ssh   | 2024-10-29 06:08:37+13:00 | <REDACTED> | 5432 | PROCESSED |
| 005ba17e-d535-11fy-8722-841d351460a6 | 14c67f6978b548d81bhd102edfd7e5cc | password-ssh   | 2024-10-29 08:37:59+13:00 | <REDACTED> |   22 | PROCESSED |
| 01be8c5b-3395-12f3-b84a-3bfd38ddfea8 | f23b47a93b50441c84444a7be878b09c | password-ssh   | 2024-10-29 00:06:22+13:00 | <REDACTED> |   22 | PROCESSED |
| 0277cb10-9ec3-234g-affb-7aa5944f89d2 | 043efa8b4a14216a6987de236e916420 | password-ssh   | 2024-10-29 06:04:01+13:00 | <REDACTED> |   22 | PROCESSED | 
....
```

Create a security risk for SSH with password authentication enabled:

```
openstack security risk create --time 2024-12-16T12:00:00+0000 --expires 2024-12-23T12:00:00+0000 -p 22 -i 130.216.217.243 c59f20bd-cd38-4fd4-be8f-ae2ea88b0460
+---------------+--------------------------------------+
| Field         | Value                                |
+---------------+--------------------------------------+
| expires       | 2024-12-24 01:00:00+13:00            |
| id            | dgg8122f-74a9-4c6f-9172-6333e581062f |
| ipaddress     | <REDACTED>                           |
| port          | 22                                   |
| project_id    | None                                 |
| resource_id   | None                                 |
| resource_type | None                                 |
| status        | NEW                                  |
| time          | 2024-12-17 01:00:00+13:00            |
| type          | password-ssh                         |
+---------------+--------------------------------------+
```

Bash helper for creating timestamps:

```
time=$(date +"%Y-%m-%dT%H:%M:%S%z")
expires=$(date -d "+7 days" +"%Y-%m-%dT%H:%M:%S%z")
```

## Links

- [https://github.com/NeCTAR-RC/python-varroaclient](https://github.com/NeCTAR-RC/python-varroaclient)
- [https://pypi.org/project/varroa/](https://pypi.org/project/varroa/)
- [https://github.com/NeCTAR-RC/varroa](https://github.com/NeCTAR-RC/varroa)
- [https://github.com/NeCTAR-RC/openstack-bash-creds-helper](https://github.com/NeCTAR-RC/openstack-bash-creds-helper)
- [https://www.tenable.com/plugins/search](https://www.tenable.com/plugins/search)
- [https://pytenable.readthedocs.io/en/stable/index.html](https://pytenable.readthedocs.io/en/stable/index.html)

