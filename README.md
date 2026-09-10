# Cisco Secure Access Private Resource Importer for Windows

This guide explains how to create Cisco Secure Access Private Resources from a
Windows computer. The importer creates Cisco Secure Client RDP resources with
TCP-RDP on port 3389. It does not assign resources to Resource Connector
Groups or change access policies.

## Before you begin

You need:

- Python 3.10 or later.
- The importer files in one local folder:
  - `private_resource_importer.py`
  - a CSV file, if importing multiple resources
- A Cisco Secure Access API key with these permissions:
  - `policies.privateresources:read`
  - `policies.privateresources:write`
- The API key client ID and client secret.
- The numeric internal DNS server ID to use. You can retrieve it from an
  existing correctly configured Private Resource with the read-only command
  shown below.

The importer uses only Python standard-library modules. It does not require a
Python package installation or a virtual environment.

## Confirm Python

Open **Command Prompt** and run:

```bat
py --version
```

If this reports Python 3.10 or later, continue. If `py` is not recognized,
install Python from [python.org](https://www.python.org/downloads/windows/) and
select **Add Python to PATH** during installation.

## Open the importer folder

In Command Prompt, change to the folder containing the script. Replace the
example path with the actual folder:

```bat
cd /d C:\Secure-Access-Importer
```

## Set API credentials for the current session

Run the following commands, replacing the placeholder values:

```bat
set "CISCO_SECURE_ACCESS_CLIENT_ID=your-client-id"
set "CISCO_SECURE_ACCESS_CLIENT_SECRET=your-client-secret"
set "CISCO_SECURE_ACCESS_DNS_SERVER_ID=123456"
```

These commands are the Windows Command Prompt equivalent of macOS/Linux
`export`. They set credentials only in the current Command Prompt window.
Closing that window clears them. Do not place credentials in the CSV file or
in `private_resource_importer.py`.

`CISCO_SECURE_ACCESS_DNS_SERVER_ID` is a tenant-specific configuration value,
not a secret. Use the `dnsServerId` from a working resource that uses the DNS
server you want; do not substitute a Resource Connector Group ID or name.

## Create one resource

Start with a dry run. It reads Cisco configuration and validates the planned
resource, but does not create or change anything:

```bat
py private_resource_importer.py --fqdn rdp-01.customer.internal
```

Review the JSON output. Confirm:

- `status` is `dry-run`
- `protocol` is `RDP-TCP`
- `port` is `3389`
- The DNS server selection is correct

Create the resource only after the dry run is correct:

```bat
py private_resource_importer.py --fqdn rdp-01.customer.internal --apply
```

The importer verifies the created resource's name, Cisco Secure Client access,
DNS server, protocol, and port. Cisco may normalize the returned protocol to
lowercase `rdp-tcp`; this is expected.

## Create resources from a CSV file

Create a UTF-8 CSV file with one required column named `fqdn`. For example,
save this as `private_resources.csv`:

```csv
fqdn
rdp-01.customer.internal
rdp-02.customer.internal
rdp-03.customer.internal
```

There are no commas after the FQDNs because this CSV contains only one column.
The selected DNS server is used for every resource in that one import run.

Run a dry run first:

```bat
py private_resource_importer.py --csv private_resources.csv
```

After reviewing every planned entry, apply it:

```bat
py private_resource_importer.py --csv private_resources.csv --apply
```

The importer creates resources serially and stops at the first failure. Any
resources verified before a later failure remain created. A retry must use a
CSV that omits any resources that were already created.

## One-command DNS override

To override the configured DNS server ID for one command:

```bat
py private_resource_importer.py --csv private_resources.csv --dns-server-id 123456
```

## After creation

1. In Secure Access, confirm the resource address, TCP-RDP/3389, and internal
   DNS selection.
2. Add created resources to the appropriate Resource Connector Group in the
   Secure Access GUI, using the normal bulk-add workflow if needed.
3. Confirm that an access policy allows the intended Cisco Secure Client users.
   This importer does not create or modify access policies.
4. Check the Admin audit log. API-created resource events may be attributed to
   **Cisco Systems Agent** and can take a few minutes to appear.

## Safe inspection commands

These commands make no changes:

```bat
py private_resource_importer.py --show-connector-group "Customer DNS Connector Group"
py private_resource_importer.py --show-private-resource 123456
```

`--show-private-resource` is the relevant command for finding a DNS server ID.
`--show-connector-group` is optional diagnostic output and is not involved in
resource creation. It requires the additional
`deployments.resourceconnectors:read` API permission.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `py` is not recognized | Install Python 3.10+ and reopen Command Prompt. |
| Credential error | Set both API environment variables in the same Command Prompt window used to run the importer. |
| DNS server ID error | Set `CISCO_SECURE_ACCESS_DNS_SERVER_ID` to a positive numeric `dnsServerId` copied from a correctly configured Private Resource. |
| Resource name already exists | The importer is create-only. Remove the existing resource only if approved, or use a different FQDN. |
| CSV stops after a failure | Review the reported row. Previously created rows remain in Cisco Secure Access and must be omitted before retrying. |
| Audit entry is not visible immediately | Confirm the resource in Private Resources first, then refresh the audit log after a few minutes. |

## Clear credentials

Close the Command Prompt window when finished. To clear values without closing
the window, run:

```bat
set "CISCO_SECURE_ACCESS_CLIENT_ID="
set "CISCO_SECURE_ACCESS_CLIENT_SECRET="
set "CISCO_SECURE_ACCESS_DNS_SERVER_ID="
```
