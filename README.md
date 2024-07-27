#  MXMaven: A tool to identify poorly configured DNS records for mail servers and help prevent domain impersonation attacks

### For a discussion on the background and purpose of this tool, [refer to this blog post](https://blog.kavadias.net/MXMaven/)
## Description:
Large organisations can have hundreds of domains. A threat actor may use a single misconfiguration in one of these domains to their advantage. MXMaven can identify poorly or misconfigured MX, SPF and DMARC records in DNS that may leave a domain susceptible to domain impersonation attacks (i.e. using your domain identity to send phishing emails to victims impersonating your organisation.) MXMaven will also find MX records that do not resolve, which could lead to mail delivery issues or, worse, be a dangling DNS record that could be vulnerable to take-over[^1]. MX Maven can detect SPF and DMARC records that do not comply with RFC standards for strings longer than 255 characters in TXT records. This issue can cause mail services to ignore long SPF and DMARC records. MX Maven will store all DNS lookups for MX, SPF and DMARC in a SQLite database and will provide a report after scanning to highlight poorly configured SPF and DMARC policies or MX resolution issues.


## Install Instructions:

```
git clone https://github.com/nkavadias/mxmaven.git
cd mxmaven
pip install -r requirements.txt
```


## Tool Capabilities

MX Maven can check a single domain using the -s parameter.  Although, it has a more power option of accepting a text file with a domain on each line with the -m parameter.  All DNS record lookups are stored in a relation database, this defaults to SQLite3, but can be easily reconfigured to use MySQL, PosgresSQL and CockroachDB, as it uses the Peewee Python ORM library.


MXMaven has three options to run the tool. The first option is `-s` or `--single`, which checks a single domain. The second option is `-m` or `--multidomain`, which accepts a text file with a domain on each line. The third option is `-a` or `--showall`, which prints a report of all stored records. The tool stores all DNS record lookups in a relation database, which defaults to SQLite3. However, it can be easily reconfigured to use MySQL, PosgresSQL, and CockroachDB, as it uses the Peewee Python ORM library.

Here is the sample result from running ``python mxmaven.py -m demo.txt ``

![demo output](/result_demo.png)

Here are the details of the switch options:

| **Option** | **Description**                                                                  |
|------------|-----------------                                                                 |
| `-h`, `--help` | Shows the help message and exits.                                            |
| `-s DOMAIN_NAME`, `--single DOMAIN_NAME` | Runs the tool in single domain mode.               |
| `-m DOMAIN_NAME_LIST.TXT`, `--multidomain DOMAIN_NAME_LIST.TXT` | Runs the tool in multiple domain mode. Accepts a text file with a domain on each line. |
| `-a`, `--showall` | Prints a report of all stored records. |
| `-v`, `--verbose` | Increases output verbosity. |
| `-d SQLITE3_DB_FILE.DB`, `--sqlitedb SQLITE3_DB_FILE.DB` | Uses an alternative Sqlitedb. The default is mxmaven.db. |



## Project TODOS:
- Implement multiprocessing or multithreading for DNS lookups.
- Do additional checks to identify dangling MX records such records which point to domains no longer registered or parked, or public cloud hostnames which are not responding (may be possible for takeover?)
- Inspect authorized hosts in SPF which are too broad and could allow any sending from a third party to impersonate domain (e.g. generic SendGrid hosts, or large IP ranges).
- Additional tool parameter to allow easy export to csv, JSON of table records from SQLite.
- Record and save TLS certificates for mail servers that support secure transport.
