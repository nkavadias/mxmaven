# TODO:
# extend mxrecord model with the has_different_backup
# which compares domains & returns true if two mxs have different domains
# extend txtrecord to work out how effective spf record is

from model import *
from hashlib import md5
from datetime import datetime
import sys
import os
import re
import inflect
import dns.resolver
import argparse
import time
import tabulate

def create_views():
    database.execute_sql("DROP VIEW IF EXISTS DomainReport;")
    database.execute_sql('''
CREATE VIEW DomainReport
AS
SELECT
    name AS domain,
    CASE
    WHEN s.policy = 'PASS'      THEN '\x1b[31mPASS\x1b[39m'
    WHEN s.policy = 'NEUTRAL'   THEN '\x1b[33mNEUTRAL\x1b[39m'
    WHEN s.policy IS NULL       THEN '\x1b[33mNOT SET\x1b[39m'
    WHEN s.policy = 'HARD_FAIL' THEN '\x1b[32mHARD_FAIL\x1b[39m'
    ELSE s.policy
    END AS SPF_policy,

    CASE
    WHEN dm.policy IS NULL             THEN '\x1b[31mNOT SET\x1b[39m'
    WHEN dm.policy = 'NONE'            THEN '\x1b[31mNONE\x1b[39m'
    WHEN dm.policy = 'REJECT'          THEN '\x1b[32mREJECT\x1b[39m'
    WHEN dm.policy = 'QUARANTINE'      THEN '\x1b[33mQUARANTINE\x1b[39m'
    ELSE s.policy
    END AS DMARC_policy,
    CASE
        WHEN dm.is_valid = 0 THEN '\x1b[31mNO-DMARC\x1b[39m'
        WHEN s.is_valid = 0 THEN '\x1b[31mNO-SPF\x1b[39m'
        WHEN dm.is_valid = 1 AND s.is_valid = 1 THEN 'OK'
        WHEN dm.is_valid = 0 AND s.is_valid = 0 THEN '\x1b[31mNO-DMARC\x1b[39m'
        ELSE 'N/A'
    END AS TXT_length_OK,
    CASE
        WHEN d.has_mx = 1 THEN 'OK'
        WHEN d.has_mx = 2 THEN '\x1b[31mNO\x1b[39m'
        ELSE 'N/A'
    END as MX_OK,
     MAX(COALESCE(d.date_added, 0), COALESCE(d.date_updated, 0)) AS last_updated
FROM
    domain d
    LEFT JOIN SpfRecord s ON d.hash_id = s.hash_id
    LEFT JOIN DmarcRecord dm ON d.hash_id = dm.hash_id
WHERE
    (d.has_mx = 1 AND (s.policy IN ('NEUTRAL', 'PASS')) OR
    (dm.policy = 'NONE' OR dm.policy IS NULL ) OR
    s.is_valid = 0 OR
    dm.is_valid = 0 OR
    (dm.policy is null and s.policy is null) OR
    d.has_mx = 2 OR
    (d.has_mx = 1 AND d.has_dmarc = 0 AND d.has_spf = 0 )
    );
''')


def get_or_insert_mx_record(hash_id, exchanger, preference, is_valid):
    global TIMESTAMP
    try:
        # Try to retrieve the record from the database
        mx_record = MxRecord.get(MxRecord.hash_id == hash_id, MxRecord.exchanger== exchanger, MxRecord.preference == preference )
    except DoesNotExist:
        # If the record doesn't exist, create a new one
        mx_record = MxRecord.create(hash_id=hash_id, exchanger=exchanger, preference=preference, date_added=TIMESTAMP, is_valid=is_valid )
    return mx_record


def get_or_insert_spf_record(hash_id, value):
    global TIMESTAMP
    try:
        # Try to retrieve the record from the database
        record = SpfRecord.get(SpfRecord.hash_id == hash_id, SpfRecord.value == value )
    except DoesNotExist:
        # If the record doesn't exist, create a new one
        record = SpfRecord.create(hash_id=hash_id, value=value, date_added=TIMESTAMP )
    return record

def get_or_insert_dmarc_record(hash_id, value):
    global TIMESTAMP
    try:
        # Try to retrieve the record from the database
        record = DmarcRecord.get(DmarcRecord.hash_id == hash_id, DmarcRecord.value == value )
    except DoesNotExist:
        # If the record doesn't exist, create a new one
        record = DmarcRecord.create(hash_id=hash_id, is_dmarc=1, value=value, date_added=TIMESTAMP )
    return record


def is_domain(name):
    pattern = r"^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$"
    match = re.match(pattern, name) # Try to match the string with the pattern
    if match:
        return True
    else:
        return False

def is_spf(txtrecord):
    pattern = r"^\"v\=spf1"
    match = re.match(pattern, txtrecord, re.IGNORECASE) # Try to match the string with the pattern
    if match:
        return True
    else:
        return False

# do some setup for SQLite
def create_tables( DATABASE_PATH):
    database.init(DATABASE_PATH)
    with database:
        database.create_tables([Domain, MxRecord, SpfRecord, DmarcRecord], safe=True)


#used for hashing domain name into a hash id
def get_hash( value ):
    result = md5(value.encode('utf-8'))
    return result.hexdigest()

#lets see if hostname resolves to something
def is_host(hostname):
    try:
        answers = dns.resolver.resolve(hostname)
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return False

def Get_MxRecord(domain: Domain):
    #
    global VERBOSE
    try:
        mx_records = dns.resolver.resolve(domain.name, 'MX')
        found_invalid_mx = 0
        if len(mx_records) >0:
            for mx in mx_records:
                exchange = str(mx.exchange)
                exchange = exchange[0:-1]
                preference = str(mx.preference)
                print(f"Found MX: {exchange} , preference {preference} ") if VERBOSE else None
                if is_host(exchange):
                    is_valid = 1
                else:
                    is_valid = 0
                    found_invalid_mx = 1
                get_or_insert_mx_record(domain.hash_id , exchange, preference, is_valid )

        if len(mx_records) == 0:
            domain.has_mx = 0
        elif len(mx_records) > 0 and found_invalid_mx == 1:
            domain.has_mx = 2
        elif len(mx_records) > 0 and found_invalid_mx == 0:
            domain.has_mx = 1
        else:
            ...
        domain.save()

        return True
    except Exception as e:
        domain.status = str(type(e).__name__)
        domain.has_mx = 0
        print(f"NS lookup error: {type(e).__name__} for {domain.name} ")
        domain.save()
        return False

def Get_SpfRecord(domain: Domain):
    #
    result = []
    try:
        result = dns.resolver.resolve(domain.name, 'TXT')
    except:
        print(f'No TXT record found for {domain.name}') if VERBOSE else None
        return
    for r in result:
        if is_spf(str(r)) == True:
            print(f"Found SPF {str(r)}" ) if VERBOSE else None
            domain.has_spf = 1
            spfObj =get_or_insert_spf_record(domain.hash_id, str(r))
            if spfObj.valid == False:
                print(f"{domain.name} failed spf length check for TXT") if VERBOSE else None
            spfObj.check_policy()
    domain.save()



def Get_DmarcRecord(domain: Domain):
    #
    dmarc_record = '_dmarc.' + domain.name
    result = []
    try:
        result = dns.resolver.resolve(dmarc_record, 'TXT')
    except:
        print(f"No DMARC record found for {domain.name}") if VERBOSE else None

    for r in result:
        print(f"Found DMARC {str(r)}" ) if VERBOSE else None
        domain.has_dmarc =1
        domain.save()
        dmarcObj = get_or_insert_dmarc_record(domain.hash_id, str(r))
        if dmarcObj.valid == False:
            print(f"{domain.name} failed DMARC length check for TXT") if VERBOSE else None
        dmarcObj.check_policy()


#TO DO: put some regex checking on line for a domain
def Add_MultiDomain(txtfile):
    global VERBOSE
    with open(txtfile, "r") as file:
        i=0
        for line in file:
            i+=1
            if ( i % 500 == 0):
                print(f"loaded {str(i)} domains... ") if VERBOSE else None
            if (len(line.strip()) == 0 or line.strip()[0] == "#" or line.strip()[0] == ""):
                continue # the line is commented out or blank
            if (is_domain(line)):
                Add_SingleDomain(line)
            else:
                raise ValueError(f"{line} is not a domain")

def Add_SingleDomain(domain):
    #make domain names consistent
    global TIMESTAMP
    domain = domain.lower().replace(" ","").strip()
    hash = get_hash(domain)
    #domain1 = Domain.create(date_added=datetime.now(),name=domain, hash_id=get_hash(domain))
    try:
        result = (Domain
              .insert(hash_id=hash , date_added=TIMESTAMP, name=domain, status='NEW')
              .on_conflict(
                  conflict_target=(Domain.hash_id,), # Specify the unique constraint
                  preserve=(Domain.date_added, Domain.name), # Specify the fields to be preserved
                  update={Domain.status: 'REFRESH', Domain.date_updated: TIMESTAMP}
                  ) # Specify the field to be updated
              .execute())
        return result
    except:
        sys.exit("Problem writing to SQLite database")

def Get_Report():
    global TIMESTAMP
    global SHOWALL
    global SHOWALL
    p = inflect.engine()
    if SHOWALL == 0:
        domain_count = Domain.select().where(
            Domain.status == "DONE", ((Domain.date_added == TIMESTAMP) | (Domain.date_updated == TIMESTAMP))
            ).count()
        print(f"Scanned {domain_count} {p.plural('domain', domain_count)}.")
    if (SHOWALL) >0:
        SHOWALL = "OR 1=1"
    else:
        SHOWALL =""
    query = "SELECT * FROM DomainReport WHERE last_updated = ? " + SHOWALL
    with database:
        cursor = database.execute_sql(query, (TIMESTAMP.strftime('%Y-%m-%d %H:%M:%S.%f'),))
        results = cursor.fetchall()
        if len(results) == 0:
            print("No domains with SPF or DMARC issues discovered")
        else:
            headers = [column[0] for column in cursor.description]
            print(tabulate.tabulate(results, headers=headers, tablefmt='simple'))


######################################## APP VARS AND STARTUP CALLS #######################################################################
SCRIPT_PATH = os.path.dirname(__file__)
VERBOSE = 0
SHOWALL = 0
TIMESTAMP = datetime.now()
########################################################################################################################
def main():
    start = time.perf_counter()
    # create a parser object
    parser = argparse.ArgumentParser(description='MX Maven will check the MX, DMARC and SPF records for a \
        domain. MXMaven will store a historic record of any domain it checks in a SQLite3 database.')

    # add a mutually exclusive group of arguments
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--single', help='run in single domain mode', metavar='DOMAIN_NAME')
    group.add_argument('-m', '--multidomain', help='run in multiple domain mode', metavar='DOMAIN_NAME_LIST.TXT')
    group.add_argument('-a', '--showall', help='print report of all stored records', action='store_true')
    parser.add_argument('-v', '--verbose', help='increase output verbosity', action='store_true')
    parser.add_argument('-d', '--sqlitedb', help='use an alternative Sqlitedb, default is mxmaven.db', metavar='SQLITE3_DB_FILE.DB', default ='./mxmaven.db')
    # parse the arguments
    args = parser.parse_args()
    global VERBOSE
    VERBOSE = 1 if args.verbose else 0
    global SHOWALL
    SHOWALL =1 if args.showall else 0
    global SCRIPT_PATH
    global DATABASE_PATH
    DATABASE_PATH = os.path.join(SCRIPT_PATH, args.sqlitedb)
    create_tables(DATABASE_PATH)
    create_views()
    # check the option and perform the corresponding action
    if args.single:
        ########################## SINGLE DOMAIN MODE ###################################################################
        domain = args.single
        print(f'Running in single domain mode with {domain}') if VERBOSE else None
        # Add to Domains list to scan
        Add_SingleDomain(domain)

    elif args.showall:
        print(f"Showing all domain records in {DATABASE_PATH} \n")

    elif args.multidomain:
        ########################## MULTIPLE DOMAIN MODE ###################################################################
        filename = args.multidomain
        print(f'Running in multiple domain mode with {filename}') if VERBOSE else None
        filepath = os.path.join(SCRIPT_PATH, filename)
        if os.path.isfile(filepath):
            Add_MultiDomain(filepath)
        else:
            raise FileNotFoundError(f"Cannot find the file {filepath}")

    domains = Domain.select().where( (Domain.status == "REFRESH") | (Domain.status == "NEW"))
    for d in domains:
        print(f'Running lookups for {d.name}') if VERBOSE else None
        is_found_mx = Get_MxRecord(d)
        # dont keep processing if it is NXDomain or another DNS Error
        if is_found_mx == False:
            continue
        Get_DmarcRecord(d)
        Get_SpfRecord(d)
        d.status = "DONE"
        d.save()
    Get_Report()

    finish = time.perf_counter()
    print (f"It took {round(finish-start,1)} seconds")

if __name__ == "__main__":
    main()
