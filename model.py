from peewee import *
import re
from playhouse.hybrid import hybrid_property
from playhouse.hybrid import hybrid_method


database = SqliteDatabase(None)

class BaseModel(Model):
    class Meta:
        database = database

class Domain(BaseModel):
    hash_id         = TextField(primary_key=True)
    date_added      = DateTimeField(null=True)
    date_updated    = DateTimeField(null=True)
    name            = TextField(null=True)
    status          = TextField(null=True)
    has_mx          = IntegerField(constraints=[SQL("DEFAULT -1")]) # -1 not init, 1= all valid , 2= has mx nslookup error
    has_dmarc       = IntegerField(constraints=[SQL("DEFAULT 0")])
    has_spf         = IntegerField(constraints=[SQL("DEFAULT 0")])

    class Meta:
        table_name = 'Domain'

class MxRecord(BaseModel):
    date_added     = DateTimeField(null=True)
    hash_id        = ForeignKeyField(Domain)
    exchanger      = TextField(null=True)
    preference     = TextField(null=True)
    is_valid       = IntegerField(null=True)
    class Meta:
        table_name = 'MxRecord'

class SpfRecord(BaseModel):
    date_added     = DateTimeField(null=True)
    hash_id        = ForeignKeyField(Domain)
    policy         = TextField(null=True) # accept, reject, neutral, hard fail , soft fail
    is_valid       = IntegerField(null=True) #record can be invalid
    value          = TextField(null=True) # raw record

    def __len__(self):
        return len(self.value)

    @hybrid_method
    def check_policy(self):
        regex = r"\s+[?~+-]*all"
        r = re.search(regex, self.value, re.MULTILINE|re.IGNORECASE)
        if r != None:
            policy_str = str(r.group(0)).strip().replace("all","")
            match policy_str:
                case "?":
                    self.policy = "NEUTRAL" #BAD
                case "~":
                    self.policy = "SOFT_FAIL"
                case "+":
                    self.policy = "PASS" #BAD
                case "-":
                    self.policy = "HARD_FAIL" #GOOD
                case _:
                    self.policy = "NEUTRAL" # BAD
        else:
            self.policy ="NEUTRAL"
        self.save()

    @hybrid_property
    def valid(self):
        #validate if the SPF record is OK
        # return None is not SPF
        if len(self.value) >258:
            values =self.value.split('" "')
            for v in values:
                if len(v) >258:
                    self.is_valid = 0
                    self.save()
                    return False
        self.is_valid = 1
        self.save()
        return True

    class Meta:
        table_name = 'SpfRecord'


class DmarcRecord(BaseModel):
    date_added     = DateTimeField(null=True)
    hash_id        = ForeignKeyField(Domain)
    policy         = TextField(null=True)
    is_valid       = IntegerField(null=True)
    value          = TextField(null=True)

    def __len__(self):
        return len(self.value)

    @hybrid_property
    def valid(self):
        # return None is not SPF
        if len(self.value) >258:
            values =self.value.split('" "')
            for v in values:
                if len(v) >258:
                    self.is_valid = 0
                    self.save()
                    return False
        self.is_valid = 1
        self.save()
        return True

    @hybrid_method
    def check_policy(self):
        regex = r"p=\w*;"
        r = re.search(regex, self.value, re.MULTILINE|re.IGNORECASE)
        if r != None:
            self.policy = str(r.group(0)).replace("p=","").replace(";","").upper()
        else:
            self.policy ="NONE" # policy set to none if not found in string
        self.save()


    class Meta:
        table_name = 'DmarcRecord'

class DomainReport(Model):
    domain_name = CharField()
    SPF_policy = CharField()
    SPF_length_OK = CharField()
    DMARC_policy = CharField()
    DMARC_length_OK = CharField()
    last_updated = DateTimeField()

    class Meta:
        table_name = 'DomainReport'
