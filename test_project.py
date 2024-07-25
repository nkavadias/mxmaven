import pytest
from mxmaven import *

domain = Domain()
domain.name = "google.com"
domain.hash_id = get_hash(domain.name)
create_tables(".\test_mxmaven.db")

def test_hash():
    assert get_hash("google.com") == "1d5920f4b44b27a802bd77c4f0536f5a"
    assert get_hash("gmail.com") == "f74d39fa044aa309eaea14b9f57fe79c"

def test_is_domain():
    assert is_domain("google.com") == True
    assert is_domain("!gimmebeer.com") == False


def test_is_spf():
    assert is_spf("v=spf") == False
    assert is_spf('"v=spf1 aaa') == True

def test_Add_SingleDomain():

    domain = Add_SingleDomain("google.com")
    assert isinstance(domain, int)
    #assert isinstance(domain, Domain)

def test_Get_MxRecord():
    global domain
    mx = Get_MxRecord(domain)
    assert mx == True
