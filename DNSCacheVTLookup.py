import ctypes
import json
from virus_total_apis import PublicApi as VirusTotalPublicApi
from ctypes.wintypes import DWORD, HANDLE, LPWSTR


API_KEY = ''

k_handle = ctypes.WinDLL("Kernel32.dll")
d_handle = ctypes.WinDLL("DNSAPI.dll")

def integer(obj):
    rv = {}
    for k, v in obj.items():
        if isinstance(v, basestring):
            try:
                rv[k] = int(v)
            except ValueError:
                rv[k] = v
        else:
            rv[k] = v
    return rv

class DNS_CACHE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("pNext", HANDLE),
        ("recName", LPWSTR),
        ("wType", DWORD),
        ("wDataLength", DWORD),
        ("dwFlags", DWORD),
    ]

print("INFO: Pulling DNS Cache Data from System")
DNS_Entry = DNS_CACHE_ENTRY()
DNS_Entry.wDataLength = 1024
response = d_handle.DnsGetCacheDataTable(ctypes.byref(DNS_Entry))

if response == 0:
    print("Error code: {0}".format(k_handle.GetLastError()))

DNS_Entry = ctypes.cast(DNS_Entry.pNext, ctypes.POINTER(DNS_CACHE_ENTRY))

while True:
    try:
        print("DNS Entry {0} - Type {1}".format(DNS_Entry.contents.recName, DNS_Entry.contents.wType))
        DNS_Entry = ctypes.cast(DNS_Entry.contents.pNext, ctypes.pointer(DNS_CACHE_ENTRY))
    except:
        break

if response > 0:
    vt = VirusTotalPublicApi(API_KEY)
    DNS_Entry_String = str(DNS_Entry.contents.recName)
    query = vt.get_url_report(DNS_Entry_String)
    pos_obj = json.dumps(query, sort_keys=False, indent=4)
    load = json.loads(pos_obj)
    print(load)
    for rating in load["results"]:
        if rating["positives"] == 0:
            print("false")
