import ctypes
import json
from virus_total_apis import PublicApi as VirusTotalPublicApi
from ctypes.wintypes import DWORD, HANDLE, LPWSTR

k_handle = ctypes.WinDLL("Kernel32.dll")
d_handle = ctypes.WinDLL("DNSAPI.dll")


class DNS_CACHE_ENTRY(ctypes.Structure):
    _fields_ = [
        ("pNext", HANDLE),
        ("recName", LPWSTR),
        ("wType", DWORD),
        ("wDataLength", DWORD),
        ("dwFlags", DWORD),
    ]

def main():
    while True:
        dnscache()

def dnscache():
    print("INFO: Pulling DNS Cache Data from System")

    #Instantiate new object
    DNS_Entry = DNS_CACHE_ENTRY()

    #Set maximum data length
    DNS_Entry.wDataLength = 1024

    #Issue api call to grab the dns entry cache
    response = d_handle.DnsGetCacheDataTable(ctypes.byref(DNS_Entry))

    #Handle the error
    if response == 0:
        print("Error code: {0}".format(k_handle.GetLastError()))

    #Cast a ctypes instance to a pointer within the memory location and a pointer to the structure
    DNS_Entry = ctypes.cast(DNS_Entry.pNext, ctypes.POINTER(DNS_CACHE_ENTRY))

    while True:
        try:
            #Format DNS_entry contents recname + wtype
            print("DNS Entry: {0} - Type {1}".format(DNS_Entry.contents.recName, DNS_Entry.contents.wType))
            #Cast to next entry
            DNS_Entry = ctypes.cast(DNS_Entry.contents.pNext, ctypes.pointer(DNS_CACHE_ENTRY))
        except:
            break

if __name__ == '__main__':
    main()
