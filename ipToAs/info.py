#!/usr/bin/python

from funciones import findasxip, findnombrexas
from math import log

def ipdecbin(ip):
    HexBin ={"0":"0000", "1":"0001", "2":"0010", "3":"0011", "4":"0100", "5":"0101", "6":"0110", "7":"0111", "8":"1000", "9":"1001", "A":"1010", "B":"1011", "C":"1100", "D":"1101", "E":"1110", "F":"1111"};

    pri_oct, seg_oct, ter_oct, cua_oct = map(int,ip.split('.'))
    
    pri_oct_bin = "".join([HexBin[i] for i in '%X'%pri_oct]).lstrip('0')
    while len(pri_oct_bin) < 8: pri_oct_bin = "0" + pri_oct_bin
    
    seg_oct_bin = "".join([HexBin[i] for i in '%X'%seg_oct]).lstrip('0')
    while len(seg_oct_bin) < 8: seg_oct_bin = "0" + seg_oct_bin
    
    ter_oct_bin = "".join([HexBin[i] for i in '%X'%ter_oct]).lstrip('0')
    while len(ter_oct_bin) < 8: ter_oct_bin = "0" + ter_oct_bin
    
    cua_oct_bin = "".join([HexBin[i] for i in '%X'%cua_oct]).lstrip('0')
    while len(cua_oct_bin) < 8: cua_oct_bin = "0" + cua_oct_bin
    
    ip_bin = pri_oct_bin + seg_oct_bin + ter_oct_bin + cua_oct_bin
    return ip_bin

def as_num_cliente(ip_dire):
    octeto1 = ip_dire.split('.')[0]
    lstasxip = findasxip(octeto1)

    if lstasxip is None:
        return None
    
    ult_mask = 0
    numas = None
    for (numascomp, ipcomp, net_mask) in lstasxip:
        ipcomp_bin = ipdecbin(ipcomp)
        ip_dire_bin = ipdecbin(ip_dire)
        if ip_dire_bin[:net_mask] == ipcomp_bin[:net_mask]:
            if net_mask > ult_mask:
                numas = numascomp
                ult_mask = net_mask
    return numas

def as_name(ip_dire):
    '''
    ip_dire: direccion ipv4
    retorna el nombre del pais, numero de as y el nombre del as, al que pertenece la ip 
    '''
    if (ip_dire is None) or (ip_dire == 'UNKNOWN'):
        return None

    octetos = [ int(x) for x in ip_dire.split('.') ]
    if (octetos[0] == 10) or (octetos[0] == 192 and octetos[1] == 168) or (octetos[0] == 172 and 16 <= octetos[1] <= 31) or (octetos[0] == 127):
        return None

    num_as = as_num_cliente(ip_dire)
    if num_as is not None:
        return findnombrexas(num_as)
    else:
        return None
    

if __name__ == '__main__':
    import sys
    ip = sys.argv[1]
    name = as_name(ip)
    if name is not None:
        print name
    else:
        print 'UNKNOWN'
