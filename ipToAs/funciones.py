#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import MySQLdb as mdb

################################
# funciones para base de datos #
################################
def conectardb():
    db_host = 'localhost'
    usuario = 'tix'
    clave = 'tix'
    base_de_datos = 'iptoas'
    conndb = mdb.connect(host=db_host, user=usuario, passwd=clave, db=base_de_datos)
    cursor = conndb.cursor()
    return cursor, conndb

def findasxip(octeto):
    '''
    Busca numero de AS que coincida con la ip que comience con el primer octeto indicado
    '''
    cursor, conndb = conectardb()
    sql = 'SELECT noderouter AS numas, ip_router AS ip, mask FROM routerviews WHERE ip_router regexp "^' + octeto + '\\.";'

    cursor.execute(sql)
    resultado = cursor.fetchall()
    cursor.close()
    conndb.close()
    
    if len(resultado) == 0:
        return None

    lstasxip=[]
    for valor in resultado:
        numas = str(valor[0])
        ip = valor[1]
        mask = valor[2]
        lstasxip.append((numas, ip, mask))
    return lstasxip

def findnombrexas(num_as):
    '''
    Busca nombre de AS que coincidan con el numero de AS indicado
    '''
    cursor, conndb = conectardb()
    sql = 'SELECT name FROM namenodes WHERE noden = ' + num_as+ ';'

    cursor.execute(sql)
    resultado = cursor.fetchall()
    cursor.close()
    conndb.close()
    
    if len(resultado) == 0:
        return None
    
    return resultado[0][0]
