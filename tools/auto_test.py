from multiprocessing.connection import wait
import os
import pwd
import re
import threading
import _thread
import subprocess
import random
import string
import json
import time
import signal
json_name_list = []
data_set_list=[]
query_set_list=[]
def check_ans(db_name,query_name,union_name):
    db = []
    query = []
    union = []
    with open(db_name,"r") as db_read:
        db = db_read.readlines()
    with open(query_name,"r") as query_read:
        query = query_read.readlines()
    with open(union_name,"r") as union_read:
        union = union_read.readlines()
    db_set = set(db)
    query_set =set(query)
    union_set = set(union)

    ins = db_set.intersection(query_set)
    un = db_set.union(query_set)
    err_set = union_set.intersection(db_set)
    que_set = union_set.intersection(query_set)
    err_ins = union_set.intersection(ins)
    assert len(err_set)==0,"ot get item in dbset"
    assert len(err_ins)==0,"ot get item in intersection"
    assert len(ins) + len(union_set) == len(query_set ), "ot forget item in query"
    assert len(que_set) == len(union_set),"ot get item not in query"
    print("success")

 


def prepare_data(sender_sz,recv_sz,int_sz,item_bc):
    data_set_name='db.csv'
    query_set_name='query.csv'

    label_bc = 0
    
    sender_list = []

    letters = string.ascii_lowercase + string.ascii_uppercase
    while len(sender_list) < sender_sz:
        item = ''.join(random.choice(letters) for i in range(item_bc))
        label = ''.join(random.choice(letters) for i in range(label_bc))
        sender_list.append((item, label))
    print('Done creating sender\'s set')

    recv_set = set()
    while len(recv_set) < min(int_sz, recv_sz):
        item = random.choice(sender_list)[0]
        recv_set.add(item)

    while len(recv_set) < recv_sz:
        item = ''.join(random.choice(letters) for i in range(item_bc))
        recv_set.add(item)
    print('Done creating receiver\'s set')

    with open(data_set_name, "w") as sender_file:
        for (item, label) in sender_list:
            sender_file.write(item + (("," + label) if label_bc != 0 else '') + '\n')
    print('Wrote sender\'s set   '+data_set_name)

    with open(query_set_name, "w") as recv_file:
        for item in recv_set:
            recv_file.write(item + '\n')
    print('Wrote receiver\'s set    '+query_set_name)
def prepare_json():
    PSU_pram = {
              "table_params": {
                "hash_func_count": 3,
                "table_size": 1638,
                "max_items_per_bin": 128
                 },
                "item_params": {
                    "felts_per_item": 5
                },
                "query_params": {
                    "ps_low_degree": 44,
                    "query_powers": [ 1, 3, 11, 18, 45, 225 ]
                },
                "seal_params": {
                    "plain_modulus_bits": 22,
                    "poly_modulus_degree": 8192,
                    "coeff_modulus_bits": [ 56, 56, 56, 50 ]
                }
                }
    
    json_name = "out.json"
    with open(json_name,"w") as f:
         json.dump(PSU_pram,f)
    json_name_list.append(json_name)
def createnetwork10G():
    cmd_t = ["tc","qdisc", "add", "dev","lo",  "root", "handle", "1:0" ,"tbf" ,"lat" ,"10ms" ,"rate" ,"10Gbit" ,"burst" ,"1G"]
    print(cmd_t)
    with open(ansout,"a+") as fp:
        fp.write(str(cmd_t)+'\n')
    subprocess.run(cmd_t)
    cmd_t1 = [ "tc", "qdisc", "add", "dev","lo", "parent", "1:1" ,"handle" ,"10:" ,"netem" ,"delay" ,"0.1msec"]
    print(cmd_t1)
    with open(ansout,"a+") as fp:
        fp.write(str(cmd_t1)+'\n')
    subprocess.run(cmd_t1)
def network10G():
    cmd_t = ["tc","qdisc", "change", "dev","lo",  "root", "handle", "1:0" ,"tbf" ,"lat" ,"10ms" ,"rate" ,"10Gbit" ,"burst" ,"1G"]
    print(cmd_t)
    with open(ansout,"a+") as fp:
        fp.write(str(cmd_t)+'\n')
    subprocess.run(cmd_t)
    cmd_t1 = [ "tc", "qdisc", "change", "dev","lo", "parent", "1:1" ,"handle" ,"10:" ,"netem" ,"delay" ,"0.1msec"]
    print(cmd_t1)
    with open(ansout,"a+") as fp:
        fp.write(str(cmd_t1)+'\n')
    subprocess.run(cmd_t1)
def network100M():
    cmd_t = ["tc","qdisc", "change", "dev","lo",  "root", "handle", "1:0" ,"tbf" ,"lat" ,"10ms" ,"rate" ,"100Mbit" ,"burst" ,"10M"]
    print(cmd_t)
    with open(ansout,"a+") as fp:
        fp.write(str(cmd_t)+'\n')
    subprocess.run(cmd_t)
    cmd_t1 = [ "tc", "qdisc", "change", "dev","lo", "parent", "1:1" ,"handle" ,"10:" ,"netem" ,"delay" ,"40msec"]
    print(cmd_t1)
    with open(ansout,"a+") as fp:
        fp.write(str(cmd_t1)+'\n')
    subprocess.run(cmd_t1)
def network10M():
    cmd_t = ["tc","qdisc", "change", "dev","lo",  "root", "handle", "1:0" ,"tbf" ,"lat" ,"10ms" ,"rate" ,"10Mbit" ,"burst" ,"1M"]
    print(cmd_t)
    with open(ansout,"a+") as fp:
        fp.write(str(cmd_t)+'\n')
    subprocess.run(cmd_t)
    cmd_t1 = [ "tc", "qdisc", "change", "dev","lo", "parent", "1:1" ,"handle" ,"10:" ,"netem" ,"delay" ,"40msec"]
    print(cmd_t1)
    with open(ansout,"a+") as fp:
        fp.write(str(cmd_t1)+'\n')
    subprocess.run(cmd_t1)
def network1M():
    cmd_t = ["tc","qdisc", "change", "dev","lo",  "root", "handle", "1:0" ,"tbf" ,"lat" ,"10ms" ,"rate" ,"1Mbit" ,"burst" ,"1M"]
    print(cmd_t)
    with open(ansout,"a+") as fp:
        fp.write(str(cmd_t)+'\n')
    subprocess.run(cmd_t)
    cmd_t1 = [ "tc", "qdisc", "change", "dev","lo", "parent", "1:1" ,"handle" ,"10:" ,"netem" ,"delay" ,"40msec"]
    print(cmd_t1)
    with open(ansout,"a+") as fp:
        fp.write(str(cmd_t1)+'\n')
    subprocess.run(cmd_t1)

def DDHwork(thread,param):
    receiver_cmd = ["./receiver_cli_ddh","-d db.csv",thread,"-p "+param]
    sender_cmd = ["./sender_cli_ddh","-q query.csv",thread,"-p "+param]
    print(receiver_cmd)
    print(sender_cmd)
    outfileS = subprocess.Popen(receiver_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    outfileR = subprocess.Popen(receiver_cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    outfileR.wait()

    outfileS.send_signal(signal.SIGINT)

    with open("recvfile"+testcast[0]+testcast[1],"a+") as fp:
            for i in outfileR.stdout.readlines():
                fp.write(i.decode())
    with open("sendfile"+testcast[0]+testcast[1],"a+") as fp:
            for i in outfileS.stdout.readlines():
                fp.write(i.decode())


def Test1():
    param = '16M-1024.json'
    receiver_size = pow(2,18)
    sender_size = pow(2,10)
    intersection_size = 256

    prepare_data(receiver_size,sender_size,intersection_size,item_bc)
    DDHwork(thread_c[0],param)

if __name__ =="__main__":
    
    db = "db.csv"
    query = "query.csv"
    param = '16M-1024.json'
    union = "union.csv"
    
    thread_c = ["-t 1","-t 2","-t 4","-t 1","-t 4","-t 8"]
    sender_c = ["./sender1","./sender4","./sender8"]
    recv_c = ["./receiver1","./receiver4","./receiver8"]
    sender_c = ["./sender_cli_osn","./sender_cli2","./sender_cli4","./sender_cli1_M","./sender_cli4","./sender_cli8"]
    recv_c = ["./receiver_cli_osn","./receiver_cli2","./receiver_cli4","./receiver_cli1_M","./receiver_cli4","./receiver_cli8"]
    item_bc = 16
    table = [0]
    item_len = "--len "+str(item_bc)
    receiver_file = "cmp"
    ansout = "cmp"
    # createnetwork10G()
    sender_file = receiver_file
    # network10G()
    #network1M()
    #network100M()
    # check_ans(db,query,union)
    prepare_data(pow(2,22),pow(2,10),256,16)
    
    # Test1()

    # network10G()
 
