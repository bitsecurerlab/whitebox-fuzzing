#!/usr/bin/python2.7
import subprocess, os
import fcntl
import time
import datetime
import binascii
import struct
#import requests
import json
import inspect
from multiprocessing import Process
import threading
import os
import sys
import zlib
import subprocess
import signal

###CONFIG BEGIN###
DECAF_ROOT = "/root/DECAF/decaf"
PLUGIN_PATH = "/root/DECAF/decaf/plugins/cgcfuzzer_tracecap/cgcfuzzer.so"
CONTROLLER_ADDR = "http://127.0.0.1:8000/main"
EXECUTION_PATH = "/root/whitebox_fuzzer/tests/C/executionDir"
INPUT_PATH = EXECUTION_PATH + "/inputs"
INPUT_BAK_PATH = EXECUTION_PATH + "/inputs_bak"
CVC_PARSE_PATH = EXECUTION_PATH + "/CVCParse/bin"
AUTOMODE = True

def main():
    if len(sys.argv) != 5:
        print "Usage: run.py cgc_image cgc_binary_path initial_input_filename output_path"
        exit()
    cgc_image_path = sys.argv[1]
    cgc_binary_path = sys.argv[2]
    initial_input_filename = sys.argv[3]
    output_path = sys.argv[4]
    if os.path.isfile(cgc_image_path) == False:
        print "CGC image does not exist"
        exit()
    if os.path.isfile(cgc_binary_path) == False:
        print "CGC binary does not exist"
        exit()
    if os.path.isfile(initial_input_filename) == False:
        print "Initial input file does not exist"
        exit()
    if os.path.isdir(output_path) == False:
        print "Output directory does not exist"
        exit()
    os.system("service ssh start")
    os.system("rm -r " + EXECUTION_PATH + "/bak " + EXECUTION_PATH + "/cvc_files " + EXECUTION_PATH + "/inputs " +     EXECUTION_PATH + "/inputs_bak " + EXECUTION_PATH + "/inputs_tmp")
    os.system("mkdir " + EXECUTION_PATH + "/bak " + EXECUTION_PATH + "/cvc_files " + EXECUTION_PATH + "/inputs " +     EXECUTION_PATH + "/inputs_bak " + EXECUTION_PATH + "/inputs_tmp")
    os.system("cp " + cgc_binary_path + " /home/weisong/LUNGE_00001")
    output_arg = "-monitor stdio"
    if AUTOMODE:
        output_arg = "-serial pty -nographic"
    os.chdir(DECAF_ROOT)
    p = subprocess.Popen(args="exec i386-softmmu/qemu-system-i386 {cgc_image} -m 512 {output_arg} -snapshot".format(cgc_image=cgc_image_path, output_arg=output_arg), stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    fl = fcntl.fcntl(p.stdout, fcntl.F_GETFL)
    fcntl.fcntl(p.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    time.sleep(3)
    input_cmd(p, "sendkey ret")
    input_cmd(p, "ps")
    input_cmd(p, "disable_tainting")
    wait_runner(p)
    input_cmd(p, "enable_tainting")
    input_cmd(p, "load_plugin {plugin}".format(plugin=PLUGIN_PATH))
    os.system("cp " + initial_input_filename + " " + INPUT_PATH)
    processed_input = []
    files_list = os.listdir(INPUT_PATH)
    while len(files_list) > 0:
        print "----------------------------------"
        file = os.path.join(INPUT_PATH, files_list[0])
        input_file =  open(file, "r")
        new_input = input_file.read()
        strlist = new_input.split('\n')
        new_input_first_line = strlist[0]
        if new_input not in processed_input and new_input_first_line not in processed_input:
            print "new input: " + new_input
            processed_input.append(new_input)
            processed_input.append(new_input_first_line)
            get_trace(p, new_input)
            os.system(EXECUTION_PATH+"/trace_fuzzing.sh false " + output_path + " " + os.path.basename(file) + " " + os.path.basename(cgc_binary_path))
#            #os.system("cp " + file + " " + output_path)
#            os.system("mv " + file + " " + INPUT_BAK_PATH)
#            #print "generate new input:"
#            #os.system("cat " + CVC_PARSE_PATH + "/newInput*")
#            new_files_list = os.listdir(CVC_PARSE_PATH)
#            file_index = 0
#            for name in new_files_list:
#                if "newInput" in name:
#                    os.rename(CVC_PARSE_PATH + "/" + name, CVC_PARSE_PATH + "/input_" + datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d_%H%M%S') + "_" + str(file_index))
#                    file_index += 1
#            os.system("mv " + CVC_PARSE_PATH + "/input* " + INPUT_PATH)
#        else:
#            print "processed input: " + new_input
#            os.system("rm " + file)
#        files_list = os.listdir(INPUT_PATH)
        print ""
        print ""
        print ""
        print ""
        print "Finished."
        exit()
    p.kill()

def get_trace(p, new_input):
    input_cmd(p, "enable_tainting")
    gen_hmessage(new_input)
    input_cmd(p, "ba", "Branch Analysis End")
    input_cmd(p, "disable_tainting")

def gen_hmessage(new_input):
    msgs = [new_input]
    hmessage = ""
    bin_path = ["/usr/share/cgc-sample-challenges/templates/service-template/bin/LUNGE_00001"]
    hmessage += struct.pack("<i", len(bin_path))
    for path in bin_path:
        hmessage += struct.pack("<i", len(path))
        hmessage += path
    hmessage += struct.pack("<i", len(msgs))
    for msg in msgs:
        hmessage += struct.pack("<i", len(msg))
        hmessage += msg
    with open("/home/weisong/hmessage", "wb") as f:
        f.write(hmessage)
    os.system("cp /home/weisong/hmessage " + EXECUTION_PATH + "/bak/hmessage." + time.strftime("%s"))

def input_cmd(proc, cmd, end=None):
    if not cmd.endswith("\n"):
        cmd += "\n"
    proc.stdin.write(cmd)
    if end == None:
        proc.stdin.write("MARK\n")
        end = "\nunknown command: 'MARK'"
    while True:
        time.sleep(0.1)
        try:    
            s = proc.stdout.read()
        except Exception, e:
            continue
        s_clean = s.replace("\nunknown command: 'MARK'", "")
        print s_clean,
        if end in s:
            break

def wait_runner(proc):
    proc.stdin.write("ps\n")
    proc.stdin.write("MARK\n")
    while True:
        time.sleep(0.1)
        try:    
            s = proc.stdout.read()
        except Exception, e:
            continue
        if "unknown command: 'MARK'" in s:
            if "runner.o" in s:
                break
            else:
                proc.stdin.write("ps\n")
                proc.stdin.write("MARK\n")
    print "runner started"
    time.sleep(1)

if __name__ == '__main__':
    main()
