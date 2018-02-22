#!/usr/bin/python2.7
import fcntl
import time
import datetime
import binascii
import struct
import json
import inspect
from multiprocessing import Process
import threading
import os
import sys
import zlib
import subprocess
import signal
import commands

###CONFIG BEGIN###
DECAF_ROOT = "/root/DECAF/decaf"
PLUGIN_PATH = "/root/DECAF/decaf/plugins/cgcfuzzer_tracecap/cgcfuzzer.so"
CONTROLLER_ADDR = "http://127.0.0.1:8000/main"
EXECUTION_PATH = "/root/whitebox_fuzzer/tests/C/executionDir"
INPUT_PATH = EXECUTION_PATH + "/inputs"
INPUT_TMP_PATH = EXECUTION_PATH + "/inputs_tmp/"
INPUT_BAK_PATH = EXECUTION_PATH + "/inputs_bak/"
CVC_PARSE_PATH = EXECUTION_PATH + "/CVCParse/bin/"
MAX_LEVEL = 3
AUTOMODE = True
DEBUG = False
LOG_PATH = sys.argv[5]

def main():
    if len(sys.argv) != 11:
        print "Usage: run.py cgc_image cgc_binary_path input_search_path output_path log_path trace_path mod_index mod_total internal_iteration_times backup"
        exit()
    cgc_image_path = sys.argv[1]
    cgc_binary_path = sys.argv[2]
    input_search_path = sys.argv[3]
    output_path = sys.argv[4]
    log_path = sys.argv[5]
    trace_path = sys.argv[6]
    MOD_INDEX = int(sys.argv[7])
    MOD_TOTAL = int(sys.argv[8])
    INTERNAL_ITERATION_TIMES = sys.argv[9]
    BACKUP = sys.argv[10]
    cgc_binary_name = os.path.basename(cgc_binary_path)
    os.system("touch " + log_path)
    print "touch " + log_path
    writeToLog(log_path, "===================================================================")
    writeToLog(log_path, "CGC_binary_path:    " + cgc_binary_path)
    writeToLog(log_path, "Input_search_path:  " + input_search_path)
    writeToLog(log_path, "Output_path:        " + output_path)
    writeToLog(log_path, "Log_path:           " + log_path)
    writeToLog(log_path, "Trace_path:         " + trace_path)
    if os.path.isfile(cgc_image_path) == False:
        print "CGC image does not exist"
        exit()
    if os.path.isfile(cgc_binary_path) == False:
        print "CGC binary does not exist"
        exit()
    if os.path.isdir(input_search_path) == False:
        print "Input directory does not exist"
        exit()
    if os.path.isdir(output_path) == False:
        print "Output directory does not exist"
        exit()
    os.system("service ssh start")
    os.system("rm -r " + EXECUTION_PATH + "/bak " + EXECUTION_PATH + "/cvc_files " + EXECUTION_PATH + "/inputs " + EXECUTION_PATH + "/inputs_bak " + EXECUTION_PATH + "/inputs_tmp")
    os.system("mkdir " + EXECUTION_PATH + "/bak " + EXECUTION_PATH + "/cvc_files " + EXECUTION_PATH + "/inputs " + EXECUTION_PATH + "/inputs_bak " + EXECUTION_PATH + "/inputs_tmp")
    os.system("cp " + cgc_binary_path + " /home/weisong/LUNGE_00001")
    output_arg = "-monitor stdio"
    if AUTOMODE:
        output_arg = "-serial pty -nographic"
    os.chdir(DECAF_ROOT)
    if DEBUG == False:
        print "exec i386-softmmu/qemu-system-i386 "+cgc_image_path+" -m 512 "+output_arg+" -snapshot"
        p = subprocess.Popen(args="exec i386-softmmu/qemu-system-i386 {cgc_image} -m 512 {output_arg} -snapshot".format(cgc_image=cgc_image_path, output_arg=output_arg), stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
        fl = fcntl.fcntl(p.stdout, fcntl.F_GETFL)
        fcntl.fcntl(p.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        input_cmd(p, "ps")
        input_cmd(p, "disable_tainting")
        wait_runner(p)
        input_cmd(p, "enable_tainting")
        input_cmd(p, "load_plugin {plugin}".format(plugin=PLUGIN_PATH))
    copyed_inputs = []
    processed_inputs = []
    duplicate_input_amount = 0
    start_index = 0
    total_input_amount = 0
    tmp_amount = 0
    processed_amount = 0
    while 1:
        writeToLog(log_path, "-------------------------------------------------------------------")
        if isAFLExited(cgc_binary_name):
            writeToLog(log_path, "AFL has already exited, exiting...")
            exit()
        file_path = ""
        files_tmp_list = os.listdir(INPUT_TMP_PATH)
#        (input_amount_lv1, input_amount_lv2, input_amount_lv3) = countEachLevelFilesAmount(input_search_path, cgc_binary_name)
#        total_input_amount = input_amount_lv1 + input_amount_lv2 + input_amount_lv3
#        total_input_amount = 99999
        if len(files_tmp_list) > 0:
            if tmp_amount >= int(INTERNAL_ITERATION_TIMES):
                os.system("rm " + INPUT_TMP_PATH + "/*")
                tmp_amount = 0
                continue
            file_path = getHighestScoreInput(INPUT_TMP_PATH);
        else:
            ret = copyNewFileToInputPath(input_search_path, INPUT_PATH, copyed_inputs, cgc_binary_name, MOD_INDEX, MOD_TOTAL)
            files_list = os.listdir(INPUT_PATH)
#            if total_input_amount <= 0 or ret == False or len(files_list) < 1:
            if ret == False or len(files_list) < 1:
#                writeToLog(log_path, "total_input_amount = " + str(total_input_amount) + ", len(files_list) = " + str(len(files_list)))
                writeToLog(log_path, "No new input, waiting...")
                time.sleep(60)
                continue
            processed_amount += 1
            file_path = os.path.join(INPUT_PATH, files_list[0])
        if len(file_path) > 0:
            file_name = os.path.basename(file_path)
            input_file = open(file_path, "r")
            new_input = input_file.read()
            input_file.close()
            if new_input not in processed_inputs:
                processed_inputs.append(new_input)
#                writeToLog(log_path, "New inputs total amount: " + str(total_input_amount) + " (" + str(input_amount_lv1) + "," + str(input_amount_lv2) + "," + str(input_amount_lv3) +"). Processed inputs amount: " + str(processed_amount) + "(" + str(int(processed_amount/float(total_input_amount) * 100)) + "%)")
                if len(files_tmp_list) > 0:
                    tmp_amount += 1
                    writeToLog(log_path, "Process inputs in tmp folder times: " + str(tmp_amount))
                writeToLog(log_path, "New input: " + file_name)
                status, output = commands.getstatusoutput("hd " + file_path)
                writeToLog(log_path, output, False)
                if DEBUG == False:
                    get_trace(p, new_input)
                else:
                    os.system("rm " + file_path)
                    continue 
                os.system(EXECUTION_PATH + "/handle_trace.sh " + cgc_binary_name + " false " + log_path + " " + file_path + " " + trace_path + " " + BACKUP)
                new_files_list = os.listdir(CVC_PARSE_PATH)
                for name in new_files_list:
                    if "newInput" in name:
                        new_name = "id:" + str(start_index).zfill(6) + "," + cgc_binary_name + ",index:" + str(MOD_INDEX)
                        start_index += 1
#                        none_zero_amount = countNoneZeroChar(CVC_PARSE_PATH + name)
                        none_zero_amount = getScore(CVC_PARSE_PATH + name)
                        if none_zero_amount >= 1:
                            os.system("cp " + CVC_PARSE_PATH + name + " " + output_path + new_name)
                            writeToLog(log_path, "none_zero_score: " + str(none_zero_amount))
                            writeToLog(log_path, "Generated new input: " + new_name)
                            writeToLog(log_path, getHDContent(output_path + new_name), False)
                            os.system("mv " + CVC_PARSE_PATH + name + " " + INPUT_TMP_PATH + new_name)
                os.system("rm " + CVC_PARSE_PATH + "/newInput*")
            else:
                writeToLog(log_path, "New input(already processed): " + file_name)
                duplicate_input_amount += 1
            os.system("rm " + file_path)

def getHDContent(path):
    status, output = commands.getstatusoutput("hd " + path)
    return output

def isAFLExited(cb_name):
#    writeToLog(LOG_PATH, "check /share/fuzz/outputs/" + cb_name + "/AFL_exit.sign")
    f = cb_name.split("_")
    if os.path.exists("/share/fuzz/outputs/" + f[0] + "/AFL_exit.sign"):
        return True
#    writeToLog(LOG_PATH, "not found AFL_exit.sign")
    return False

def countEachLevelFilesAmount(input_search_path, binary_name):
    input_amount_lv1 = 0
    input_amount_lv2 = 0
    input_amount_lv3 = 0
    for parent,dirnames,filenames in os.walk(input_search_path, topdown=True):
        for dirname in dirnames:
            if "filter1" in dirname:
                sub_path = input_search_path + dirname + "/queue"
                input_amount_lv1 = countFilesAmount(sub_path)
    for parent,dirnames,filenames in os.walk(input_search_path, topdown=True):
        for dirname in dirnames:
            if "filter2" in dirname:
                sub_path = input_search_path + dirname + "/queue"
                input_amount_lv2 = countFilesAmount(sub_path)
    for parent,dirnames,filenames in os.walk(input_search_path, topdown=True):
        for dirname in dirnames:
            if "filter3" in dirname:
                sub_path = input_search_path + dirname + "/queue"
                input_amount_lv3 = countFilesAmount(sub_path)
    return (input_amount_lv1, input_amount_lv2, input_amount_lv3)

def countFilesAmount(path):
    files_amount = 0
    for parent,dirnames,filenames in os.walk(path):
        for filename in filenames:
            if "id:" in filename:
                files_amount += 1
    return files_amount

def copyNewFileToInputPath(input_search_path, input_path, copyed_inputs, binary_name, mod_index, mod_total):
#    if mod_index == 0:
#        first_input_path = "/share/whitebox_fuzzer/first_input.txt"
#        if first_input_path not in copyed_inputs:
#            os.system("cp -p " + first_input_path + " " + input_path)
#            copyed_inputs.append(first_input_path)
#            return True
    for parent,dirnames,filenames in os.walk(input_search_path, topdown=True):
        for dirname in dirnames:
            if "afl" in dirname:
                ret = copyFile(input_search_path, dirname, input_path, copyed_inputs, mod_index, mod_total)
                if ret == True:
                    return True
    return False

def copyFile(input_search_path, dirname, input_path, copyed_inputs, mod_index, mod_total):
    for parent,dirnames,filenames in os.walk(input_search_path + dirname + "/queue", topdown=True):
        filenames.sort(reverse = True)
        for filename in filenames:
#            file_index = getIndexOfFilename(filename)
#            if file_index % mod_total == mod_index:
            file_path = input_search_path + dirname + "/queue/" + filename
            if file_path not in copyed_inputs:
                copyed_inputs.append(file_path);
                cmd = "cp -p " + file_path + " " + input_path
                os.system(cmd)
                writeToLog(LOG_PATH, "Copy " + file_path)
                return True
    return False

def getIndexOfFilename(name):
    return int(name[3:11])

def get_trace(p, new_input):
    input_cmd(p, "enable_tainting")
    gen_hmessage(new_input)
    input_cmd(p, "ba", "Branch Analysis End")
    input_cmd(p, "disable_tainting")

def writeToLog(log_file, str, need_time=True):
    log = open(log_file, 'a')
    if need_time == True:
        log.write("[" + getDateTime() + "] " + str + "\n")
        print "[" + getDateTime() + "] " + str
    else:
        log.write(str + "\n")
        print str
    log.close()

def getDateTime():
    #tmp fix to docker time on this machine is not synchronize
    ts = time.time() - 5*60*60 + 3*60
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    return st

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
        time.sleep(1)
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

def getHighestScoreInput(PATH):
    files_list = os.listdir(PATH)
    map_file_score = {}
    for input_file in files_list:
        input_file_path = os.path.join(PATH, input_file)
#        score = countNoneZeroChar(input_file_path)
        score = getScore(input_file_path)
        map_file_score[input_file] = score
    sorted_map = sorted(map_file_score.iteritems(), key=lambda d:d[1], reverse = True)
    return os.path.join(PATH, sorted_map[0][0])

def countNoneZeroChar(file_path):
    f = open(file_path, "r")
    content = f.read()
    f.close()
    count = 0
    for c in content:
        if ord(c) != 0 and ord(c) != 10:
            count += 1
    return count

def getScore(file_path):
    startFromBegin = True
    f = open(file_path, "r")
    content = f.read()
    f.close()
    count = 0
    for c in content:
        if ord(c) >= 32 and ord(c) <= 126:
            count += 1
            if startFromBegin == True:
                count += 2
        else:
            startFromBegin = False
            if ord(c) != 0 and ord(c) != 10:
                count += 0.1
    return count

def isPrintable(c):
    if ord(c) >= 32 and ord(c) <= 126:
        return True
    else:
        return False

if __name__ == '__main__':
    main()
