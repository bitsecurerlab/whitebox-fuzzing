#!/bin/bash

DEBUG=$1
OUTPUT_PATH=$2
INPUT_FILE=$3
CB_NAME=$4
#EXECUTION_DIR=$PWD
EXECUTION_DIR=/root/whitebox_fuzzer/tests/C/executionDir
BAP_DIR=$EXECUTION_DIR/../../..
ILTRANS=$BAP_DIR/utils/iltrans
CVC_PARSER_BIN_DIR=$EXECUTION_DIR/CVCParse/bin
CVC_DIR=$EXECUTION_DIR/cvc_files 
LOG_DIR=$EXECUTION_DIR/log_files
#CVC4SOLVER=$EXECUTION_DIR/cvc4-1.4-x86_64-linux-opt

if [ -d "$LOG_DIR" ]; then
    rm -r $LOG_DIR
fi

mkdir $LOG_DIR

rm -rf $EXECUTION_DIR/*.bpt
rm -rf $EXECUTION_DIR/*.bap

cd /root/DECAF/decaf/
traceFile=`date +"%s"`.bpt

cp testlog.log $EXECUTION_DIR/bak/testlog.log.`date +"%s"`
cp tags.xml $EXECUTION_DIR/bak/tags.xml.`date +"%s"`
./trace_reader_cpp -i testlog.log -t $traceFile -a > trace_reader_cpp.log
cp $traceFile $OUTPUT_PATH/${CB_NAME}_${INPUT_FILE}.bpt
cp testlog.log $OUTPUT_PATH/${CB_NAME}_${INPUT_FILE}.DECAF_trace
cp tags.xml $OUTPUT_PATH/${CB_NAME}_${INPUT_FILE}.tags.xml
echo "Generated trace file $traceFile"
