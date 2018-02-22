#!/bin/bash

DEBUG=$1
INITIAL_INPUT_FILE=$2
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
./trace_reader_cpp -i testlog.log -t $traceFile > trace_reader_cpp.log
#rm testlog.log testlog.log.netlog tags.xml
mv $traceFile $EXECUTION_DIR/
cd $EXECUTION_DIR

if [ "$DEBUG" = true ] ; then
    echo "start analyzing trace file $traceFile"
fi

#$ILTRANS -trace $traceFile -trace-formula ${traceFile}.bap 1> $LOG_DIR/${traceFile}log
#generate CFG and extract new cjmp labels from it. 
#new cjmp labels will be stored in new_cjmps file and be read in path constraint generation phase
rm cjmps new_cjmps
$ILTRANS -trace $traceFile -to-cfg
#execute the trace file to generate path constraints
$ILTRANS -trace $traceFile -trace-formula ${traceFile}.bap 1> /dev/null 

if [ "$DEBUG" = true ] ; then    
    echo "start to analyze bap output file $(basename $traceFile).bap to generate new path constraints"
fi

#parse the path constraints file to generate multiple CVC files
cd $CVC_PARSER_BIN_DIR
java CVCParse.CVCParser $EXECUTION_DIR/${traceFile}.bap $(basename $traceFile).bap $CVC_DIR

if [ "$DEBUG" = true ] ; then
    echo "delete $EXECUTION_DIR/${traceFile}bap"
fi

#leverage STP solver to generate new inputs
COUNTER=0

for cvcfile in $CVC_DIR/*cvc
do
    COUNTER=$((COUNTER+1))
#    echo $cvcfile
#    echo $COUNTER
    if [ "$DEBUG" = true ] ; then
        echo "cvc4 solver to solve $cvcfile"
    fi
#    $CVC4SOLVER -im $cvcfile > $CVC_DIR/solvedLog${COUNTER}
    stp $cvcfile > $CVC_DIR/solvedLog${COUNTER}
    #extract new inputs from solvedLog${COUNTER}
    cd $CVC_PARSER_BIN_DIR
    if [ "$DEBUG" = true ] ; then
        echo "parse solver result file $CVC_DIR/solvedLog${COUNTER}"
    fi
    java SolverResultExtractor.SolverResultExtractor $EXECUTION_DIR/${traceFile}.bap $CVC_DIR/solvedLog${COUNTER} newInput${COUNTER} $INITIAL_INPUT_FILE
done #end of for cvcfile in $CVC_DIR/*cvc

mv $EXECUTION_DIR/${traceFile}.bap $EXECUTION_DIR/bak/
mv $EXECUTION_DIR/*.bpt $EXECUTION_DIR/bak/
#rm $CVC_DIR/solvedLog*
timestamp=`date +%Y%m%d_%H%M%S`
mkdir $EXECUTION_DIR/bak/cvc_$timestamp
mv $CVC_DIR/* $EXECUTION_DIR/bak/cvc_$timestamp
mv cjmps new_cjmps $EXECUTION_DIR/bak/
