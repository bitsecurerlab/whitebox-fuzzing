#!/bin/bash

CB_NAME=$1
DEBUG=$2
LOG_PATH=$3
INPUT_FILE_PATH=$4
TRACE_PATH=$5
BACKUP=$6
#EXECUTION_DIR=$PWD
INPUT_FILE=$(basename $INPUT_FILE_PATH)
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

#cp testlog.log $EXECUTION_DIR/bak/testlog.log.`date +"%s"`
#cp tags.xml $EXECUTION_DIR/bak/tags.xml.`date +"%s"`
if [ $BACKUP = "True" ]; then
    cp testlog.log $TRACE_PATH/${CB_NAME}_${INPUT_FILE}.DECAF_trace
    cp tags.xml $TRACE_PATH/${CB_NAME}_${INPUT_FILE}.tags.xml
fi
./trace_reader_cpp -i testlog.log -t $traceFile -c 1500 > trace_reader_cpp.log
file_size=`ls -l $traceFile | awk '{ print $5 }'`
#echo "Generate trace file size: $file_size" >> $LOG_PATH
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
if [ $BACKUP = "True" ]; then
    cp $INPUT_FILE_PATH $TRACE_PATH/${CB_NAME}_$INPUT_FILE
    cp $traceFile $TRACE_PATH/${CB_NAME}_${INPUT_FILE}.bpt
    cp ${traceFile}.bap $TRACE_PATH/${CB_NAME}_${INPUT_FILE}.bap
fi

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
#    $CVC4SOLVER -im $cvcfile > $CVC_DIR/solvedLog${COUNTER}
    if [ $(basename $cvcfile) = "no_flip.cvc" ] ; then
        stp $cvcfile > $CVC_DIR/no_flip_solvedLog
        #extract new inputs from solvedLog${COUNTER}
        cd $CVC_PARSER_BIN_DIR
        java SolverResultExtractor.SolverResultExtractor $EXECUTION_DIR/${traceFile}.bap $CVC_DIR/no_flip_solvedLog $EXECUTION_DIR/no_flip_result $INPUT_FILE_PATH
    else
        COUNTER=$((COUNTER+1))
        stp $cvcfile > $CVC_DIR/solvedLog${COUNTER}
        #extract new inputs from solvedLog${COUNTER}
        cd $CVC_PARSER_BIN_DIR
        java SolverResultExtractor.SolverResultExtractor $EXECUTION_DIR/${traceFile}.bap $CVC_DIR/solvedLog${COUNTER} newInput${COUNTER} $INPUT_FILE_PATH
    fi
done #end of for cvcfile in $CVC_DIR/*cvc

mv $EXECUTION_DIR/${traceFile}.bap $EXECUTION_DIR/bak/
mv $EXECUTION_DIR/*.bpt $EXECUTION_DIR/bak/
#rm $CVC_DIR/solvedLog*
timestamp=`date +%Y%m%d_%H%M%S`
mkdir $EXECUTION_DIR/bak/cvc_$timestamp
mv $CVC_DIR/* $EXECUTION_DIR/bak/cvc_$timestamp
if [ $BACKUP = "True" ]; then
    cp -pr $EXECUTION_DIR/bak/cvc_$timestamp $TRACE_PATH/${CB_NAME}_$INPUT_FILE.cvcfiles
fi
mv cjmps new_cjmps $EXECUTION_DIR/bak/
