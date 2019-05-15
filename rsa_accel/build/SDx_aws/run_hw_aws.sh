# Running FPGA-accelerated application with warning, it should be run with root rights

if [ $USER != "root" ]; then
    echo "ERROR: FPGA-accelerated application should be run with root rights: sudo sh"
else
    source ../xilinx_aws_run_setup.sh	
    ./test_rsa_hls -bench-count 1000 -bench-private -bench-parallel -low-level
fi
