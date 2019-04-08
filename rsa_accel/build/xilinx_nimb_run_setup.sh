# Setup actions for Xilinx/Nimbix runtime stage, should be run for any new shell.

# Script must be sourced from a bash shell or it will not work
# When being sourced $0 will be the interactive shell and $BASH_SOURCE_ will contain the script being sourced
# When being run $0 and $_ will be the same.
script=${BASH_SOURCE[0]}
if [ $script == $0 ]; then
    echo "ERROR: You must source this script"
    exit 2
fi

export AWS_PLATFORM=/opt/xilinx/platforms/xilinx_u250_xdma_201830_1/xilinx_u250_xdma_201830_1.xpfm
export OPENSSL_DIR=/home/nimbix/data/openssl
echo "OPENSSL_DIR, needed for OpenSSL use cases of RSA accelerator, is set to $OPENSSL_DIR."
