# Setup actions for Xilinx/AWS runtime stage, should be run for any new shell.

# Script must be sourced from a bash shell or it will not work
# When being sourced $0 will be the interactive shell and $BASH_SOURCE_ will contain the script being sourced
# When being run $0 and $_ will be the same.
script=${BASH_SOURCE[0]}
if [ $script == $0 ]; then
    echo "ERROR: You must source this script"
    exit 2
fi

source /opt/Xilinx/SDx/2018.2.op2258646/settings64.sh

if [[ -z "$AWS_FPGA_REPO_DIR" ]]; then
	export AWS_FPGA_REPO_DIR=/home/centos/src/project_data/aws-fpga
	echo "AWS_FPGA_REPO_DIR is not set, setting it to $AWS_FPGA_REPO_DIR location by default (meaning runtime on AWS F1 instance)."
	echo "In case AWS FPGA tools location is different, please set it accordingly:"
	echo "export AWS_FPGA_REPO_DIR=$AWS_FPGA_REPO_DIR"
	echo "And clone AWS FPGA tools there as follows:"
	echo "git clone --recurse-submodules https://github.com/aws/aws-fpga.git \$AWS_FPGA_REPO_DIR"
fi
echo "AWS_FPGA_REPO_DIR is set to $AWS_FPGA_REPO_DIR"

# Activation of XRT (Xilinx/AWS runtime)
source $AWS_FPGA_REPO_DIR/sdaccel_runtime_setup.sh
# The above script may require update/install of Xilinx/AWS XRT (runtime environment), something like following. Please do it if needed.
# curl -s https://s3.amazonaws.com/aws-fpga-developer-ami/1.5.0/Patches/XRT_2018_2_XDF_RC5/xrt_201802.2.1.0_7.5.1804-xrt.rpm -o xrt_201802.2.1.0_7.5.1804-xrt.rpm
# curl -s https://s3.amazonaws.com/aws-fpga-developer-ami/1.5.0/Patches/XRT_2018_2_XDF_RC5/xrt_201802.2.1.0_7.5.1804-aws.rpm -o xrt_201802.2.1.0_7.5.1804-aws.rpm
# sudo yum remove -y xrt-aws
# sudo yum remove -y xrt
# sudo yum install -y xrt_201802.2.1.0_7.5.1804-xrt.rpm
# sudo yum install -y xrt_201802.2.1.0_7.5.1804-aws.rpm

# Alternative way to activate Xilinx/AWS runtime: using XRT, pre-installed separtely on AWS F1 development AMI.
# It could be outdated comparing with AWS github repo, but doesn't require additional system installations.
# source /opt/xilinx/xrt/setup.sh

export AWS_PLATFORM=/home/centos/src/project_data/aws-fpga/SDAccel/aws_platform/xilinx_aws-vu9p-f1-04261818_dynamic_5_0/xilinx_aws-vu9p-f1-04261818_dynamic_5_0.xpfm

# defining XCL_EMULATION_MODE as execution on AWS to differ it from other clouds (Nimbix or what ever).
export XCL_EMULATION_MODE=hw_aws

if [[ -z "$OPENSSL_DIR" ]]; then
	export OPENSSL_DIR=/home/centos/src/project_data/openssl
	echo "OPENSSL_DIR is not set, setting it to $OPENSSL_DIR location by default (meaning runtime on AWS F1 instance)."
	echo "In case OpenSSL location is different, please set it accordingly:"
	echo "export OPENSSL_DIR=$OPENSSL_DIR"
fi
echo "OPENSSL_DIR, needed for OpenSSL use cases of RSA accelerator, is set to $OPENSSL_DIR."
