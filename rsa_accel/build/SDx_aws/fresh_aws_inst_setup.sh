# Setup actions for newly created AWS F1 instance

# Update/install required/usefull packages (taken from https://github.com/aws/aws-fpga/blob/master/SDAccel/docs/Create_Runtime_AMI.md) 
sudo yum update
sudo yum install git
sudo yum install gcc
sudo yum install gcc-c++
sudo yum install make
sudo yum install kernel-headers
sudo yum install kernel-devel
sudo yum --enablerepo=epel install ocl-icd ocl-icd-devel opencl-headers
sudo mkdir -p /etc/OpenCL/vendors/

sudo yum install svn
sudo yum install mc
sudo yum install gmp-devel # required for modular exponentiation
sudo yum install glibc     # for pthread lib update

# Clonning of AWS tools (according to https://github.com/aws/aws-fpga/blob/master/SDAccel/README.md):
git clone --recurse-submodules https://github.com/aws/aws-fpga.git $AWS_FPGA_REPO_DIR
cd $AWS_FPGA_REPO_DIR                                         
source ./sdaccel_setup.sh

# Installing OpenSSL
sudo yum install perl
sudo yum install perl-core
sudo yum install perl-Test-Simple
#sudo yum install perl-Text-Template # perl Text::Template module should be 1.46 or later
#sudo yum install rh-perl524-perl-Text-Template
export OPENSSL_DIR=/home/centos/src/project_data/openssl
source ~/src/project_data/zt_rsa/rsa_use/install_openssl.sh

# System reboot
sudo shutdown -r now
