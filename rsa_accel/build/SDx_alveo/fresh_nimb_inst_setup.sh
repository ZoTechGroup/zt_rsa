# Setup actions for newly created Nimbix instance

sudo apt -y update
sudo apt -y upgrade # system update may take a long time
sudo apt -y install build-essential
sudo apt -y install gcc
sudo apt -y install g++
sudo apt -y install make
sudo apt -y install git
sudo apt -y install subversion
sudo apt -y install mc
sudo apt -y install libgmp-dev # required for modular exponentiation
sudo apt -y install libpthread-stubs0-dev # for pthread lib update

# Installing OpenSSL
sudo apt -y install perl
sudo apt -y install libtext-template-perl
export OPENSSL_DIR=/opt/example/openssl
source /opt/example/zt_rsa/rsa_use/install_openssl.sh

# System reboot
#sudo shutdown -r now
