# Setup actions for newly created Nimbix instance

sudo apt update
#sudo apt upgrade -y # upgrade is not recommended for docker build (https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run)
sudo apt install -y apt-utils
sudo apt install -y build-essential
sudo apt install -y gcc
sudo apt install -y g++
sudo apt install -y make
sudo apt install -y git
sudo apt install -y subversion
sudo apt install -y mc
sudo apt install -y libgmp-dev # required for modular exponentiation
sudo apt install -y libpthread-stubs0-dev # for pthread lib update

# Installing OpenSSL
sudo apt install -y perl
sudo apt install -y libtext-template-perl
export OPENSSL_DIR=/opt/example/openssl
. /opt/example/zt_rsa/rsa_use/install_openssl.sh

# System reboot
#sudo shutdown -r now
