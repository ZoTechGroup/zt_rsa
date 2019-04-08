# Setup actions for newly created Nimbix instance

sudo apt update
# sudo apt-get upgrade # system update may take a long time
sudo apt install build-essential
sudo apt install gcc
sudo apt install g++
sudo apt install make
sudo apt install git
sudo apt install subversion
sudo apt install mc
sudo apt install libgmp-dev # required for modular exponentiation
sudo apt install libpthread-stubs0-dev # for pthread lib update

# Installing OpenSSL
sudo apt install perl
sudo apt install libtext-template-perl

export OPENSSL_DIR=/home/nimbix/data/openssl
if [ -d "$OPENSSL_DIR" ]; then
	echo "$OPENSSL_DIR already exists, just installing OpenSSL:"
	cd $OPENSSL_DIR
	sudo make install
else
	echo "OPENSSL_DIR doesn't exist, downloading and installing OpenSSL:"
    source ~/data/rsa_use/install_openssl.sh
fi

# System reboot
sudo shutdown -r now
