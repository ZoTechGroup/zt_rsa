
if [ -z "$OPENSSL_DIR" ]; then
	export OPENSSL_DIR=/home2/software/openssl
	echo "OPENSSL_DIR is not set, setting it to $OPENSSL_DIR location by default (meaning on-premises implementation)."
	echo "In case OpenSSL location should be different, please set it accordingly:"
	echo "export OPENSSL_DIR=$OPENSSL_DIR"
fi
echo "OPENSSL_DIR, needed for OpenSSL use cases of RSA accelerator, is set to $OPENSSL_DIR."

git clone --recurse-submodules git://git.openssl.org/openssl.git $OPENSSL_DIR
cd $OPENSSL_DIR
git checkout OpenSSL_1_1_1a
./config
make
make test
sudo make install
