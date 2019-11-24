TOPDIR = $(shell pwd)
OPENSSL_DIR := $(TOPDIR)/../openssl-1.1.1d
INCLUDES = -I$(OPENSSL_DIR)/include
SRC :=  aes.cpp \
	connection.cpp \
	cmdparser.cpp \
	posixdaemon.cpp \
	private_key.cpp \
	reader.cpp \
	session.cpp


all:
#	g++ -std=c++11 -Wall $(INCLUDES) $(SRC) main.cpp -o app -L. $(OPENSSL_DIR)/libcrypto.a -ldl -lpthread
	g++ -std=c++11 -Wall $(INCLUDES) $(SRC) posixdaemon_main.cpp -o posixdaemon_app -L. $(OPENSSL_DIR)/libcrypto.a -ldl -lpthread
