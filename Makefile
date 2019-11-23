OPENSSL_DIR := /mnt/ssd/msopiha/repo/BMW/openssl-1.1.1d
INCLUDES = -I$(OPENSSL_DIR)/include
SRC :=  main.cpp \
	aes.cpp \
	reader.cpp \
	private_key.cpp \
	connection.cpp \
	session.cpp

all:
	g++ -std=c++11 -Wall $(INCLUDES) $(SRC) -o app -L. $(OPENSSL_DIR)/libcrypto.a -ldl -lpthread
