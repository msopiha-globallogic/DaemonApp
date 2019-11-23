OPENSSL_DIR := /home/alukin/proj/secure_debug/DaemonApp/openssl-1.1.1d
INCLUDES = -I$(OPENSSL_DIR)/include
SRC :=  aes.cpp \
	reader.cpp \
	private_key.cpp \
	connection.cpp \
	session.cpp


all:
	g++ -std=c++11 -Wall $(INCLUDES) $(SRC) main.cpp -o app -L. $(OPENSSL_DIR)/libcrypto.a -ldl -lpthread
	g++ -std=c++11 -Wall $(INCLUDES) $(SRC) posixdaemon.cpp posixdaemon_main.cpp -o posixdaemon_app -L. $(OPENSSL_DIR)/libcrypto.a -ldl -lpthread
