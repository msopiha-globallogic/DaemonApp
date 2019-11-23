#include <iostream>
#include <cstdio>

#include "token.h"
#include "connection.h"
#include "session.h"

int main() {
    Connection con(8080);
    if (con.StartListening()) {
        std::cout << "Failed to start listening. Err = " << con.GetLastErrorString()
                  << std::endl;
        return -1;
    }
    Session s(con.GetNextConnection(), "cert", "key");
    Token t = s.getSessionToken();
    std::cout << "Got token state " << t.getState();
    return 0;
}
