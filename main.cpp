#include <iostream>
#include <cstdio>

#include "log.h"
#include "token.h"
#include "connection.h"
#include "session.h"

int main() {
    LOGE("Start");
    LOGW("Start");
    LOGI("Start");
    LOGD("Start");
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
