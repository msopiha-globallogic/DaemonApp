#ifndef TOKEN_H
#define TOKEN_H

class Token {
public:
    Token(): mState(SecurityState::Invalid){}
    enum SecurityState {
        DebugEnabled = 0,
        DebugDisabled,
        Invalid
    };

    SecurityState getState() {
        return mState;
    }

    bool isDebugEnabled() {
        if(mState == DebugEnabled)
            return true;
        else
            return false;
    }

    void setState(long state) {
        switch (state) {
        case DebugEnabled:
            mState = DebugEnabled;
            break;
        case DebugDisabled:
            mState = DebugDisabled;
            break;
        default:
            break;
        }
    }

private:
    SecurityState  mState = DebugDisabled;
};

#endif // TOKEN_H
