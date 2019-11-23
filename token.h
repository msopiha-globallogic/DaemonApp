#ifndef TOKEN_H
#define TOKEN_H

class Token {
public:
    Token(): mState(SecurityState::Invalid){}
    enum SecurityState {
        Permissive = 0,
        Enforced,
        Invalid
    };

    SecurityState getState() {
        return mState;
    }

    void setState(long state) {
        switch (state) {
        case Permissive:
            mState = Permissive;
            break;
        case Enforced:
            mState = Enforced;
            break;
        default:
            break;
        }
    }

private:
    SecurityState  mState;
};

#endif // TOKEN_H
