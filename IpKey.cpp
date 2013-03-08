
#include "IpKey.h"

bool operator<(const IpKey& lhs, const IpKey& rhs) {
    return lhs.addrA > rhs.addrA;
}

bool operator==(const IpKey &lhs, const IpKey &rhs) {
    if (lhs.addrA == rhs.addrA &&
            lhs.addrB == rhs.addrB &&
            lhs.portA == rhs.portA &&
            lhs.portB == rhs.portB
            ) {
        return true;
    } else {
        return false;
    }
}