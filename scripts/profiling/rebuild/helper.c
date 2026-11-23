#include "shared.h"
int profile_work(int n) {
    int i = 0;
    int value = 0;
    while (i < n) {
        value = value + 1;
        i = i + 1;
    }
    return value - 54;
}
