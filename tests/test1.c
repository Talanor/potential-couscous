#include <stdio.h>

int
main(void) {
    int i;

    i = 0;
    while (i < 10) {
        printf("i = %d\n", i);
        ++i;
    }
    return 0;
}
