#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

// This is the hidden function we want to find and execute.
void handle_sigill(int signum) {
    printf("Secret message revealed!\\n");
    printf("The signal handler was the key.\\n");
    exit(0);
}

// Macro to cause an illegal instruction.
#define BUG() __asm__("ud2")

int main() {
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = handle_sigill;
    sigaction(SIGILL, &act, NULL);
    printf("Hello guys!\\n");
    BUG();
    return 0;
}
