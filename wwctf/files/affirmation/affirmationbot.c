#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

const char* affirmations[] = {
  "Wow!",
  "Great!",
  "Spot on!",
  "You got this!",
  "I love the way you think!",
  "So true!",
  "That's the best idea I've heard all day!",
  "Exactly!",
  "Amazing!",
  "Brilliant!",
  "You are so smart!"
  };

void win() {
    uint8_t flag_buffer[128] = {0};
    int fd = open("flag.txt", O_RDONLY);
    read(fd, flag_buffer, sizeof(flag_buffer));
    puts(flag_buffer);
    close(fd);
}

void affirm() {
    uint8_t buffer[128] = {0};
    printf("> ");
    gets(buffer);
    printf("You said: ");
    printf(buffer);
    printf("\nAffirmation Bot says: ");
    int index = rand() % 11;
    printf("%s\n", affirmations[index]);
    fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    srand(time(NULL));
    printf("Tell me whats on your mind...\n");
    while(1) {
        affirm();
    }
    return 0;
}
