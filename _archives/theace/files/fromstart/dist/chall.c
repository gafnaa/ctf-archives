#include <stdio.h>

__attribute__((constructor)) void init(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
}

__attribute__((naked)) void helper(){
    __asm__(
        "pop %rdi\nret\n"
        "pop %rsi\nret\n"
        "pop %rdx\nret\n"
    );
}

int main(){
    init();
    char mem[0x100];
    puts("pwning from the start okay?");
    gets(mem);
    return 0;
}