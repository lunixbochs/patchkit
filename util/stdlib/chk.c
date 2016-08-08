void stack_chk_fail() {
    printf("**** stack smashing detected ****\n");
    _terminate(1);
}
