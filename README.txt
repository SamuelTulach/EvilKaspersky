This is an old experiment I did year ago and now just saw the repo and decided
to make it public. It is KasperkyHook, but the syscalls directly point onto
functions useful for interprocess memory copying. You can fully unload the control
driver afterwards and erase its memory. Another advantage is that you won't have any
unsigned code at the stack trace of the thread.

KasperskyHook: https://github.com/iPower/KasperskyHook
