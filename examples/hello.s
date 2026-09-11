; hello.s — Hello from Anka, assembled from source
;
; Assemble:  anka asm hello.s -o hello.srec
; Run:       anka hello.srec

CONSOLE = $F00000

start:
    lea     message,a0
    lea     CONSOLE,a1

loop:
    move.b  (a0)+,d0
    beq     done
    move.b  d0,(a1)
    bra     loop

done:
    stop    #$2700

message:
    .ascii  "Hello from Anka!\n"
    .byte   0
