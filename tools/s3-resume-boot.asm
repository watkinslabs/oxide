; BIOS boot sector for the S3 wakeup-trampoline execution harness.

bits 16
org 0x7c00

start:
    cli
    mov ax, 0x0800
    mov es, ax
    xor bx, bx
    mov ah, 0x02
    mov al, 16
    mov ch, 0
    mov cl, 2
    mov dh, 0
    int 0x13
    jc disk_fail

    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00

    ; BIOS may use low scratch memory before loading this sector. Build the
    ; identity-map tables after firmware has handed control to the harness.
    mov di, 0x1000
    mov cx, 0x1800
    rep stosw
    mov dword [0x1000], 0x2003
    mov dword [0x1004], 0
    mov dword [0x2000], 0x3003
    mov dword [0x2004], 0
    mov dword [0x3000], 0x0083
    mov dword [0x3004], 0

    mov dword [0x9f00], 0x1000
    mov dword [0x9f04], 0
    mov dword [0x9f08], 0x8000
    mov dword [0x9f0c], 0
    jmp 0x0900:0

disk_fail:
    hlt
    jmp disk_fail

times 510 - ($ - $$) db 0
dw 0xaa55
