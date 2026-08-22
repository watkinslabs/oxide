; Payload entered by the linked S3 wakeup trampoline. The trampoline owns
; every transition into long mode; this code is only the observable oracle.

bits 64
org 0x8000

start:
    mov rax, cr0
    and eax, 0x80000001
    cmp eax, 0x80000001
    jne fail

    mov rax, cr4
    test eax, 0x20
    jz fail

    mov rax, cr3
    cmp rax, 0x1000
    jne fail

    mov ecx, 0xc0000080
    rdmsr
    and eax, 0x0d00
    cmp eax, 0x0d00
    jne fail

    mov ax, cs
    cmp ax, 0x18
    jne fail
    mov ax, ds
    cmp ax, 0x10
    jne fail
    mov ax, ss
    cmp ax, 0x10
    jne fail

    lea rsi, [rel pass_message]
    mov dx, 0xe9
.pass_byte:
    lodsb
    test al, al
    jz .pass_exit
    out dx, al
    jmp .pass_byte
.pass_exit:
    mov dx, 0xf4
    mov eax, 0x10
    out dx, eax
    hlt

fail:
    lea rsi, [rel fail_message]
    mov dx, 0xe9
.fail_byte:
    lodsb
    test al, al
    jz .fail_exit
    out dx, al
    jmp .fail_byte
.fail_exit:
    mov dx, 0xf4
    mov eax, 0x11
    out dx, eax
    hlt

pass_message: db 'S3-TRAMPOLINE-PASS', 10, 0
fail_message: db 'S3-TRAMPOLINE-FAIL', 10, 0
