/* Additional x86 external-device vector heads.  Each 16-byte slot carries
 * the same synthetic error/vector frame as irq.rs before joining its common
 * register-save, GS-transition, and IRQ-exit path. */
.section .text

.p2align 4
.globl oxide_irq_vec_60
.type oxide_irq_vec_60, @function
oxide_irq_vec_60:
    push 0
    push 0x60
    jmp oxide_irq_common
.size oxide_irq_vec_60, . - oxide_irq_vec_60

.p2align 4
.globl oxide_irq_vec_61
.type oxide_irq_vec_61, @function
oxide_irq_vec_61:
    push 0
    push 0x61
    jmp oxide_irq_common
.size oxide_irq_vec_61, . - oxide_irq_vec_61

.p2align 4
.globl oxide_irq_vec_62
.type oxide_irq_vec_62, @function
oxide_irq_vec_62:
    push 0
    push 0x62
    jmp oxide_irq_common
.size oxide_irq_vec_62, . - oxide_irq_vec_62

.p2align 4
.globl oxide_irq_vec_63
.type oxide_irq_vec_63, @function
oxide_irq_vec_63:
    push 0
    push 0x63
    jmp oxide_irq_common
.size oxide_irq_vec_63, . - oxide_irq_vec_63

.p2align 4
.globl oxide_irq_vec_64
.type oxide_irq_vec_64, @function
oxide_irq_vec_64:
    push 0
    push 0x64
    jmp oxide_irq_common
.size oxide_irq_vec_64, . - oxide_irq_vec_64

.p2align 4
.globl oxide_irq_vec_65
.type oxide_irq_vec_65, @function
oxide_irq_vec_65:
    push 0
    push 0x65
    jmp oxide_irq_common
.size oxide_irq_vec_65, . - oxide_irq_vec_65

.p2align 4
.globl oxide_irq_vec_66
.type oxide_irq_vec_66, @function
oxide_irq_vec_66:
    push 0
    push 0x66
    jmp oxide_irq_common
.size oxide_irq_vec_66, . - oxide_irq_vec_66

.p2align 4
.globl oxide_irq_vec_67
.type oxide_irq_vec_67, @function
oxide_irq_vec_67:
    push 0
    push 0x67
    jmp oxide_irq_common
.size oxide_irq_vec_67, . - oxide_irq_vec_67

.p2align 4
.globl oxide_irq_vec_68
.type oxide_irq_vec_68, @function
oxide_irq_vec_68:
    push 0
    push 0x68
    jmp oxide_irq_common
.size oxide_irq_vec_68, . - oxide_irq_vec_68

.p2align 4
.globl oxide_irq_vec_69
.type oxide_irq_vec_69, @function
oxide_irq_vec_69:
    push 0
    push 0x69
    jmp oxide_irq_common
.size oxide_irq_vec_69, . - oxide_irq_vec_69

.p2align 4
.globl oxide_irq_vec_6a
.type oxide_irq_vec_6a, @function
oxide_irq_vec_6a:
    push 0
    push 0x6a
    jmp oxide_irq_common
.size oxide_irq_vec_6a, . - oxide_irq_vec_6a

.p2align 4
.globl oxide_irq_vec_6b
.type oxide_irq_vec_6b, @function
oxide_irq_vec_6b:
    push 0
    push 0x6b
    jmp oxide_irq_common
.size oxide_irq_vec_6b, . - oxide_irq_vec_6b

.p2align 4
.globl oxide_irq_vec_6c
.type oxide_irq_vec_6c, @function
oxide_irq_vec_6c:
    push 0
    push 0x6c
    jmp oxide_irq_common
.size oxide_irq_vec_6c, . - oxide_irq_vec_6c

.p2align 4
.globl oxide_irq_vec_6d
.type oxide_irq_vec_6d, @function
oxide_irq_vec_6d:
    push 0
    push 0x6d
    jmp oxide_irq_common
.size oxide_irq_vec_6d, . - oxide_irq_vec_6d

.p2align 4
.globl oxide_irq_vec_6e
.type oxide_irq_vec_6e, @function
oxide_irq_vec_6e:
    push 0
    push 0x6e
    jmp oxide_irq_common
.size oxide_irq_vec_6e, . - oxide_irq_vec_6e

.p2align 4
.globl oxide_irq_vec_6f
.type oxide_irq_vec_6f, @function
oxide_irq_vec_6f:
    push 0
    push 0x6f
    jmp oxide_irq_common
.size oxide_irq_vec_6f, . - oxide_irq_vec_6f

.p2align 4
.globl oxide_irq_vec_70
.type oxide_irq_vec_70, @function
oxide_irq_vec_70:
    push 0
    push 0x70
    jmp oxide_irq_common
.size oxide_irq_vec_70, . - oxide_irq_vec_70

.p2align 4
.globl oxide_irq_vec_71
.type oxide_irq_vec_71, @function
oxide_irq_vec_71:
    push 0
    push 0x71
    jmp oxide_irq_common
.size oxide_irq_vec_71, . - oxide_irq_vec_71

.p2align 4
.globl oxide_irq_vec_72
.type oxide_irq_vec_72, @function
oxide_irq_vec_72:
    push 0
    push 0x72
    jmp oxide_irq_common
.size oxide_irq_vec_72, . - oxide_irq_vec_72

.p2align 4
.globl oxide_irq_vec_73
.type oxide_irq_vec_73, @function
oxide_irq_vec_73:
    push 0
    push 0x73
    jmp oxide_irq_common
.size oxide_irq_vec_73, . - oxide_irq_vec_73

.p2align 4
.globl oxide_irq_vec_74
.type oxide_irq_vec_74, @function
oxide_irq_vec_74:
    push 0
    push 0x74
    jmp oxide_irq_common
.size oxide_irq_vec_74, . - oxide_irq_vec_74

.p2align 4
.globl oxide_irq_vec_75
.type oxide_irq_vec_75, @function
oxide_irq_vec_75:
    push 0
    push 0x75
    jmp oxide_irq_common
.size oxide_irq_vec_75, . - oxide_irq_vec_75

.p2align 4
.globl oxide_irq_vec_76
.type oxide_irq_vec_76, @function
oxide_irq_vec_76:
    push 0
    push 0x76
    jmp oxide_irq_common
.size oxide_irq_vec_76, . - oxide_irq_vec_76

.p2align 4
.globl oxide_irq_vec_77
.type oxide_irq_vec_77, @function
oxide_irq_vec_77:
    push 0
    push 0x77
    jmp oxide_irq_common
.size oxide_irq_vec_77, . - oxide_irq_vec_77

.p2align 4
.globl oxide_irq_vec_78
.type oxide_irq_vec_78, @function
oxide_irq_vec_78:
    push 0
    push 0x78
    jmp oxide_irq_common
.size oxide_irq_vec_78, . - oxide_irq_vec_78

.p2align 4
.globl oxide_irq_vec_79
.type oxide_irq_vec_79, @function
oxide_irq_vec_79:
    push 0
    push 0x79
    jmp oxide_irq_common
.size oxide_irq_vec_79, . - oxide_irq_vec_79

.p2align 4
.globl oxide_irq_vec_7a
.type oxide_irq_vec_7a, @function
oxide_irq_vec_7a:
    push 0
    push 0x7a
    jmp oxide_irq_common
.size oxide_irq_vec_7a, . - oxide_irq_vec_7a

.p2align 4
.globl oxide_irq_vec_7b
.type oxide_irq_vec_7b, @function
oxide_irq_vec_7b:
    push 0
    push 0x7b
    jmp oxide_irq_common
.size oxide_irq_vec_7b, . - oxide_irq_vec_7b

.p2align 4
.globl oxide_irq_vec_7c
.type oxide_irq_vec_7c, @function
oxide_irq_vec_7c:
    push 0
    push 0x7c
    jmp oxide_irq_common
.size oxide_irq_vec_7c, . - oxide_irq_vec_7c

.p2align 4
.globl oxide_irq_vec_7d
.type oxide_irq_vec_7d, @function
oxide_irq_vec_7d:
    push 0
    push 0x7d
    jmp oxide_irq_common
.size oxide_irq_vec_7d, . - oxide_irq_vec_7d

.p2align 4
.globl oxide_irq_vec_7e
.type oxide_irq_vec_7e, @function
oxide_irq_vec_7e:
    push 0
    push 0x7e
    jmp oxide_irq_common
.size oxide_irq_vec_7e, . - oxide_irq_vec_7e

.p2align 4
.globl oxide_irq_vec_7f
.type oxide_irq_vec_7f, @function
oxide_irq_vec_7f:
    push 0
    push 0x7f
    jmp oxide_irq_common
.size oxide_irq_vec_7f, . - oxide_irq_vec_7f
