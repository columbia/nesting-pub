#ifndef __ARM64_KVM_NESTED_PV_ENCODING_H__
#define __ARM64_KVM_NESTED_PV_ENCODING_H__

#include <asm/kvm_arm.h>

/*
 * PV encoding in HVC 16bit immediate field.
 * The first three bits are used to encode instruction.
 *
 * 000 Reserved
 * 001 MRS
 * 010 MSR (register)
 * 011 MSR (immediate)
 * 100 ERET
 * 101 TLBI
 * 110 HVC
 * 111 Reserved
 *
 */

#define PV_INSTR_SHIFT	13
#define MRS_PV		0x1
#define MSR_REG_PV	0x2
#define MSR_IMM_PV	0x3
#define ERET_PV		0x4
#define TLBI_PV		0x5
#define HVC_PV		0x6

/*
 * MRS and MSR
 * 16bit = 3bit (intr) + 8bit (sysregs) + 5bit (gpregs)
 */

#define MS_IMM          (1 << 13)	/* [13] Set if MRS_IMM*/
#define MS_SYSREG_SHIFT 5
#define MS_SYSREG_MASK  (0xFF << MS_SYSREG_SHIFT) /* 8 bits [5:12]*/
#define MS_GPREG_MASK   0x1F		/* 5 bits [0:4] */
#define MS_IMM_MASK     0x0F		/* 4 bits [0:3] */

#define get_sysreg_num(x)	(((x) & MS_SYSREG_MASK) >> MS_SYSREG_SHIFT)
#define get_gpreg_num(x)	((x) & MS_GPREG_MASK)
#define get_msr_imm(x)		((x) & MS_IMM_MASK)
#define is_msr_imm(x)		((x) & MS_IMM)
#define is_el2_reg(x)		0

/*
 * TLBI
 * 16bit = 3bit (intr) + 8bit (tlbi-instr) + 5bit (gpregs)
 */

#define TLBI_INSTR_SHIFT 5

#define	IPAS2E1IS	1
#define	VMALLE1IS	2
#define	VMALLS12E1IS	3
#define	ALLE2		4
#define	ALLE1IS		5

/* Macros for encoding */
#define HVC_IMM_OFFSET		5	/* imm field is in hvc[20:5] */
#define HVC_IMM_SHIFT(x)	((x) << HVC_IMM_OFFSET)

/* Common */
#define ENCODE_INSTR(x)		(HVC_IMM_SHIFT((x) << PV_INSTR_SHIFT))
#define ENCODE_GP_REG(x)	(HVC_IMM_SHIFT(x))

/* For MRS, MSR */
#define ENCODE_EL2_SYSREG(x)	(HVC_IMM_SHIFT(((x) << MS_SYSREG_SHIFT)))
#define ENCODE_EL1_SYSREG(x)	(HVC_IMM_SHIFT(((x) << MS_SYSREG_SHIFT)))

/* For TLBI*/
#define ENCODE_TLBI_INSTR(x)	(HVC_IMM_SHIFT((x) << TLBI_INSTR_SHIFT))

#ifdef __ASSEMBLY__
/* Instructions */
.equ .L__mrs,	(ENCODE_INSTR(MRS_PV))
.equ .L__msr_imm,	(ENCODE_INSTR(MSR_IMM_PV))
.equ .L__msr,	(ENCODE_INSTR(MSR_REG_PV))
.equ .L__eret,	(ENCODE_INSTR(ERET_PV))
.equ .L__tlbi,	(ENCODE_INSTR(TLBI_PV))
.equ .L__hvc,	(ENCODE_INSTR(HVC_PV))

/* EL2 system registers */
.equ .L__elr_el2,	(ENCODE_EL2_SYSREG(ELR_EL2))
.equ .L__spsr_el2,	(ENCODE_EL2_SYSREG(SPSR_EL2))
.equ .L__sp_el2,	(ENCODE_EL2_SYSREG(SP_EL2))
.equ .L__amair_el2,	(ENCODE_EL2_SYSREG(AMAIR_EL2))
.equ .L__mair_el2,	(ENCODE_EL2_SYSREG(MAIR_EL2))
.equ .L__tcr_el2,	(ENCODE_EL2_SYSREG(TCR_EL2))
.equ .L__ttbr0_el2,	(ENCODE_EL2_SYSREG(TTBR0_EL2))
.equ .L__vtcr_el2,	(ENCODE_EL2_SYSREG(VTCR_EL2))
.equ .L__vttbr_el2,	(ENCODE_EL2_SYSREG(VTTBR_EL2))
.equ .L__vmpidr_el2,	(ENCODE_EL2_SYSREG(VMPIDR_EL2))
.equ .L__vpidr_el2,	(ENCODE_EL2_SYSREG(VPIDR_EL2))
.equ .L__mdcr_el2,	(ENCODE_EL2_SYSREG(MDCR_EL2))
.equ .L__cnthctl_el2,	(ENCODE_EL2_SYSREG(CNTHCTL_EL2))
.equ .L__cnthp_ctl_el2,	(ENCODE_EL2_SYSREG(CNTHP_CTL_EL2))
.equ .L__cnthp_cval_el2,	(ENCODE_EL2_SYSREG(CNTHP_CVAL_EL2))
.equ .L__cnthp_tval_el2,	(ENCODE_EL2_SYSREG(CNTHP_TVAL_EL2))
.equ .L__cntvoff_el2,	(ENCODE_EL2_SYSREG(CNTVOFF_EL2))
.equ .L__actlr_el2,	(ENCODE_EL2_SYSREG(ACTLR_EL2))
.equ .L__afsr0_el2,	(ENCODE_EL2_SYSREG(AFSR0_EL2))
.equ .L__afsr1_el2,	(ENCODE_EL2_SYSREG(AFSR1_EL2))
.equ .L__cptr_el2,	(ENCODE_EL2_SYSREG(CPTR_EL2))
.equ .L__esr_el2,	(ENCODE_EL2_SYSREG(ESR_EL2))
.equ .L__far_el2,	(ENCODE_EL2_SYSREG(FAR_EL2))
.equ .L__hacr_el2,	(ENCODE_EL2_SYSREG(HACR_EL2))
.equ .L__hcr_el2,	(ENCODE_EL2_SYSREG(HCR_EL2))
.equ .L__hpfar_el2,	(ENCODE_EL2_SYSREG(HPFAR_EL2))
.equ .L__hstr_el2,	(ENCODE_EL2_SYSREG(HSTR_EL2))
.equ .L__rmr_el2,	(ENCODE_EL2_SYSREG(RMR_EL2))
.equ .L__rvbar_el2,	(ENCODE_EL2_SYSREG(RVBAR_EL2))
.equ .L__sctlr_el2,	(ENCODE_EL2_SYSREG(SCTLR_EL2))
.equ .L__tpidr_el2,	(ENCODE_EL2_SYSREG(TPIDR_EL2))
.equ .L__vbar_el2,	(ENCODE_EL2_SYSREG(VBAR_EL2))
.equ .L__sp_el1,	(ENCODE_EL1_SYSREG(SP_EL1))
.equ .L__vbar_el1,	(ENCODE_EL1_SYSREG(VBAR_EL1))

/* TLBI instructions */
.equ .L__ipas2e1is,	(ENCODE_TLBI_INSTR(IPAS2E1IS))
.equ .L__vmalle1is,	(ENCODE_TLBI_INSTR(VMALLE1IS))
.equ .L__vmalls12e1is,	(ENCODE_TLBI_INSTR(VMALLS12E1IS))
.equ .L__alle2,		(ENCODE_TLBI_INSTR(ALLE2))
.equ .L__alle1is,	(ENCODE_TLBI_INSTR(ALLE1IS))

/* GP registers*/
.irp	num,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
.equ .L__gpreg_num_x\num, (ENCODE_GP_REG(\num))
.endr
.equ .L__gpreg_num_lr, (ENCODE_GP_REG(30))
.equ .L__gpreg_num_xzr, (ENCODE_GP_REG(31))

#else
#endif /* __ASSEMBLY__ */

#define PV_CONST							\
".equ .L__mrs,"		__stringify(ENCODE_INSTR(MRS_PV))"\n"		\
".equ .L__msr_imm,"	__stringify(ENCODE_INSTR(MSR_IMM_PV))"\n"	\
".equ .L__msr,"		__stringify(ENCODE_INSTR(MSR_REG_PV))"\n"	\
".equ .L__eret,"	__stringify(ENCODE_INSTR(ERET_PV))"\n"		\
".equ .L__tlbi,"	__stringify(ENCODE_INSTR(TLBI_PV))"\n"		\
".equ .L__hvc,"		__stringify(ENCODE_INSTR(HVC_PV))"\n"		\
"\n"									\
".equ .L__elr_el2,"	__stringify(ENCODE_EL2_SYSREG(ELR_EL2))"\n"	\
".equ .L__spsr_el2,"	__stringify(ENCODE_EL2_SYSREG(SPSR_EL2))"\n"	\
".equ .L__sp_el2,"	__stringify(ENCODE_EL2_SYSREG(SP_EL2))"\n"	\
".equ .L__amair_el2,"	__stringify(ENCODE_EL2_SYSREG(AMAIR_EL2))"\n"	\
".equ .L__mair_el2,"	__stringify(ENCODE_EL2_SYSREG(MAIR_EL2))"\n"	\
".equ .L__tcr_el2,"	__stringify(ENCODE_EL2_SYSREG(TCR_EL2))"\n"	\
".equ .L__ttbr0_el2,"	__stringify(ENCODE_EL2_SYSREG(TTBR0_EL2))"\n"	\
".equ .L__vtcr_el2,"	__stringify(ENCODE_EL2_SYSREG(VTCR_EL2))"\n"	\
".equ .L__vttbr_el2,"	__stringify(ENCODE_EL2_SYSREG(VTTBR_EL2))"\n"	\
".equ .L__vmpidr_el2,"	__stringify(ENCODE_EL2_SYSREG(VMPIDR_EL2))"\n"	\
".equ .L__vpidr_el2,"	__stringify(ENCODE_EL2_SYSREG(VPIDR_EL2))"\n"	\
".equ .L__mdcr_el2,"	__stringify(ENCODE_EL2_SYSREG(MDCR_EL2))"\n"	\
".equ .L__cnthctl_el2,"	__stringify(ENCODE_EL2_SYSREG(CNTHCTL_EL2))"\n"	\
".equ .L__cnthp_ctl_el2,"	__stringify(ENCODE_EL2_SYSREG(CNTHP_CTL_EL2))"\n"	\
".equ .L__cnthp_cval_el2,"	__stringify(ENCODE_EL2_SYSREG(CNTHP_CVAL_EL2))"\n"	\
".equ .L__cnthp_tval_el2,"	__stringify(ENCODE_EL2_SYSREG(CNTHP_TVAL_EL2))"\n"	\
".equ .L__cntvoff_el2,"	__stringify(ENCODE_EL2_SYSREG(CNTVOFF_EL2))"\n"	\
".equ .L__actlr_el2,"	__stringify(ENCODE_EL2_SYSREG(ACTLR_EL2))"\n"	\
".equ .L__afsr0_el2,"	__stringify(ENCODE_EL2_SYSREG(AFSR0_EL2))"\n"	\
".equ .L__afsr1_el2,"	__stringify(ENCODE_EL2_SYSREG(AFSR1_EL2))"\n"	\
".equ .L__cptr_el2,"	__stringify(ENCODE_EL2_SYSREG(CPTR_EL2))"\n"	\
".equ .L__esr_el2,"	__stringify(ENCODE_EL2_SYSREG(ESR_EL2))"\n"	\
".equ .L__far_el2,"	__stringify(ENCODE_EL2_SYSREG(FAR_EL2))"\n"	\
".equ .L__hacr_el2,"	__stringify(ENCODE_EL2_SYSREG(HACR_EL2))"\n"	\
".equ .L__hcr_el2,"	__stringify(ENCODE_EL2_SYSREG(HCR_EL2))"\n"	\
".equ .L__hpfar_el2,"	__stringify(ENCODE_EL2_SYSREG(HPFAR_EL2))"\n"	\
".equ .L__hstr_el2,"	__stringify(ENCODE_EL2_SYSREG(HSTR_EL2))"\n"	\
".equ .L__rmr_el2,"	__stringify(ENCODE_EL2_SYSREG(RMR_EL2))"\n"	\
".equ .L__rvbar_el2,"	__stringify(ENCODE_EL2_SYSREG(RVBAR_EL2))"\n"	\
".equ .L__sctlr_el2,"	__stringify(ENCODE_EL2_SYSREG(SCTLR_EL2))"\n"	\
".equ .L__tpidr_el2,"	__stringify(ENCODE_EL2_SYSREG(TPIDR_EL2))"\n"	\
".equ .L__vbar_el2,"	__stringify(ENCODE_EL2_SYSREG(VBAR_EL2))"\n"	\
".equ .L__sp_el1,"	__stringify(ENCODE_EL1_SYSREG(SP_EL1))"\n"	\
".equ .L__vbar_el1,"	__stringify(ENCODE_EL1_SYSREG(VBAR_EL1))"\n"	\
"\n"									\
".equ .L__ipas2e1is,"	__stringify(ENCODE_TLBI_INSTR(IPAS2E1IS))"\n"	\
".equ .L__vmalle1is,"	__stringify(ENCODE_TLBI_INSTR(VMALLE1IS))"\n"	\
".equ .L__vmalls12e1is,"	__stringify(ENCODE_TLBI_INSTR(VMALLS12E1IS))"\n"	\
".equ .L__alle2,"	__stringify(ENCODE_TLBI_INSTR(ALLE2))"\n"	\
".equ .L__alle1is,"	__stringify(ENCODE_TLBI_INSTR(ALLE1IS))"\n"	\
"\n"									\
".irp	num,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30\n"	\
".equ .L__gpreg_num_x\\num," 	__stringify(ENCODE_GP_REG(\\num))"\n"	\
".endr\n"								\
".equ .L__gpreg_num_lr,"	__stringify(ENCODE_GP_REG(30))"\n"	\
".equ .L__gpreg_num_xzr,"	__stringify (ENCODE_GP_REG(31))"\n"

#endif
