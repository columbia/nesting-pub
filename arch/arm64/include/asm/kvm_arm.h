/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ARM64_KVM_ARM_H__
#define __ARM64_KVM_ARM_H__

#include <asm/esr.h>
#include <asm/memory.h>
#include <asm/types.h>

/* Hyp Configuration Register (HCR) bits */
#define HCR_AT		(UL(1) << 44)
#define HCR_NV1		(UL(1) << 43)
#define HCR_NV		(UL(1) << 42)
#define HCR_E2H		(UL(1) << 34)
#define HCR_ID		(UL(1) << 33)
#define HCR_CD		(UL(1) << 32)
#define HCR_RW_SHIFT	31
#define HCR_RW		(UL(1) << HCR_RW_SHIFT)
#define HCR_TRVM	(UL(1) << 30)
#define HCR_HCD		(UL(1) << 29)
#define HCR_TDZ		(UL(1) << 28)
#define HCR_TGE		(UL(1) << 27)
#define HCR_TVM		(UL(1) << 26)
#define HCR_TTLB	(UL(1) << 25)
#define HCR_TPU		(UL(1) << 24)
#define HCR_TPC		(UL(1) << 23)
#define HCR_TSW		(UL(1) << 22)
#define HCR_TAC		(UL(1) << 21)
#define HCR_TIDCP	(UL(1) << 20)
#define HCR_TSC		(UL(1) << 19)
#define HCR_TID3	(UL(1) << 18)
#define HCR_TID2	(UL(1) << 17)
#define HCR_TID1	(UL(1) << 16)
#define HCR_TID0	(UL(1) << 15)
#define HCR_TWE		(UL(1) << 14)
#define HCR_TWI		(UL(1) << 13)
#define HCR_DC		(UL(1) << 12)
#define HCR_BSU		(3 << 10)
#define HCR_BSU_IS	(UL(1) << 10)
#define HCR_FB		(UL(1) << 9)
#define HCR_VSE		(UL(1) << 8)
#define HCR_VI		(UL(1) << 7)
#define HCR_VF		(UL(1) << 6)
#define HCR_AMO		(UL(1) << 5)
#define HCR_IMO		(UL(1) << 4)
#define HCR_FMO		(UL(1) << 3)
#define HCR_PTW		(UL(1) << 2)
#define HCR_SWIO	(UL(1) << 1)
#define HCR_VM		(UL(1) << 0)

/*
 * The bits we set in HCR:
 * RW:		64bit by default, can be overridden for 32bit VMs
 * TAC:		Trap ACTLR
 * TSC:		Trap SMC
 * TVM:		Trap VM ops (until M+C set in SCTLR_EL1)
 * TSW:		Trap cache operations by set/way
 * TWE:		Trap WFE
 * TWI:		Trap WFI
 * TIDCP:	Trap L2CTLR/L2ECTLR
 * BSU_IS:	Upgrade barriers to the inner shareable domain
 * FB:		Force broadcast of all maintainance operations
 * AMO:		Override CPSR.A and enable signaling with VA
 * IMO:		Override CPSR.I and enable signaling with VI
 * FMO:		Override CPSR.F and enable signaling with VF
 * SWIO:	Turn set/way invalidates into set/way clean+invalidate
 */
#define HCR_GUEST_FLAGS (HCR_TSC | HCR_TSW | HCR_TWE | HCR_TWI | HCR_VM | \
			 HCR_TVM | HCR_BSU_IS | HCR_FB | HCR_TAC | \
			 HCR_AMO | HCR_SWIO | HCR_TIDCP | HCR_RW)
#define HCR_VIRT_EXCP_MASK (HCR_VSE | HCR_VI | HCR_VF)
#define HCR_INT_OVERRIDE   (HCR_FMO | HCR_IMO)
#define HCR_HOST_VHE_FLAGS (HCR_RW | HCR_TGE | HCR_E2H)

/* TCR_EL2 Registers bits */
#define TCR_EL2_RES1		((1 << 31) | (1 << 23))
#define TCR_EL2_TBI		(1 << 20)
#define TCR_EL2_PS_SHIFT	16
#define TCR_EL2_PS_MASK		(7 << TCR_EL2_PS_SHIFT)
#define TCR_EL2_PS_40B		(2 << TCR_EL2_PS_SHIFT)
#define TCR_EL2_TG0_MASK	TCR_TG0_MASK
#define TCR_EL2_SH0_MASK	TCR_SH0_MASK
#define TCR_EL2_ORGN0_MASK	TCR_ORGN0_MASK
#define TCR_EL2_IRGN0_MASK	TCR_IRGN0_MASK
#define TCR_EL2_T0SZ_MASK	0x3f
#define TCR_EL2_MASK	(TCR_EL2_TG0_MASK | TCR_EL2_SH0_MASK | \
			 TCR_EL2_ORGN0_MASK | TCR_EL2_IRGN0_MASK | TCR_EL2_T0SZ_MASK)

/* VTCR_EL2 Registers bits */
#define VTCR_EL2_RES1		(1 << 31)
#define VTCR_EL2_HD		(1 << 22)
#define VTCR_EL2_HA		(1 << 21)
#define VTCR_EL2_PS_SHIFT	TCR_EL2_PS_SHIFT
#define VTCR_EL2_PS_MASK	TCR_EL2_PS_MASK
#define VTCR_EL2_TG0_MASK	TCR_TG0_MASK
#define VTCR_EL2_TG0_4K		TCR_TG0_4K
#define VTCR_EL2_TG0_16K	TCR_TG0_16K
#define VTCR_EL2_TG0_64K	TCR_TG0_64K
#define VTCR_EL2_SH0_MASK	TCR_SH0_MASK
#define VTCR_EL2_SH0_SHIFT	TCR_SH0_SHIFT
#define VTCR_EL2_SH0_INNER	TCR_SH0_INNER
#define VTCR_EL2_ORGN0_MASK	TCR_ORGN0_MASK
#define VTCR_EL2_ORGN0_WBWA	TCR_ORGN0_WBWA
#define VTCR_EL2_IRGN0_MASK	TCR_IRGN0_MASK
#define VTCR_EL2_IRGN0_WBWA	TCR_IRGN0_WBWA
#define VTCR_EL2_SL0_SHIFT	6
#define VTCR_EL2_SL0_MASK	(3 << VTCR_EL2_SL0_SHIFT)
#define VTCR_EL2_SL0_LVL1	(1 << VTCR_EL2_SL0_SHIFT)
#define VTCR_EL2_T0SZ_MASK	0x3f
#define VTCR_EL2_T0SZ_40B	24
#define VTCR_EL2_VS_SHIFT	19
#define VTCR_EL2_VS_8BIT	(0 << VTCR_EL2_VS_SHIFT)
#define VTCR_EL2_VS_16BIT	(1 << VTCR_EL2_VS_SHIFT)

/*
 * We configure the Stage-2 page tables to always restrict the IPA space to be
 * 40 bits wide (T0SZ = 24).  Systems with a PARange smaller than 40 bits are
 * not known to exist and will break with this configuration.
 *
 * VTCR_EL2.PS is extracted from ID_AA64MMFR0_EL1.PARange at boot time
 * (see hyp-init.S).
 *
 * Note that when using 4K pages, we concatenate two first level page tables
 * together. With 16K pages, we concatenate 16 first level page tables.
 *
 * The magic numbers used for VTTBR_X in this patch can be found in Tables
 * D4-23 and D4-25 in ARM DDI 0487A.b.
 */

#define VTCR_EL2_T0SZ_IPA	VTCR_EL2_T0SZ_40B
#define VTCR_EL2_COMMON_BITS	(VTCR_EL2_SH0_INNER | VTCR_EL2_ORGN0_WBWA | \
				 VTCR_EL2_IRGN0_WBWA | VTCR_EL2_RES1)

#ifdef CONFIG_ARM64_64K_PAGES
/*
 * Stage2 translation configuration:
 * 64kB pages (TG0 = 1)
 * 2 level page tables (SL = 1)
 */
#define VTCR_EL2_TGRAN_FLAGS		(VTCR_EL2_TG0_64K | VTCR_EL2_SL0_LVL1)
#define VTTBR_X_TGRAN_MAGIC		38
#elif defined(CONFIG_ARM64_16K_PAGES)
/*
 * Stage2 translation configuration:
 * 16kB pages (TG0 = 2)
 * 2 level page tables (SL = 1)
 */
#define VTCR_EL2_TGRAN_FLAGS		(VTCR_EL2_TG0_16K | VTCR_EL2_SL0_LVL1)
#define VTTBR_X_TGRAN_MAGIC		42
#else	/* 4K */
/*
 * Stage2 translation configuration:
 * 4kB pages (TG0 = 0)
 * 3 level page tables (SL = 1)
 */
#define VTCR_EL2_TGRAN_FLAGS		(VTCR_EL2_TG0_4K | VTCR_EL2_SL0_LVL1)
#define VTTBR_X_TGRAN_MAGIC		37
#endif

#define VTCR_EL2_FLAGS			(VTCR_EL2_COMMON_BITS | VTCR_EL2_TGRAN_FLAGS)
#define VTTBR_X				(VTTBR_X_TGRAN_MAGIC - VTCR_EL2_T0SZ_IPA)

#define VTTBR_BADDR_MASK  (((UL(1) << (PHYS_MASK_SHIFT - VTTBR_X)) - 1) << VTTBR_X)
#define VTTBR_VMID_SHIFT  (UL(48))
#define VTTBR_VMID_MASK(size) (_AT(u64, (1 << size) - 1) << VTTBR_VMID_SHIFT)

#define SCTLR_EE	(UL(1) << 25)

/* Hyp System Trap Register */
#define HSTR_EL2_T(x)	(1 << x)

/* Hyp Coprocessor Trap Register Shifts */
#define CPTR_EL2_TFP_SHIFT 10

/* Hyp Coprocessor Trap Register */
#define CPTR_EL2_TCPAC	(1 << 31)
#define CPTR_EL2_TTA	(1 << 20)
#define CPTR_EL2_TFP	(1 << CPTR_EL2_TFP_SHIFT)
#define CPTR_EL2_TZ	(1 << 8)
#define CPTR_EL2_RES1	0x000032ff /* known RES1 bits in CPTR_EL2 */
#define CPTR_EL2_DEFAULT	CPTR_EL2_RES1

/* Hyp Debug Configuration Register bits */
#define MDCR_EL2_TPMS		(1 << 14)
#define MDCR_EL2_E2PB_MASK	(UL(0x3))
#define MDCR_EL2_E2PB_SHIFT	(UL(12))
#define MDCR_EL2_TDRA		(1 << 11)
#define MDCR_EL2_TDOSA		(1 << 10)
#define MDCR_EL2_TDA		(1 << 9)
#define MDCR_EL2_TDE		(1 << 8)
#define MDCR_EL2_HPME		(1 << 7)
#define MDCR_EL2_TPM		(1 << 6)
#define MDCR_EL2_TPMCR		(1 << 5)
#define MDCR_EL2_HPMN_MASK	(0x1F)

/* For compatibility with fault code shared with 32-bit */
#define FSC_FAULT	ESR_ELx_FSC_FAULT
#define FSC_ACCESS	ESR_ELx_FSC_ACCESS
#define FSC_PERM	ESR_ELx_FSC_PERM
#define FSC_SEA		ESR_ELx_FSC_EXTABT
#define FSC_SEA_TTW0	(0x14)
#define FSC_SEA_TTW1	(0x15)
#define FSC_SEA_TTW2	(0x16)
#define FSC_SEA_TTW3	(0x17)
#define FSC_SECC	(0x18)
#define FSC_SECC_TTW0	(0x1c)
#define FSC_SECC_TTW1	(0x1d)
#define FSC_SECC_TTW2	(0x1e)
#define FSC_SECC_TTW3	(0x1f)

/* Hyp Prefetch Fault Address Register (HPFAR/HDFAR) */
#define HPFAR_MASK	(~UL(0xf))

#define kvm_arm_exception_type	\
	{0, "IRQ" }, 		\
	{1, "TRAP" }

#define ECN(x) { ESR_ELx_EC_##x, #x }

#define kvm_arm_exception_class \
	ECN(UNKNOWN), ECN(WFx), ECN(CP15_32), ECN(CP15_64), ECN(CP14_MR), \
	ECN(CP14_LS), ECN(FP_ASIMD), ECN(CP10_ID), ECN(CP14_64), ECN(SVC64), \
	ECN(HVC64), ECN(SMC64), ECN(SYS64), ECN(IMP_DEF), ECN(IABT_LOW), \
	ECN(IABT_CUR), ECN(PC_ALIGN), ECN(DABT_LOW), ECN(DABT_CUR), \
	ECN(SP_ALIGN), ECN(FP_EXC32), ECN(FP_EXC64), ECN(SERROR), \
	ECN(BREAKPT_LOW), ECN(BREAKPT_CUR), ECN(SOFTSTP_LOW), \
	ECN(SOFTSTP_CUR), ECN(WATCHPT_LOW), ECN(WATCHPT_CUR), \
	ECN(BKPT32), ECN(VECTOR32), ECN(BRK64)

#define CPACR_EL1_FPEN		(3 << 20)
#define CPACR_EL1_TTA		(1 << 28)
#define CPACR_EL1_DEFAULT	(CPACR_EL1_FPEN | CPACR_EL1_ZEN_EL1EN)

#ifdef CONFIG_KVM_ARM_NESTED_PV
/*
 * 0 is reserved as an invalid value.
 * Order should be kept in sync with the save/restore code.
 */
#define	__INVALID_SYSREG__ 0
#define	MPIDR_EL1	1	/* MultiProcessor Affinity Register */
#define	CSSELR_EL1	2	/* Cache Size Selection Register */
#define	SCTLR_EL1	3	/* System Control Register */
#define	ACTLR_EL1	4	/* Auxiliary Control Register */
#define	CPACR_EL1	5	/* Coprocessor Access Control */
#define	TTBR0_EL1	6	/* Translation Table Base Register 0 */
#define	TTBR1_EL1	7	/* Translation Table Base Register 1 */
#define	TCR_EL1		8	/* Translation Control Register */
#define	ESR_EL1		9	/* Exception Syndrome Register */
#define	AFSR0_EL1	10	/* Auxiliary Fault Status Register 0 */
#define	AFSR1_EL1	11	/* Auxiliary Fault Status Register 1 */
#define	FAR_EL1		12	/* Fault Address Register */
#define	MAIR_EL1	13	/* Memory Attribute Indirection Register */
#define	VBAR_EL1	14	/* Vector Base Address Register */
#define	CONTEXTIDR_EL1	15	/* Context ID Register */
#define	TPIDR_EL0	16	/* Thread ID, User R/W */
#define	TPIDRRO_EL0	17	/* Thread ID, User R/O */
#define	TPIDR_EL1	18	/* Thread ID, Privileged */
#define	AMAIR_EL1	19	/* Aux Memory Attribute Indirection Register */
#define	CNTKCTL_EL1	20	/* Timer Control Register (EL1) */
#define	PAR_EL1		21	/* Physical Address Register */
#define	MDSCR_EL1	22	/* Monitor Debug System Control Register */
#define	MDCCINT_EL1	23	/* Monitor Debug Comms Channel Interrupt Enable Reg */
/* Performance Monitors Registers */
#define	PMCR_EL0	24	/* Control Register */
#define	PMSELR_EL0	25	/* Event Counter Selection Register */
#define	PMEVCNTR0_EL0	26	/* Event Counter Register (0-30) */
#define	PMEVCNTR30_EL0  (PMEVCNTR0_EL0 + 30)
#define	PMCCNTR_EL0	57	/* Cycle Counter Register */
#define	PMEVTYPER0_EL0	58	/* Event Type Register (0-30) */
#define	PMEVTYPER30_EL0 (PMEVTYPER0_EL0 + 30)
#define	PMCCFILTR_EL0	89	/* Cycle Count Filter Register */
#define	PMCNTENSET_EL0	90	/* Count Enable Set Register */
#define	PMINTENSET_EL1	91	/* Interrupt Enable Set Register */
#define	PMOVSSET_EL0	92	/* Overflow Flag Status Set Register */
#define	PMSWINC_EL0	93	/* Software Increment Register */
#define	PMUSERENR_EL0	94	/* User Enable Register */
/* 32bit specific registers. Keep them at the end of the range */
#define	DACR32_EL2	95	/* Domain Access Control Register */
#define	IFSR32_EL2	96	/* Instruction Fault Status Register */
#define	FPEXC32_EL2	97	/* Floating-Point Exception Control Register */
#define	DBGVCR32_EL2	98	/* Debug Vector Catch Register */
/* EL2 Regs */
#define VPIDR_EL2	99      /* Virtualization Processor ID Register */
#define VMPIDR_EL2	100	/* Virtualization Multiprocessor ID Register */
#define SCTLR_EL2	101	/* System Control Register (EL2) */
#define ACTLR_EL2	102	/* Auxiliary Control Register (EL2) */
#define HCR_EL2		103	/* Hypervisor Configuration Register */
#define MDCR_EL2	104	/* Monitor Debug Configuration Register (EL2) */
#define CPTR_EL2	105	/* Architectural Feature Trap Register (EL2) */
#define HSTR_EL2	106	/* Hypervisor System Trap Register */
#define HACR_EL2	107	/* Hypervisor Auxiliary Control Register */
#define TTBR0_EL2	108	/* Translation Table Base Register 0 (EL2) */
#define TTBR1_EL2	109	/* Translation Table Base Register 1 (EL2) */
#define TCR_EL2		110	/* Translation Control Register (EL2) */
#define VTTBR_EL2	111	/* Virtualization Translation Table Base Register */
#define VTCR_EL2	112	/* Virtualization Translation Control Register */
#define AFSR0_EL2	113	/* Auxiliary Fault Status Register 0 (EL2) */
#define AFSR1_EL2	114	/* Auxiliary Fault Status Register 1 (EL2) */
#define ESR_EL2		115	/* Exception Syndrome Register (EL2) */
#define FAR_EL2		116	/* Hypervisor IPA Fault Address Register */
#define HPFAR_EL2	117	/* Hypervisor IPA Fault Address Register */
#define MAIR_EL2	118	/* Memory Attribute Indirection Register (EL2) */
#define AMAIR_EL2	119	/* Auxiliary Memory Attribute Indirection Register (EL2) */
#define VBAR_EL2	120	/* Vector Base Address Register (EL2) */
#define RVBAR_EL2	121	/* Reset Vector Base Address Register */
#define RMR_EL2		122	/* Reset Management Register */
#define	CONTEXTIDR_EL2	123	/* Context ID Register */
#define TPIDR_EL2	124	/* EL2 Software Thread ID Register */
#define CNTVOFF_EL2	125	/* Counter-timer Virtual Offset register */
#define CNTHCTL_EL2	126	/* Counter-timer Hypervisor Control register */

#define	NR_SYS_REGS	127	/* Nothing after this line! */

#define	SP_EL1		128	/* Stack pointer (EL1) */
#define	ELR_EL1		129	/* Exception Link Register */
#define	SPSR_EL1	130	/* Saved Program Status Register */

#define SPSR_EL2_PV	131	/* Saved Program Status Register (EL2) */
#define ELR_EL2_PV	132	/* Exception Link Register (EL2) */
#define SP_EL2_PV	133	/* Stack Pointer (EL2) */

#define SPSR_EL2	1	/* Saved Program Status Register (EL2) */
#define ELR_EL2		2	/* Exception Link Register (EL2) */
#define SP_EL2		3	/* Stack Pointer (EL2) */
#define	NR_EL2_SPECIAL_REGS	4	/* Nothing after this line! */

#endif

#endif /* __ARM64_KVM_ARM_H__ */
