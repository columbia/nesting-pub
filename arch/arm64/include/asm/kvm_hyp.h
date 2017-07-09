/*
 * Copyright (C) 2015 - ARM Ltd
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

#ifndef __ARM64_KVM_HYP_H__
#define __ARM64_KVM_HYP_H__

#include <linux/compiler.h>
#include <linux/kvm_host.h>
#include <asm/kvm_mmu.h>
#include <asm/sysreg.h>

#define __hyp_text __section(.hyp.text) notrace

#define read_sysreg_elx(r,nvh,vh)					\
	({								\
		u64 reg;						\
		asm volatile(ALTERNATIVE("mrs %0, " __stringify(r##nvh),\
					 "mrs_s %0, " __stringify(r##vh),\
					 ARM64_HAS_VIRT_HOST_EXTN)	\
			     : "=r" (reg));				\
		reg;							\
	})

#define write_sysreg_elx(v,r,nvh,vh)					\
	do {								\
		u64 __val = (u64)(v);					\
		asm volatile(ALTERNATIVE("msr " __stringify(r##nvh) ", %x0",\
					 "msr_s " __stringify(r##vh) ", %x0",\
					 ARM64_HAS_VIRT_HOST_EXTN)	\
					 : : "rZ" (__val));		\
	} while (0)

/*
 * Unified accessors for registers that have a different encoding
 * between VHE and non-VHE. They must be specified without their "ELx"
 * encoding.
 */
#define read_sysreg_el2(r)						\
	({								\
		u64 reg;						\
		asm volatile(ALTERNATIVE("mrs %0, " __stringify(r##_EL2),\
					 "mrs %0, " __stringify(r##_EL1),\
					 ARM64_HAS_VIRT_HOST_EXTN)	\
			     : "=r" (reg));				\
		reg;							\
	})

#define write_sysreg_el2(v,r)						\
	do {								\
		u64 __val = (u64)(v);					\
		asm volatile(ALTERNATIVE("msr " __stringify(r##_EL2) ", %x0",\
					 "msr " __stringify(r##_EL1) ", %x0",\
					 ARM64_HAS_VIRT_HOST_EXTN)	\
					 : : "rZ" (__val));		\
	} while (0)

#define read_sysreg_el0(r)	read_sysreg_elx(r, _EL0, _EL02)
#define write_sysreg_el0(v,r)	write_sysreg_elx(v, r, _EL0, _EL02)
#define read_sysreg_el1(r)	read_sysreg_elx(r, _EL1, _EL12)
#define write_sysreg_el1(v,r)	write_sysreg_elx(v, r, _EL1, _EL12)

/**
 * hyp_alternate_select - Generates patchable code sequences that are
 * used to switch between two implementations of a function, depending
 * on the availability of a feature.
 *
 * @fname: a symbol name that will be defined as a function returning a
 * function pointer whose type will match @orig and @alt
 * @orig: A pointer to the default function, as returned by @fname when
 * @cond doesn't hold
 * @alt: A pointer to the alternate function, as returned by @fname
 * when @cond holds
 * @cond: a CPU feature (as described in asm/cpufeature.h)
 */
#define hyp_alternate_select(fname, orig, alt, cond)			\
typeof(orig) * __hyp_text fname(void)					\
{									\
	typeof(alt) *val = orig;					\
	asm volatile(ALTERNATIVE("nop		\n",			\
				 "mov	%0, %1	\n",			\
				 cond)					\
		     : "+r" (val) : "r" (alt));				\
	return val;							\
}

void __vgic_v2_save_state(struct kvm_vcpu *vcpu);
void __vgic_v2_restore_state(struct kvm_vcpu *vcpu);
int __vgic_v2_perform_cpuif_access(struct kvm_vcpu *vcpu);

void __vgic_v3_save_state(struct kvm_vcpu *vcpu);
void __vgic_v3_restore_state(struct kvm_vcpu *vcpu);
int __vgic_v3_perform_cpuif_access(struct kvm_vcpu *vcpu);

void __timer_save_state(struct kvm_vcpu *vcpu);
void __timer_restore_state(struct kvm_vcpu *vcpu);

void __sysreg_save_host_state(struct kvm_cpu_context *ctxt);
void __sysreg_restore_host_state(struct kvm_cpu_context *ctxt);
void __sysreg_save_guest_state(struct kvm_cpu_context *ctxt);
void __sysreg_restore_guest_state(struct kvm_cpu_context *ctxt);
void __sysreg32_save_state(struct kvm_vcpu *vcpu);
void __sysreg32_restore_state(struct kvm_vcpu *vcpu);

void __debug_save_state(struct kvm_vcpu *vcpu,
			struct kvm_guest_debug_arch *dbg,
			struct kvm_cpu_context *ctxt);
void __debug_restore_state(struct kvm_vcpu *vcpu,
			   struct kvm_guest_debug_arch *dbg,
			   struct kvm_cpu_context *ctxt);
void __debug_cond_save_host_state(struct kvm_vcpu *vcpu);
void __debug_cond_restore_host_state(struct kvm_vcpu *vcpu);

void __fpsimd_save_state(struct user_fpsimd_state *fp_regs);
void __fpsimd_restore_state(struct user_fpsimd_state *fp_regs);
bool __fpsimd_enabled(void);

u64 __guest_enter(struct kvm_vcpu *vcpu, struct kvm_cpu_context *host_ctxt);
void __noreturn __hyp_do_panic(unsigned long, ...);

#endif /* __ARM64_KVM_HYP_H__ */

