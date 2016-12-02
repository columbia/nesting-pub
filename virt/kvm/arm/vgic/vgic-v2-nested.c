#include <linux/cpu.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/uaccess.h>

#include <linux/irqchip/arm-gic.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <kvm/arm_vgic.h>

#include "vgic.h"
#include "vgic-mmio.h"

static inline struct vgic_v2_cpu_if *vcpu_nested_if(struct kvm_vcpu *vcpu)
{
	return &vcpu->arch.vgic_cpu.nested_vgic_v2;
}

static inline struct vgic_v2_cpu_if *vcpu_shadow_if(struct kvm_vcpu *vcpu)
{
	return &vcpu->arch.vgic_cpu.shadow_vgic_v2;
}

static unsigned long vgic_mmio_read_v2_vtr(struct kvm_vcpu *vcpu,
					   gpa_t addr, unsigned int len)
{
	u32 reg;

	reg = kvm_vgic_global_state.nr_lr - 1;
	reg |= 0b100 << 26;
	reg |= 0b100 << 29;

	return reg;
}

static inline bool lr_triggers_eoi(u32 lr)
{
	return !(lr & (GICH_LR_STATE | GICH_LR_HW)) && (lr & GICH_LR_EOI);
}

static unsigned long get_eisr(struct kvm_vcpu *vcpu, bool upper_reg)
{
	struct vgic_v2_cpu_if *cpu_if = vcpu_nested_if(vcpu);
	int max_lr = upper_reg ? 64 : 32;
	int min_lr = upper_reg ? 32 : 0;
	int nr_lr = min(kvm_vgic_global_state.nr_lr, max_lr);
	int i;
	u32 reg = 0;

	for (i = min_lr; i < nr_lr; i++) {
		if (lr_triggers_eoi(cpu_if->vgic_lr[i]))
			reg |= BIT(i - min_lr);
	}

	return reg;
}

static unsigned long vgic_mmio_read_v2_eisr0(struct kvm_vcpu *vcpu,
					     gpa_t addr, unsigned int len)
{
	return get_eisr(vcpu, false);
}

static unsigned long vgic_mmio_read_v2_eisr1(struct kvm_vcpu *vcpu,
					     gpa_t addr, unsigned int len)
{
	return get_eisr(vcpu, true);
}

static u32 get_elrsr(struct kvm_vcpu *vcpu, bool upper_reg)
{
	struct vgic_v2_cpu_if *cpu_if = vcpu_nested_if(vcpu);
	int max_lr = upper_reg ? 64 : 32;
	int min_lr = upper_reg ? 32 : 0;
	int nr_lr = min(kvm_vgic_global_state.nr_lr, max_lr);
	u32 reg = 0;
	int i;

	for (i = min_lr; i < nr_lr; i++) {
		if (!(cpu_if->vgic_lr[i] & GICH_LR_STATE))
			reg |= BIT(i - min_lr);
	}

	return reg;
}

static unsigned long vgic_mmio_read_v2_elrsr0(struct kvm_vcpu *vcpu,
					      gpa_t addr, unsigned int len)
{
	return get_elrsr(vcpu, false);
}

static unsigned long vgic_mmio_read_v2_elrsr1(struct kvm_vcpu *vcpu,
					      gpa_t addr, unsigned int len)
{
	return get_elrsr(vcpu, true);
}

static unsigned long vgic_mmio_read_v2_misr(struct kvm_vcpu *vcpu,
					    gpa_t addr, unsigned int len)
{
	struct vgic_v2_cpu_if *cpu_if = vcpu_nested_if(vcpu);
	int nr_lr = kvm_vgic_global_state.nr_lr;
	u32 reg = 0;

	if (vgic_mmio_read_v2_eisr0(vcpu, addr, len) ||
			vgic_mmio_read_v2_eisr1(vcpu, addr, len))
		reg |= GICH_MISR_EOI;

	if (cpu_if->vgic_hcr & GICH_HCR_UIE) {
		u32 elrsr0 = vgic_mmio_read_v2_elrsr0(vcpu, addr, len);
		u32 elrsr1 = vgic_mmio_read_v2_elrsr1(vcpu, addr, len);
		int used_lrs;

		used_lrs = nr_lr - (hweight32(elrsr0) + hweight32(elrsr1));
		if (used_lrs <= 1)
			reg |= GICH_MISR_U;
	}

	/* TODO: Support remaining bits in this register */
	return reg;
}

static unsigned long vgic_mmio_read_v2_gich(struct kvm_vcpu *vcpu,
					    gpa_t addr, unsigned int len)
{
	struct vgic_v2_cpu_if *cpu_if = vcpu_nested_if(vcpu);
	u32 value;

	switch (addr & 0xfff) {
	case GICH_HCR:
		value = cpu_if->vgic_hcr;
		break;
	case GICH_VMCR:
		value = cpu_if->vgic_vmcr;
		break;
	case GICH_APR:
		value = cpu_if->vgic_apr;
		break;
	case GICH_LR0 ... (GICH_LR0 + 4 * (VGIC_V2_MAX_LRS - 1)):
		value = cpu_if->vgic_lr[(addr & 0xff) >> 2];
		break;
	default:
		return 0;
	}

	return value;
}

static void vgic_mmio_write_v2_gich(struct kvm_vcpu *vcpu,
				    gpa_t addr, unsigned int len,
				    unsigned long val)
{
	struct vgic_v2_cpu_if *cpu_if = vcpu_nested_if(vcpu);

	switch (addr & 0xfff) {
	case GICH_HCR:
		cpu_if->vgic_hcr = val;
		break;
	case GICH_VMCR:
		cpu_if->vgic_vmcr = val;
		break;
	case GICH_APR:
		cpu_if->vgic_apr = val;
		break;
	case GICH_LR0 ... (GICH_LR0 + 4 * (VGIC_V2_MAX_LRS - 1)):
		cpu_if->vgic_lr[(addr & 0xff) >> 2] = val;
		break;
	}
}

static const struct vgic_register_region vgic_v2_gich_registers[] = {
	REGISTER_DESC_WITH_LENGTH(GICH_HCR,
		vgic_mmio_read_v2_gich, vgic_mmio_write_v2_gich, 4,
		VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICH_VTR,
		vgic_mmio_read_v2_vtr, vgic_mmio_write_wi, 4,
		VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICH_VMCR,
		vgic_mmio_read_v2_gich, vgic_mmio_write_v2_gich, 4,
		VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICH_MISR,
		vgic_mmio_read_v2_misr, vgic_mmio_write_wi, 4,
		VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICH_EISR0,
		vgic_mmio_read_v2_eisr0, vgic_mmio_write_wi, 4,
		VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICH_EISR1,
		vgic_mmio_read_v2_eisr1, vgic_mmio_write_wi, 4,
		VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICH_ELRSR0,
		vgic_mmio_read_v2_elrsr0, vgic_mmio_write_wi, 4,
		VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICH_ELRSR1,
		vgic_mmio_read_v2_elrsr1, vgic_mmio_write_wi, 4,
		VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICH_APR,
		vgic_mmio_read_v2_gich, vgic_mmio_write_v2_gich, 4,
		VGIC_ACCESS_32bit),
	REGISTER_DESC_WITH_LENGTH(GICH_LR0,
		vgic_mmio_read_v2_gich, vgic_mmio_write_v2_gich,
		4 * VGIC_V2_MAX_LRS, VGIC_ACCESS_32bit),
};
