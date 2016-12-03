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

int vgic_register_gich_iodev(struct kvm *kvm, struct vgic_dist *dist)
{
	struct vgic_io_device *io_device = &kvm->arch.vgic.hyp_iodev;
	int ret = 0;
	unsigned int len;

	len = KVM_VGIC_V2_GICH_SIZE;

	io_device->regions = vgic_v2_gich_registers;
	io_device->nr_regions = ARRAY_SIZE(vgic_v2_gich_registers);
	kvm_iodevice_init(&io_device->dev, &kvm_io_gic_ops);

	io_device->base_addr = KVM_VGIC_V2_GICH_BASE;
	io_device->iodev_type = IODEV_GICH;
	io_device->redist_vcpu = NULL;

	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, KVM_VGIC_V2_GICH_BASE,
			len, &io_device->dev);
	mutex_unlock(&kvm->slots_lock);

	return ret;
}

/*
 * For LRs which have HW bit set such as timer interrupts, we modify them to
 * have the host hardware interrupt number instead of the virtual one programmed
 * by the guest hypervisor.
 */
static void vgic_v2_create_shadow_lr(struct kvm_vcpu *vcpu)
{
	int i;
	struct vgic_v2_cpu_if *cpu_if = vcpu_nested_if(vcpu);
	struct vgic_v2_cpu_if *s_cpu_if = vcpu_shadow_if(vcpu);
	struct vgic_irq *irq;

	int nr_lr = kvm_vgic_global_state.nr_lr;

	for (i = 0; i < nr_lr; i++) {
		u32 lr = cpu_if->vgic_lr[i];
		int l1_irq;

		if (!(lr & GICH_LR_HW))
			goto next;

		/* We have the HW bit set */
		l1_irq = (lr & GICH_LR_PHYSID_CPUID) >>
			GICH_LR_PHYSID_CPUID_SHIFT;
		irq = vgic_get_irq(vcpu->kvm, vcpu, l1_irq);

		if (!irq->hw) {
			/* There was no real mapping, so nuke the HW bit */
			lr &= ~GICH_LR_HW;
			vgic_put_irq(vcpu->kvm, irq);
			goto next;
		}

		/* Translate the virtual mapping to the real one */
		lr &= ~GICH_LR_EOI;
		lr &= ~GICH_LR_PHYSID_CPUID;
		lr |= irq->hwintid << GICH_LR_PHYSID_CPUID_SHIFT;
		vgic_put_irq(vcpu->kvm, irq);

next:
		s_cpu_if->vgic_lr[i] = lr;
	}
}

/*
 * Change the shadow HWIRQ field back to the virtual value before copying over
 * the entire shadow struct to the nested state.
 */
static void vgic_v2_restore_shadow_lr(struct kvm_vcpu *vcpu)
{
	struct vgic_v2_cpu_if *cpu_if = vcpu_nested_if(vcpu);
	struct vgic_v2_cpu_if *s_cpu_if = vcpu_shadow_if(vcpu);
	int nr_lr = kvm_vgic_global_state.nr_lr;
	int lr;

	for (lr = 0; lr < nr_lr; lr++) {
		s_cpu_if->vgic_lr[lr] &= ~GICH_LR_PHYSID_CPUID;
		s_cpu_if->vgic_lr[lr] |= cpu_if->vgic_lr[lr] &
			GICH_LR_PHYSID_CPUID;
	}
}

void vgic_v2_setup_shadow_state(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_v2_cpu_if *cpu_if;

	if (vcpu_el2_imo_is_set(vcpu) && !vcpu_mode_el2(vcpu)) {
		vgic_cpu->shadow_vgic_v2 = vgic_cpu->nested_vgic_v2;
		vgic_v2_create_shadow_lr(vcpu);
		cpu_if = vcpu_shadow_if(vcpu);
	} else {
		cpu_if = &vgic_cpu->vgic_v2;
	}

	vgic_cpu->hw_v2_cpu_if = cpu_if;
}

void vgic_v2_restore_shadow_state(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;

	/* Not using shadow state: Nothing to do... */
	if (vgic_cpu->hw_v2_cpu_if == &vgic_cpu->vgic_v2)
		return;

	/*
	 * Translate the shadow state HW fields back to the virtual ones
	 * before copying the shadow struct back to the nested one.
	 */
	vgic_v2_restore_shadow_lr(vcpu);
	vgic_cpu->nested_vgic_v2 = vgic_cpu->shadow_vgic_v2;
}

void vgic_handle_nested_maint_irq(struct kvm_vcpu *vcpu)
{
	struct vgic_v2_cpu_if *cpu_if = vcpu_nested_if(vcpu);

	/*
	 * If we exit a nested VM with a pending maintenance interrupt from the
	 * GIC, then we need to forward this to the guest hypervisor so that it
	 * can re-sync the appropriate LRs and sample level triggered interrupts
	 * again.
	 */
	if (vcpu_el2_imo_is_set(vcpu) && !vcpu_mode_el2(vcpu) &&
	    (cpu_if->vgic_hcr & GICH_HCR_EN) &&
	    vgic_mmio_read_v2_misr(vcpu, 0, 0))
		kvm_inject_nested_irq(vcpu);
}

void vgic_init_nested(struct kvm_vcpu *vcpu)
{
	vgic_v2_setup_shadow_state(vcpu);
}
