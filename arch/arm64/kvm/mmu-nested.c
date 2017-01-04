/*
 * Copyright (C) 2016 - Columbia University
 * Author: Jintack Lim <jintack@cs.columbia.edu>
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

#include <linux/kvm_host.h>

#include <asm/kvm_arm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_nested.h>

struct kvm_nested_s2_mmu *get_nested_mmu(struct kvm_vcpu *vcpu, u64 vttbr)
{
	struct kvm_nested_s2_mmu *mmu;
	u64 target_vmid = get_vmid(vttbr);
	struct list_head *nested_mmu_list = &vcpu->kvm->arch.nested_mmu_list;

	list_for_each_entry_rcu(mmu, nested_mmu_list, list) {
		u64 vmid = get_vmid(mmu->virtual_vttbr);

		if (target_vmid == vmid)
			return mmu;
	}
	return NULL;
}

struct kvm_s2_mmu *vcpu_get_active_s2_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_nested_s2_mmu *nested_mmu;

	/* If we are NOT entering the nested VM, return mmu in kvm_arch */
	if (vcpu_mode_el2(vcpu) || !vcpu_nested_stage2_enabled(vcpu))
		return &vcpu->kvm->arch.mmu;

	/* Otherwise, search for nested_mmu in the list */
	nested_mmu = get_nested_mmu(vcpu, vcpu_el2_reg(vcpu, VTTBR_EL2));

	/* When this function is called, nested_mmu should be in the list */
	BUG_ON(!nested_mmu);

	return &nested_mmu->mmu;
}
