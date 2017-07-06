/*
 * Copyright (C) 2017 - Columbia University and Linaro Ltd.
 * Author: Jintack Lim <jintack.lim@linaro.org>
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

#include <linux/kvm.h>
#include <linux/kvm_host.h>

static bool nested_param;

int __init kvmarm_nested_cfg(char *buf)
{
	return strtobool(buf, &nested_param);
}

int init_nested_virt(void)
{
	if (nested_param && cpus_have_const_cap(ARM64_HAS_NESTED_VIRT))
		kvm_info("Nested virtualization is supported\n");

	return 0;
}

bool nested_virt_in_use(struct kvm_vcpu *vcpu)
{
	if (nested_param && cpus_have_const_cap(ARM64_HAS_NESTED_VIRT)
	    && test_bit(KVM_ARM_VCPU_NESTED_VIRT, vcpu->arch.features))
		return true;

	return false;
}
