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

#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/kvm_emulate.h>

/* We forward all hvc instruction to the guest hypervisor. */
int handle_hvc_nested(struct kvm_vcpu *vcpu)
{
	return kvm_inject_nested_sync(vcpu, kvm_vcpu_get_hsr(vcpu));
}
