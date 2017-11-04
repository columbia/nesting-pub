#ifndef __ARM64_KVM_NESTED_PV_H__
#define __ARM64_KVM_NESTED_PV_H__

#include <asm/kvm_nested_pv_encoding.h>

int kvm_handle_eret(struct kvm_vcpu *vcpu, struct kvm_run *run);

int handle_pv(struct kvm_vcpu *vcpu);
bool psci_pv(struct kvm_vcpu *vcpu);

#endif
