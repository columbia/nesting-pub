#ifndef __ARM64_KVM_NESTED_H__
#define __ARM64_KVM_NESTED_H__

int handle_hvc_nested(struct kvm_vcpu *vcpu);
int handle_wfx_nested(struct kvm_vcpu *vcpu, bool is_wfe);
#endif
