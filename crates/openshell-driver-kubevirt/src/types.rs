// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! KubeVirt CRD type definitions for use with kube-rs `DynamicObject` API.

use kube::api::ApiResource;
use kube::core::gvk::GroupVersionKind;

/// KubeVirt API group.
pub const KUBEVIRT_GROUP: &str = "kubevirt.io";

/// KubeVirt API version.
pub const KUBEVIRT_VERSION: &str = "v1";

/// KubeVirt `VirtualMachine` kind.
pub const VM_KIND: &str = "VirtualMachine";

/// KubeVirt `VirtualMachineInstance` kind.
pub const VMI_KIND: &str = "VirtualMachineInstance";

/// Build an [`ApiResource`] for KubeVirt `VirtualMachine` objects.
#[must_use]
pub fn vm_api_resource() -> ApiResource {
    let gvk = GroupVersionKind::gvk(KUBEVIRT_GROUP, KUBEVIRT_VERSION, VM_KIND);
    ApiResource::from_gvk(&gvk)
}

/// Build an [`ApiResource`] for KubeVirt `VirtualMachineInstance` objects.
#[must_use]
pub fn vmi_api_resource() -> ApiResource {
    let gvk = GroupVersionKind::gvk(KUBEVIRT_GROUP, KUBEVIRT_VERSION, VMI_KIND);
    ApiResource::from_gvk(&gvk)
}
