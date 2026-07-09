// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod driver;
pub mod grpc;
pub mod types;

pub use driver::{KubevirtComputeDriver, KubevirtDriverError};
pub use grpc::ComputeDriverService;
