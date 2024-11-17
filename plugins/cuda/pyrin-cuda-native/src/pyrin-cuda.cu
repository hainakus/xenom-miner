// CUDA Pyrin Hash Optimized Kernel

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdint.h>

// Assuming keccak and blake3 implementations have been included properly
#include "keccak-tiny.h"
#include "blake3_compact.h"

__device__ uint64_t xoshiro256starstar(uint64_t* state) {
    uint64_t result = rotl(state[1] * 5, 7) * 9;
    uint64_t t = state[1] << 17;

    state[2] ^= state[0];
    state[3] ^= state[1];
    state[1] ^= state[2];
    state[0] ^= state[3];

    state[2] ^= t;
    state[3] = rotl(state[3], 45);

    return result;
}

__global__ void pyrin_cuda_kernel(uint8_t* input_data, uint8_t* output_data, size_t data_size) {
    extern __shared__ uint8_t shared_data[];

    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    if (idx >= data_size) return;

    // Load input data to shared memory
    shared_data[threadIdx.x] = input_data[idx];
    __syncthreads();

    // Perform keccak hash on the input
    uint8_t keccak_output[32];
    keccak(shared_data, blockDim.x, keccak_output, sizeof(keccak_output));

    // Perform blake3 hash on keccak output
    uint8_t blake3_output[32];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, keccak_output, sizeof(keccak_output));
    blake3_hasher_finalize(&hasher, blake3_output, sizeof(blake3_output));

    // Write the final output back to global memory
    output_data[idx] = blake3_output[0];
}

extern "C" void launch_pyrin_cuda_kernel(uint8_t* input_data, uint8_t* output_data, size_t data_size) {
    int block_size = 256;
    int grid_size = (data_size + block_size - 1) / block_size;
    int shared_memory_size = block_size * sizeof(uint8_t);

    pyrin_cuda_kernel<<<grid_size, block_size, shared_memory_size>>>(input_data, output_data, data_size);
    cudaDeviceSynchronize();
}
