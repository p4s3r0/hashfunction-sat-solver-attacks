#!/bin/bash
# Cluster script for Spongent brute-force attack

# create folders
mkdir r7h32
mkdir r8h32
mkdir r9h32

# attacks
# hash: 0
srun -w xeon192g0 -J Br7h32i0 ./attack_exe 7 32 0 > r7h32/BF_r7_0.txt &
srun -w xeon192g0 -J Br8h32i0 ./attack_exe 8 32 0 > r8h32/BF_r8_0.txt &
srun -w xeon192g0 -J Br9h32i0 ./attack_exe 9 32 0 > r9h32/BF_r9_0.txt &

# hash: 1
srun -w xeon192g0 -J Br7h32i1 ./attack_exe 7 32 1 > r7h32/BF_r7_1.txt &
srun -w xeon192g0 -J Br8h32i1 ./attack_exe 8 32 1 > r8h32/BF_r8_1.txt &
srun -w xeon192g0 -J Br9h32i1 ./attack_exe 9 32 1 > r9h32/BF_r9_1.txt &

# hash: 2
srun -w xeon192g0 -J Br7h32i2 ./attack_exe 7 32 2 > r7h32/BF_r7_2.txt &
srun -w xeon192g0 -J Br8h32i2 ./attack_exe 8 32 2 > r8h32/BF_r8_2.txt &
srun -w xeon192g0 -J Br9h32i2 ./attack_exe 9 32 2 > r9h32/BF_r9_2.txt &

# hash: 3
srun -w xeon192g0 -J Br7h32i3 ./attack_exe 7 32 3 > r7h32/BF_r7_3.txt &
srun -w xeon192g0 -J Br8h32i3 ./attack_exe 8 32 3 > r8h32/BF_r8_3.txt &
srun -w xeon192g0 -J Br9h32i3 ./attack_exe 9 32 3 > r9h32/BF_r9_3.txt &

# hash: 4
srun -w xeon192g0 -J Br7h32i4 ./attack_exe 7 32 4 > r7h32/BF_r7_4.txt &
srun -w xeon192g0 -J Br8h32i4 ./attack_exe 8 32 4 > r8h32/BF_r8_4.txt &
srun -w xeon192g0 -J Br9h32i4 ./attack_exe 9 32 4 > r9h32/BF_r9_4.txt &

# hash: 5
srun -w xeon192g0 -J Br7h32i5 ./attack_exe 7 32 5 > r7h32/BF_r7_5.txt &
srun -w xeon192g0 -J Br8h32i5 ./attack_exe 8 32 5 > r8h32/BF_r8_5.txt &
srun -w xeon192g0 -J Br9h32i5 ./attack_exe 9 32 5 > r9h32/BF_r9_5.txt &

# hash: 6
srun -w xeon192g0 -J Br7h32i6 ./attack_exe 7 32 6 > r7h32/BF_r7_6.txt &
srun -w xeon192g0 -J Br8h32i6 ./attack_exe 8 32 6 > r8h32/BF_r8_6.txt &
srun -w xeon192g0 -J Br9h32i6 ./attack_exe 9 32 6 > r9h32/BF_r9_6.txt &

# hash: 7
srun -w xeon192g0 -J Br7h32i7 ./attack_exe 7 32 7 > r7h32/BF_r7_7.txt &
srun -w xeon192g0 -J Br8h32i7 ./attack_exe 8 32 7 > r8h32/BF_r8_7.txt &
srun -w xeon192g0 -J Br9h32i7 ./attack_exe 9 32 7 > r9h32/BF_r9_7.txt &

# hash: 8
srun -w xeon192g0 -J Br7h32i8 ./attack_exe 7 32 8 > r7h32/BF_r7_8.txt &
srun -w xeon192g0 -J Br8h32i8 ./attack_exe 8 32 8 > r8h32/BF_r8_8.txt &
srun -w xeon192g0 -J Br9h32i8 ./attack_exe 9 32 8 > r9h32/BF_r9_8.txt &

# hash: 9
srun -w xeon192g0 -J Br7h32i9 ./attack_exe 7 32 9 > r7h32/BF_r7_9.txt &
srun -w xeon192g0 -J Br8h32i9 ./attack_exe 8 32 9 > r8h32/BF_r8_9.txt &
srun -w xeon192g0 -J Br9h32i9 ./attack_exe 9 32 9 > r9h32/BF_r9_9.txt &
