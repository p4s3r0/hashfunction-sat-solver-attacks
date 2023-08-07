hashTestValues = range(10)
rounds = [7, 8, 9]
hashBits = [32]
hashName = "Spongent"

output = "#!/bin/bash\n"
output += f"# Cluster script for {hashName} brute-force attack\n\n"

# create directories
output += "# create folders\n"
for h_rounds in rounds:
    output += f"mkdir r{h_rounds}h32\n"

output += "\n# attacks"
for h_index in hashTestValues:
    output += f"\n# hash: {h_index}\n"
    for h_bits in hashBits:
        for h_round in rounds:
            output += f"srun -w xeon192g0 -J Br{h_round}h{h_bits}i{h_index} ./attack_exe {h_round} {h_bits} {h_index} > r{h_round}h32/BF_r{h_round}_{h_index}.txt &\n"


f = open("attack.sh", "w")
f.write(output)
f.close()
print("attacks.sh file created!")



