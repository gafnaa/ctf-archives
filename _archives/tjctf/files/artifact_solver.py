import math
import sys

# Constants from artifact.py
circ = 24901
diam = (circ / (2 * math.pi)) ** 2
rad = math.sqrt(diam)

# Points from points.txt
points_from_file = [3138.646783707992, 3457.2582930122776, 3598.7367550156378, 3040.4756803395558, 3484.526946191407, 2519.956584175499, 2934.2112052732805, 3963.025229186761, 3158.7994047792304, 3374.243599019833, 3491.2798644768354, 2796.893598944792, 2651.741878163264, 2771.1638661495103, 3225.777673643851, 3356.480386346154, 3929.6978538988164, 2554.4811235983225, 3263.5429941734396, 2467.0141963657006, 2761.443281011399, 3890.3037897658146, 2081.9024164501952, 3099.2228544211634, 2411.1562780802647, 3832.918095693915, 3808.724614842792, 2327.4828501137918, 2855.5817254958906, 2016.5822640455892, 2436.5374314809196, 1796.8608560544374, 2395.1802525565245, 3624.1004445195163, 885.0536563698248]
L = len(points_from_file)

# Helper functions from artifact.py
def find_ang(point):
    # Handle potential floating point errors that might make point/rad slightly > 1 or < -1
    arg = point / rad
    if arg > 1.0:
        arg = 1.0
    elif arg < -1.0:
        arg = -1.0
    return math.degrees(math.asin(arg))

def is_printable_ascii(byte_val):
    return 32 <= byte_val <= 126

# Brute-force 'time' (which is an integer)
# Assuming 'time' is in a reasonable range, e.g., 1 to 15000
for time_candidate in range(1, 15001):
    A = time_candidate * 360 / circ
    
    possible_flag = []
    is_valid_time = True

    for j in range(L):
        P_j_final = points_from_file[j]
        
        # Calculate the principal angle from the final point
        theta_j_final = find_ang(P_j_final)
        
        # Iterate through possible k values for 360*k
        # A reasonable range for k, considering L*A can be large
        # Max (L-j)*A is L*A. If A is ~72, L*A is ~2500. 2500/360 is ~7.
        # So k_offset from -10 to 10 should be enough.
        found_alpha_j_for_j = False
        for k_offset in range(-25, 26): # Increased range for k_offset
            # Try Case 1: phi_j_final = theta_j_final + 360 * k_offset
            phi_j_final_case1 = theta_j_final + 360 * k_offset
            alpha_j_candidate_case1 = phi_j_final_case1 - (L - j) * A
            
            # Normalize alpha_j_candidate_case1 to [0, 360)
            alpha_j_candidate_case1_norm = alpha_j_candidate_case1 % 360
            
            # Since base values are positive, find_ang(base[j]) is in [0, 90]
            if 0 <= alpha_j_candidate_case1_norm <= 90:
                base_j_candidate = rad * math.sin(math.radians(alpha_j_candidate_case1_norm))
                
                # Reconstruct flag byte
                # (flag_byte * 31)^2 = diam - base_j_candidate^2
                # flag_byte = sqrt(diam - base_j_candidate^2) / 31
                
                val_under_sqrt = diam - base_j_candidate**2
                if val_under_sqrt < 0: # Floating point errors might make it slightly negative
                    val_under_sqrt = 0
                
                flag_byte_val = math.sqrt(val_under_sqrt) / 31.0
                
                # Check if it's close to an integer and a printable ASCII character
                if abs(flag_byte_val - round(flag_byte_val)) < 1e-6: # Removed is_printable_ascii for initial debug
                    if is_printable_ascii(round(flag_byte_val)): # Only append if printable
                        possible_flag.append(chr(round(flag_byte_val)))
                        found_alpha_j_for_j = True
                        break # Found a valid alpha_j for this j, move to next j
                    else: # If not printable, it's not a valid path for this time_candidate
                        continue # Try next k_offset or case
            
            # Try Case 2: phi_j_final = (180 - theta_j_final) + 360 * k_offset
            # This handles the ambiguity of asin(x) = asin(180-x)
            phi_j_final_case2 = (180 - theta_j_final) + 360 * k_offset
            alpha_j_candidate_case2 = phi_j_final_case2 - (L - j) * A
            
            # Normalize alpha_j_candidate_case2 to [0, 360)
            alpha_j_candidate_case2_norm = alpha_j_candidate_case2 % 360
            
            if 0 <= alpha_j_candidate_case2_norm <= 90:
                base_j_candidate = rad * math.sin(math.radians(alpha_j_candidate_case2_norm))
                
                val_under_sqrt = diam - base_j_candidate**2
                if val_under_sqrt < 0:
                    val_under_sqrt = 0
                
                flag_byte_val = math.sqrt(val_under_sqrt) / 31.0
                
                if abs(flag_byte_val - round(flag_byte_val)) < 1e-6: # Removed is_printable_ascii for initial debug
                    if is_printable_ascii(round(flag_byte_val)): # Only append if printable
                        possible_flag.append(chr(round(flag_byte_val)))
                        found_alpha_j_for_j = True
                        break # Found a valid alpha_j for this j, move to next j
                    else: # If not printable, it's not a valid path for this time_candidate
                        continue # Try next k_offset or case
        
        if not found_alpha_j_for_j:
            is_valid_time = False
            break # This time_candidate doesn't work for this j, try next time_candidate
            
    if is_valid_time and len(possible_flag) == L:
        print(f"Found valid time: {time_candidate}")
        print(f"Recovered Flag: {''.join(possible_flag)}")
        sys.exit(0) # Exit after finding the first valid flag

print("No valid time found in the tested range.")
