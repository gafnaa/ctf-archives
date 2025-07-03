import numpy as np
import galois # Needs pip install galois

def solve_mceliece_hamming():
    # Step 1: Load Key and Parameters
    try:
        G_pub = np.load('alice_pub.npy')
    except FileNotFoundError:
        print("Error: 'alice_pub.npy' not found. Please ensure the file is in the same directory.")
        return "Error: alice_pub.npy not found."

    R_val = 6
    N_val = 2**R_val - 1  # 63
    K_val = N_val - R_val  # 57

    if G_pub.shape != (K_val, N_val):
        return f"Error: G_pub shape is {G_pub.shape}, expected ({K_val}, {N_val})."

    GF2 = galois.GF(2)
    G_pub_gf2_instance = GF2(G_pub.astype(int)) 

    if not isinstance(G_pub_gf2_instance, galois.FieldArray):
        return (f"Error: G_pub_gf2_instance is of type {type(G_pub_gf2_instance)}, "
                f"expected galois.FieldArray. This might be an issue with galois version or G_pub data.")

    # Debug: Check if G_pub_gf2_instance is all zeros
    if np.all(G_pub_gf2_instance.view(np.ndarray) == 0):
        return ("Error: G_pub_gf2_instance appears to be an all-zero matrix after GF2 conversion. "
                "Check content of 'alice_pub.npy' or your 'galois' library version/behavior.")
    # print(f"Debug: First 5 elements of G_pub_gf2_instance.flatten(): {G_pub_gf2_instance.flatten()[:5].view(np.ndarray)}")


    # Step 2: Compute Parity Check Matrix (H_pub_dual) and determine G_pub rank + pivot columns
    pivot_cols_indices = []
    rank_G_pub = 0

    try:
        # Attempt to use .rref() first, as it's the standard way
        _G_pub_rref_form, pivot_cols_indices_rref = G_pub_gf2_instance.rref()
        rank_G_pub_rref = len(pivot_cols_indices_rref)
        
        if rank_G_pub_rref != K_val:
            return (f"Error (via rref): G_pub_gf2_instance has rank {rank_G_pub_rref}, expected {K_val}. "
                    f"Not a valid generator matrix.")
        pivot_cols_indices = pivot_cols_indices_rref
        rank_G_pub = rank_G_pub_rref
        # print("Successfully used .rref() for pivot selection.")

    except AttributeError as e_rref:
        print(f"Warning: G_pub_gf2_instance.rref() failed ('{e_rref}'). Attempting manual pivot selection using .null_space().")
        print("This might be slow and is less reliable. Strongly consider upgrading the 'galois' library: pip install --upgrade galois")

        # Manual pivot selection fallback
        current_selected_pivots_matrix_gf2 = GF2(np.empty((K_val, 0), dtype=int)) # Stores the actual selected K_val x num_pivots matrix
        # pivot_cols_indices is already initialized to []

        for col_idx in range(N_val):
            if len(pivot_cols_indices) == K_val: # Found enough pivots
                break 

            col_to_test_gf2 = G_pub_gf2_instance[:, col_idx:col_idx+1] # K_val x 1 FieldArray

            is_col_linearly_independent = False
            if current_selected_pivots_matrix_gf2.shape[1] == 0: # If no pivots selected yet
                # A column is a pivot if it's non-zero
                if not np.all(col_to_test_gf2.view(np.ndarray) == 0):
                    is_col_linearly_independent = True
            else:
                # Form prospective matrix with current pivots + new test column
                prospective_matrix_gf2 = GF2(np.hstack((current_selected_pivots_matrix_gf2.view(np.ndarray), col_to_test_gf2.view(np.ndarray))))
                
                try:
                    # Rank = num_cols - dim_null_space
                    dim_null_prospective = prospective_matrix_gf2.null_space().shape[1]
                    rank_prospective = prospective_matrix_gf2.shape[1] - dim_null_prospective
                except Exception as e_ns_manual:
                    return (f"Error during manual pivot selection's null_space call: {e_ns_manual}. "
                            f"This often indicates issues with older 'galois' versions. Please upgrade.")
                
                # If rank increased, the column is linearly independent
                # Current rank is len(pivot_cols_indices)
                if rank_prospective > len(pivot_cols_indices):
                    is_col_linearly_independent = True
            
            if is_col_linearly_independent:
                pivot_cols_indices.append(col_idx)
                # Update the matrix of selected pivot columns
                if current_selected_pivots_matrix_gf2.shape[1] == 0:
                    current_selected_pivots_matrix_gf2 = col_to_test_gf2.copy()
                else:
                    # This was the prospective matrix that showed increased rank
                    current_selected_pivots_matrix_gf2 = GF2(np.hstack((current_selected_pivots_matrix_gf2.view(np.ndarray), col_to_test_gf2.view(np.ndarray))))


        rank_G_pub = len(pivot_cols_indices) # Final rank is the number of pivots found
        if rank_G_pub != K_val:
            return (f"Error: Manually found {rank_G_pub} pivot columns, expected {K_val}. "
                    f"G_pub_gf2_instance may not have full row rank or the fallback pivot selection failed. "
                    f"Strongly consider upgrading 'galois' library.")
    
    except Exception as e_general:
        return f"Error computing RREF or selecting pivots for G_pub_gf2_instance: {e_general}"


    # Validate G_pub rank (this check is somewhat redundant if logic above is sound, but good for safety)
    if rank_G_pub != K_val: 
        return (f"Error: G_pub_gf2_instance determined to have rank {rank_G_pub}, but expected rank {K_val}. "
                f"Cannot proceed. This indicates an issue with G_pub or the rank determination method.")

    try:
        H_pub_dual_transpose_gf2 = G_pub_gf2_instance.null_space()
    except Exception as e_ns_main:
        return f"Error computing null space for G_pub_gf2_instance: {e_ns_main}. Consider upgrading 'galois'."
        
    if H_pub_dual_transpose_gf2.shape != (N_val, R_val):
        return (f"Error: H_pub_dual_transpose_gf2 shape is {H_pub_dual_transpose_gf2.shape}, expected ({N_val}, {R_val}). "
                f"Inconsistent with G_pub_gf2_instance rank {rank_G_pub}.")

    H_pub_dual_gf2 = H_pub_dual_transpose_gf2.T 

    G_pub_pivots_gf2 = G_pub_gf2_instance[:, pivot_cols_indices] 
    
    try:
        # Check if G_pub_pivots_gf2 (KxK) is invertible. Rank must be K.
        # Try .rref() for rank check first
        try:
            _G_pivots_rref, G_pivots_pivots_indices = G_pub_pivots_gf2.rref()
            rank_G_pub_pivots = len(G_pivots_pivots_indices)
        except AttributeError:
            # .rref() not available, use null_space based rank for KxK matrix
            # print("Warning: .rref() not available for G_pub_pivots_gf2 rank check. Using .null_space().")
            dim_null_G_pivots = G_pub_pivots_gf2.null_space().shape[1]
            rank_G_pub_pivots = G_pub_pivots_gf2.shape[1] - dim_null_G_pivots # shape[1] is K_val

        if rank_G_pub_pivots != K_val:
             return (f"Error: The KxK submatrix G_pub_pivots_gf2 is not invertible "
                     f"(its rank is {rank_G_pub_pivots}, expected {K_val}).")
        G_pub_pivots_inv_gf2 = G_pub_pivots_gf2.inv()
    except np.linalg.LinAlgError: 
        return f"Error: G_pub_pivots_gf2 is singular (LinAlgError during inversion)."
    except Exception as e_inv:
        return f"Error inverting G_pub_pivots_gf2 or checking its rank: {e_inv}"


    # Step 3: Prepare Ciphertext
    c_hex = "33b4ba0c3c11ad7e298b79de7261c5dd8edd7b537007b383cad9f38dbcf584e66a07c9808edad6e289516f3c6cc4186686f3a7fc8e1603e80aba601efe82e8cf2f6a28aa405cf7419b9dd1f01925c5"
    
    if len(c_hex) % 2 != 0: 
        c_hex = "0" + c_hex 
        
    expected_bit_len = len(c_hex) * 4
    try:
        c_binary_str = bin(int(c_hex, 16))[2:].zfill(expected_bit_len)
    except ValueError:
        return "Error: Invalid hexadecimal string in c_hex."
        
    c_bits_total = [int(b) for b in c_binary_str]

    if len(c_bits_total) != expected_bit_len: # Should be rare with zfill
        c_bits_total = [0]*(expected_bit_len - len(c_bits_total)) + c_bits_total

    if len(c_bits_total) % N_val != 0:
        return (f"Error: Total ciphertext bit length ({len(c_bits_total)}) "
                f"is not a multiple of N_val ({N_val}). Ciphertext length: {len(c_hex)} hex chars.")

    num_blocks = len(c_bits_total) // N_val
    c_blocks_list_np = []
    for i in range(num_blocks):
        c_block_bits = c_bits_total[i*N_val : (i+1)*N_val]
        c_blocks_list_np.append(np.array(c_block_bits, dtype=int))

    # Step 4 & 5: Decode Each Block and Recover Message Block
    all_recovered_msg_bits = []

    for block_idx, c_block_np in enumerate(c_blocks_list_np):
        c_block_gf2 = GF2(c_block_np) 

        syndrome_gf2 = c_block_gf2 @ H_pub_dual_transpose_gf2

        error_vector_gf2 = GF2(np.zeros(N_val, dtype=int)) 
        if np.any(syndrome_gf2.view(np.ndarray) != 0): 
            syndrome_as_col_view = syndrome_gf2.T.view(np.ndarray)
            
            found_error_pos = -1
            for j_err_pos in range(N_val):
                H_col_view = H_pub_dual_gf2[:, j_err_pos].view(np.ndarray) 
                if np.array_equal(H_col_view, syndrome_as_col_view):
                    error_vector_gf2[j_err_pos] = 1
                    found_error_pos = j_err_pos
                    break
            
            if found_error_pos == -1:
                return (f"Critical Error in block {block_idx}: Non-zero syndrome {syndrome_gf2} "
                        f"not found in H_pub_dual_gf2 columns.")

        codeword_gf2 = c_block_gf2 + error_vector_gf2 
        codeword_pivots_gf2 = codeword_gf2[pivot_cols_indices]
        msg_block_gf2 = codeword_pivots_gf2 @ G_pub_pivots_inv_gf2
        all_recovered_msg_bits.extend(msg_block_gf2.view(np.ndarray).flatten().tolist())

    # Step 6: Unpad and Convert to String
    idx_last_bit = len(all_recovered_msg_bits) - 1
    while idx_last_bit >= 0 and all_recovered_msg_bits[idx_last_bit] == 0:
        idx_last_bit -= 1
    
    if idx_last_bit < 0 or all_recovered_msg_bits[idx_last_bit] != 1:
        return ("Error: Padding '1' not found after stripping trailing zeros.")

    original_m_bits = all_recovered_msg_bits[:idx_last_bit]

    if len(original_m_bits) % 8 != 0:
        return (f"Error: Length of original message bits after unpadding ({len(original_m_bits)}) "
                f"is not a multiple of 8.")

    flag_chars = []
    for i in range(0, len(original_m_bits), 8):
        byte_chunk_bits = original_m_bits[i:i+8]
        byte_str = "".join(map(str, byte_chunk_bits))
        try:
            char_val = int(byte_str, 2)
            if 32 <= char_val <= 126 or char_val in [9, 10, 13]: # Printable ASCII + common whitespace
                 flag_chars.append(chr(char_val))
            else:
                 flag_chars.append(f'[NP:{char_val}]') # Non-printable
        except ValueError:
             return f"Error converting byte string {byte_str} to character value."
            
    decrypted_flag = "".join(flag_chars)
    return "Decrypted flag: " + decrypted_flag

if __name__ == '__main__':
    try:
        with open('alice_pub.npy', 'rb') as f:
            pass # File exists
    except FileNotFoundError:
        print("Creating a dummy 'alice_pub.npy' for script execution test...")
        print("NOTE: THIS WILL NOT PRODUCE THE CORRECT FLAG for the challenge.")
        R_test = 6; N_test = 2**R_test - 1; K_test = N_test - R_test
        def p2(x): return x != 0 and (x & (x - 1) == 0)
        def check(r): # Generates standard H for Hamming code (parity bits at powers of 2)
            n = 2**r - 1; H_matrix = np.zeros((r, n), dtype=int)
            for j_col_idx in range(n): # Iterate 0 to n-1 for columns of H
                binary_representation = [( (j_col_idx+1) >> i_row_idx) & 1 for i_row_idx in range(r)]
                H_matrix[:, j_col_idx] = binary_representation
            return H_matrix

        def gen_G_h_systematic_from_H(H_std, r_param, n_param, k_param):
            # H_std should be in form [P^T | I_r] (after permutation) or [A | I_r]
            # This function assumes H_std is the standard Hamming check matrix where columns are binary numbers 1 to N
            # We need to find P such that G_sys = [I_k | P]
            # The problem's original `gen` function built G_h by identifying data and parity positions.
            
            # Identify parity bit positions (powers of 2, 1-indexed)
            parity_pos_1_indexed = [2**i for i in range(r_param)] # e.g., [1, 2, 4, 8, 16, 32]
            parity_pos_0_indexed = [p-1 for p in parity_pos_1_indexed]

            # Identify data bit positions (non-powers of 2, 1-indexed)
            data_pos_1_indexed = [j for j in range(1, n_param + 1) if not p2(j)]
            data_pos_0_indexed = [d-1 for d in data_pos_1_indexed]

            if len(data_pos_0_indexed) != k_param:
                raise ValueError(f"k_param mismatch in dummy G_h generation. Expected {k_param}, got {len(data_pos_0_indexed)} data positions.")

            # Extract P from H_std. H_std = [P_matrix_T_cols_from_data_pos | Identity_like_cols_from_parity_pos ] (potentially permuted)
            # P is k x r. P_ij is the coefficient of the j-th parity bit in the i-th data bit's encoding.
            # Or, G = [I_k | P]. H = [-P^T | I_r] = [P^T | I_r] over GF(2).
            # So, the columns of H corresponding to data positions form P^T.
            P_T_matrix = H_std[:, data_pos_0_indexed] # r x k
            P_matrix = P_T_matrix.T # k x r

            G_h_systematic = np.zeros((k_param, n_param), dtype=int)
            # Identity part for data positions
            for i, d_idx in enumerate(data_pos_0_indexed):
                G_h_systematic[i, d_idx] = 1
            # P part for parity positions
            for i in range(k_param): # row in G (and P)
                for j in range(r_param): # col in P (corresponds to j-th parity bit)
                    G_h_systematic[i, parity_pos_0_indexed[j]] = P_matrix[i, j]
            return G_h_systematic


        def bm_scramble(k_param): # Scrambling matrix S
            S_matrix = np.eye(k_param, dtype=int)
            for _ in range(k_param * 3): 
                i, j = np.random.choice(k_param, 2, replace=False)
                op_type = np.random.rand()
                if op_type < 0.5: S_matrix[[i,j], :] = S_matrix[[j,i], :] 
                else: S_matrix[i, :] = (S_matrix[i, :] + S_matrix[j, :]) % 2
            
            GF2_bm_check = galois.GF(2)
            S_gf2_check = GF2_bm_check(S_matrix)
            rank_S = -1
            try:
                _s_rref, s_pivots = S_gf2_check.rref()
                rank_S = len(s_pivots)
            except AttributeError: 
                try:
                    rank_S = S_gf2_check.shape[1] - S_gf2_check.null_space().shape[1]
                except Exception: # If null_space also fails or gives weird result
                    pass # rank_S remains -1 or previous error state
            except Exception:
                 pass # rank_S remains -1

            if rank_S != k_param: 
                # print(f"Warning: Dummy S matrix was singular (rank {rank_S}), regenerating...")
                return bm_scramble(k_param) 
            return S_matrix

        H_standard_dummy = check(R_test) # Standard H for (N,K) Hamming
        G_h_dummy = gen_G_h_systematic_from_H(H_standard_dummy, R_test, N_test, K_test)
        
        # Verify G_h_dummy @ H_standard_dummy.T == 0
        # product_check = (GF2(G_h_dummy) @ GF2(H_standard_dummy.T)).view(np.ndarray)
        # if not np.all(product_check == 0):
        #    print("Warning: Dummy G_h @ H.T != 0. Product:\n", product_check)


        S_dummy = bm_scramble(K_test)
        perm_dummy = np.random.permutation(N_test)
        
        G_pub_dummy_unpermuted = (S_dummy @ G_h_dummy) % 2
        G_pub_dummy = G_pub_dummy_unpermuted[:, perm_dummy]
        
        np.save('alice_pub.npy', G_pub_dummy)
        print("Dummy 'alice_pub.npy' created. This will likely not decrypt the challenge ciphertext correctly.")

    result = solve_mceliece_hamming()
    print(result)

