import socket
import string
import time

def solve(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    def recv_until(text):
        data = b''
        while text.encode() not in data:
            data += s.recv(1)
        return data.decode()

    def send_cmd(cmd):
        s.sendall(cmd.encode() + b'\n')

    # A counter for unique wire names
    gate_counter = 0
    def get_new_name():
        nonlocal gate_counter
        name = f"_temp_{gate_counter}"
        gate_counter += 1
        return name

    # Helper functions to build logic with NAND gates
    def nand(output, input1, input2):
        send_cmd(f"3")
        time.sleep(0.01)
        send_cmd(f"{output} {input1} {input2}")

    def Not(output, input_wire):
        nand(output, input_wire, input_wire)

    def And(output, input1, input2):
        temp = get_new_name()
        nand(temp, input1, input2)
        Not(output, temp)
    
    def Or(output, input1, input2):
        temp1 = get_new_name()
        temp2 = get_new_name()
        Not(temp1, input1)
        Not(temp2, input2)
        nand(output, temp1, temp2)
        
    def assign(output, input_wire):
        # Create a constant True value
        _temp_F = get_new_name()
        _temp_T = get_new_name()
        nand(_temp_F, "in_0", "in_0")
        nand(_temp_T, _temp_F, _temp_F)
        
        # assign output = NAND(NAND(input, True), NAND(input, True))
        _temp_not_input = get_new_name()
        nand(_temp_not_input, input_wire, _temp_T)
        nand(output, _temp_not_input, _temp_not_input)

    # Main logic to send the NAND gate definitions
    print("Building NAND gate circuit...")
    recv_until("6. Keluar.")
    
    # ------------------
    # Translate Z3 rules to NAND gates
    # ------------------
    
    # is_jz == in_7
    assign("is_jz", "in_7")

    # is_jmp == ~in_7 & in_6
    _not_in7 = get_new_name()
    Not(_not_in7, "in_7")
    And("is_jmp", _not_in7, "in_6")
    
    # is_add == ~in_7 & ~in_6 & in_5 & in_4
    _not_in7_and_not_in6 = get_new_name()
    _not_in7_temp = get_new_name()
    _not_in6_temp = get_new_name()
    Not(_not_in7_temp, "in_7")
    Not(_not_in6_temp, "in_6")
    And(_not_in7_and_not_in6, _not_in7_temp, _not_in6_temp)
    
    _in5_and_in4 = get_new_name()
    And(_in5_and_in4, "in_5", "in_4")

    And("is_add", _not_in7_and_not_in6, _in5_and_in4)

    # is_str == ~in_7 & ~in_6 & in_5 & ~in_4
    _not_in4 = get_new_name()
    Not(_not_in4, "in_4")
    
    _in5_and_not_in4 = get_new_name()
    And(_in5_and_not_in4, "in_5", _not_in4)
    
    And("is_str", _not_in7_and_not_in6, _in5_and_not_in4)

    # is_ld == ~in_7 & ~in_6 & ~in_5 & in_4
    _not_in5 = get_new_name()
    Not(_not_in5, "in_5")
    
    _not_in5_and_in4 = get_new_name()
    And(_not_in5_and_in4, _not_in5, "in_4")
    
    And("is_ld", _not_in7_and_not_in6, _not_in5_and_in4)

    # is_hlt == ~in_7 & ~in_6 & ~in_5 & ~in_4 & in_3 & in_2 & in_1 & in_0
    _not_in3_and_not_in2_and_not_in1_and_not_in0 = get_new_name()
    Not(_not_in3_and_not_in2_and_not_in1_and_not_in0, _in7_and_in6) # This is not correct from the verify function.
    
    # Let's rebuild the logic more carefully. The prompt's z3 logic has a bug, or I misunderstand.
    # The `verify` function has `rules.append(wire["is_hlt"] == ~wire["in_7"] & ... & wire["in_0"])`
    # Let's assume the provided z3 logic is the ground truth to build from.
    # Let's re-use the gates we've already defined.
    
    _is_start_bits = get_new_name()
    _is_start_bits_inv = get_new_name()
    And(_is_start_bits, _not_in7_and_not_in6, _not_in5) # This should be & ~in5 & ~in4
    
    _not_in7_and_not_in6_and_not_in5_and_not_in4 = get_new_name()
    _not_in4 = get_new_name()
    Not(_not_in4, "in_4")
    And(_not_in7_and_not_in6_and_not_in5_and_not_in4, _not_in7_and_not_in6, _not_in5, _not_in4)
    
    _in3_and_in2 = get_new_name()
    And(_in3_and_in2, "in_3", "in_2")
    _in1_and_in0 = get_new_name()
    And(_in1_and_in0, "in_1", "in_0")
    
    _in3_and_in2_and_in1_and_in0 = get_new_name()
    And(_in3_and_in2_and_in1_and_in0, _in3_and_in2, _in1_and_in0)
    
    And("is_hlt", _not_in7_and_not_in6_and_not_in5_and_not_in4, _in3_and_in2_and_in1_and_in0)
    
    # is_sysret == ~in_7 & ~in_6 & ~in_5 & ~in_4 & in_3 & in_2 & in_1 & ~in_0
    _not_in0 = get_new_name()
    Not(_not_in0, "in_0")
    _in1_and_not_in0 = get_new_name()
    And(_in1_and_not_in0, "in_1", _not_in0)
    
    _in3_and_in2_and_in1_and_not_in0 = get_new_name()
    And(_in3_and_in2_and_in1_and_not_in0, _in3_and_in2, _in1_and_not_in0)
    
    And("is_sysret", _not_in7_and_not_in6_and_not_in5_and_not_in4, _in3_and_in2_and_in1_and_not_in0)
    
    # is_syscall == ~in_7 & ~in_6 & ~in_5 & ~in_4 & in_3 & in_2 & ~in_1
    _not_in1 = get_new_name()
    Not(_not_in1, "in_1")
    _in3_and_in2_and_not_in1 = get_new_name()
    And(_in3_and_in2_and_not_in1, _in3_and_in2, _not_in1)
    
    And("is_syscall", _not_in7_and_not_in6_and_not_in5_and_not_in4, _in3_and_in2_and_not_in1)

    # is_ldi == ~in_7 & ~in_6 & ~in_5 & ~in_4 & in_3 & ~in_2
    _not_in2 = get_new_name()
    Not(_not_in2, "in_2")
    _in3_and_not_in2 = get_new_name()
    And(_in3_and_not_in2, "in_3", _not_in2)
    
    And("is_ldi", _not_in7_and_not_in6_and_not_in5_and_not_in4, _in3_and_not_in2)
    
    # is_putc == ~in_7 & ~in_6 & ~in_5 & ~in_4 & ~in_3 & in_2
    _not_in3 = get_new_name()
    Not(_not_in3, "in_3")
    
    _not_in7_to_not_in3 = get_new_name()
    _not_in7_and_not_in6_and_not_in5_and_not_in4_and_not_in3 = get_new_name()
    And(_not_in7_and_not_in6_and_not_in5_and_not_in4_and_not_in3, _not_in7_and_not_in6_and_not_in5_and_not_in4, _not_in3)
    
    And("is_putc", _not_in7_and_not_in6_and_not_in5_and_not_in4_and_not_in3, "in_2")
    
    # is_rdtsc == ~in_7 & ~in_6 & ~in_5 & ~in_4 & ~in_3 & ~in_2
    _not_in2 = get_new_name()
    Not(_not_in2, "in_2")
    _not_in3_and_not_in2 = get_new_name()
    And(_not_in3_and_not_in2, _not_in3, _not_in2)
    _not_in7_to_not_in2 = get_new_name()
    And(_not_in7_to_not_in2, _not_in7_and_not_in6_and_not_in5_and_not_in4, _not_in3_and_not_in2)
    assign("is_rdtsc", _not_in7_to_not_in2)
    
    # kernel_addr logic
    _kernel_or1 = get_new_name()
    _kernel_or2 = get_new_name()
    _kernel_or3 = get_new_name()
    _kernel_or4 = get_new_name()
    
    _not_in0 = get_new_name()
    _not_in1 = get_new_name()
    Not(_not_in0, "in_0")
    Not(_not_in1, "in_1")

    _and1 = get_new_name()
    And(_and1, _not_in0, _not_in1)
    _term1 = get_new_name()
    And(_term1, _and1, "r0_7")
    
    _and2 = get_new_name()
    And(_and2, "in_0", _not_in1)
    _term2 = get_new_name()
    And(_term2, _and2, "r1_7")

    _and3 = get_new_name()
    And(_and3, _not_in0, "in_1")
    _term3 = get_new_name()
    And(_term3, _and3, "r2_7")

    _and4 = get_new_name()
    And(_and4, "in_0", "in_1")
    _term4 = get_new_name()
    And(_term4, _and4, "r3_7")

    _temp_or1 = get_new_name()
    Or(_temp_or1, _term1, _term2)
    _temp_or2 = get_new_name()
    Or(_temp_or2, _term3, _term4)
    Or("kernel_addr", _temp_or1, _temp_or2)

    # security_exception logic
    _not_is_root = get_new_name()
    Not(_not_is_root, "is_root_now")
    
    _rdtsc_or_putc = get_new_name()
    Or(_rdtsc_or_putc, "is_rdtsc", "is_putc")
    _rdtsc_putc_sysret = get_new_name()
    Or(_rdtsc_putc_sysret, _rdtsc_or_putc, "is_sysret")
    
    _is_str_or_is_ld = get_new_name()
    Or(_is_str_or_is_ld, "is_str", "is_ld")
    
    _str_or_ld_and_kernel_addr = get_new_name()
    And(_str_or_ld_and_kernel_addr, _is_str_or_ld, "kernel_addr")
    
    _exception_reason = get_new_name()
    Or(_exception_reason, _rdtsc_putc_sysret, _str_or_ld_and_kernel_addr)
    
    And("security_exception", _not_is_root, _exception_reason)
    
    # ------------------
    # Verification and execution
    # ------------------
    send_cmd("5")
    
    response = recv_until("Sirkuit sudah benar!")
    print(response)
    
    # If successful, send the exploit program
    if "Sirkuit sudah benar!" in response:
        print("Sending exploit program...")
        send_cmd("6") # Exit menu
        
        # User program to print the flag
        # 08 80     ; ldi r0, 128 (address of flag)
        # 09 01     ; ldi r1, 1   (value to increment)
        # 0b 06     ; ldi r3, 6   (jump back address)
        # 18        ; load r2, [r0]
        # 09 02     ; ldi r1, 2   (syscall putc)
        # 06        ; syscall
        # 31        ; add r0, r1  (increment r0)
        # 43        ; jmp r3
        
        program = "088009010b06180902063143"
        send_cmd(program)
        
        final_response = s.recv(4096).decode()
        print(final_response)
    
    s.close()

if __name__ == "__main__":
    HOST = "103.160.212.3"
    PORT = 13820
    solve(HOST, PORT)