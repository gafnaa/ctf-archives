import copy
import random
import numpy as np
import ast

class RubiksCube:
    def __init__(self):
        self.faces = {
            'U': [['⬜'] * 3 for _ in range(3)],
            'L': [['🟧'] * 3 for _ in range(3)],
            'F': [['🟩'] * 3 for _ in range(3)],
            'R': [['🟥'] * 3 for _ in range(3)],
            'B': [['🟦'] * 3 for _ in range(3)],
            'D': [['🟨'] * 3 for _ in range(3)]
        }

    def _rotate_face_clockwise(self, face_name):
        face = self.faces[face_name]
        new_face = [[None] * 3 for _ in range(3)]
        for i in range(3):
            for j in range(3):
                new_face[i][j] = face[2-j][i]
        self.faces[face_name] = new_face

    def _rotate_face_counter_clockwise(self, face_name):
        face = self.faces[face_name]
        new_face = [[None] * 3 for _ in range(3)]
        for i in range(3):
            for j in range(3):
                new_face[i][j] = face[j][2-i]
        self.faces[face_name] = new_face

    def display(self):
        for i in range(3):
            print("      " + " ".join(self.faces['U'][i]))
        for i in range(3):
            print(" ".join(self.faces['L'][i]) + "  " +
                  " ".join(self.faces['F'][i]) + "  " +
                  " ".join(self.faces['R'][i]) + "  " +
                  " ".join(self.faces['B'][i]))
        for i in range(3):
            print("      " + " ".join(self.faces['D'][i]))
        print("-" * 30)

    def get_flat_cube_encoded(self):
        return "".join([chr(ord(i) % 94 + 33) for i in str(list(np.array(self.faces).flatten())) if ord(i)>256])
    
    def get_cube(self):
        return self.faces
    
    def U(self):
        self._rotate_face_clockwise('U')
        temp_row = copy.deepcopy(self.faces['F'][0])
        self.faces['F'][0] = self.faces['R'][0]
        self.faces['R'][0] = self.faces['B'][0]
        self.faces['B'][0] = self.faces['L'][0]
        self.faces['L'][0] = temp_row

    def L(self):
        self._rotate_face_clockwise('L')
        temp_col = [self.faces['U'][i][0] for i in range(3)]
        for i in range(3): self.faces['U'][i][0] = self.faces['B'][2-i][2]
        for i in range(3): self.faces['B'][2-i][2] = self.faces['D'][i][0]
        for i in range(3): self.faces['D'][i][0] = self.faces['F'][i][0]
        for i in range(3): self.faces['F'][i][0] = temp_col[i]

    def F(self):
        self._rotate_face_clockwise('F')
        temp_strip = copy.deepcopy(self.faces['U'][2])
        for i in range(3): self.faces['U'][2][i] = self.faces['L'][2-i][2]
        for i in range(3): self.faces['L'][i][2] = self.faces['D'][0][i]
        for i in range(3): self.faces['D'][0][2-i] = self.faces['R'][i][0]
        for i in range(3): self.faces['R'][i][0] = temp_strip[i]

    def D_prime(self):
        self._rotate_face_counter_clockwise('D')
        temp_row = copy.deepcopy(self.faces['F'][2])
        self.faces['F'][2] = self.faces['R'][2]
        self.faces['R'][2] = self.faces['B'][2]
        self.faces['B'][2] = self.faces['L'][2]
        self.faces['L'][2] = temp_row

    def R_prime(self):
        self._rotate_face_counter_clockwise('R')
        temp_col = [self.faces['U'][i][2] for i in range(3)]
        for i in range(3): self.faces['U'][i][2] = self.faces['B'][2-i][0]
        for i in range(3): self.faces['B'][2-i][0] = self.faces['D'][i][2]
        for i in range(3): self.faces['D'][i][2] = self.faces['F'][i][2]
        for i in range(3): self.faces['F'][i][2] = temp_col[i]

    def B_prime(self):
        self._rotate_face_counter_clockwise('B')
        temp_strip = copy.deepcopy(self.faces['U'][0])
        for i in range(3): self.faces['U'][0][i] = self.faces['L'][i][0]
        for i in range(3): self.faces['L'][i][0] = self.faces['D'][2][2-i]
        for i in range(3): self.faces['D'][2][i] = self.faces['R'][i][2]
        for i in range(3): self.faces['R'][i][2] = temp_strip[2-i]

    def apply_moves(self, moves_string):
        moves = moves_string.split()
        for move in moves:
            if move == "U": self.U()
            elif move == "D'": self.D_prime()
            elif move == "L": self.L()
            elif move == "R'": self.R_prime()
            elif move == "F": self.F()
            elif move == "B'": self.B_prime()
            else:
                print(f"Warning: Unknown move '{move}' ignored.")

    # Inverse moves (applying the original move 3 times)
    def U_inv(self):
        self.U(); self.U(); self.U()
    def L_inv(self):
        self.L(); self.L(); self.L()
    def F_inv(self):
        self.F(); self.F(); self.F()
    def D_prime_inv(self): # Inverse of D' is D
        self.D_prime(); self.D_prime(); self.D_prime()
    def R_prime_inv(self): # Inverse of R' is R
        self.R_prime(); self.R_prime(); self.R_prime()
    def B_prime_inv(self): # Inverse of B' is B
        self.B_prime(); self.B_prime(); self.B_prime()

def solve_rubiks_cube():
    # Read the scrambled cube state
    with open("files/cube_scrambled.txt", "r", encoding="utf-8") as f:
        scrambled_cube_str = f.read()
    
    # Parse the string into a dictionary
    scrambled_faces = ast.literal_eval(scrambled_cube_str)

    # Create a RubiksCube instance and set its faces to the scrambled state
    cube = RubiksCube()
    cube.faces = scrambled_faces

    # Define the original moves list from rubixcube.py
    moves = ["U", "L", "F", "B'", "D'", "R'"]

    # Map original moves to their inverse methods
    inverse_moves_map = {
        "U": cube.U_inv,
        "L": cube.L_inv,
        "F": cube.F_inv,
        "B'": cube.B_prime_inv,
        "D'": cube.D_prime_inv,
        "R'": cube.R_prime_inv
    }

    # Reproduce the random sequence of moves that were applied AFTER flag generation
    random.seed(42)
    generated_moves_sequence = []
    for _ in range(20):
        order = [random.randint(0,len(moves)-1) for _ in range(50)]
        for i in range(len(order)):
            generated_moves_sequence.append(moves[order[i]])
    
    # Apply the inverse of these moves in reverse order
    for move_name in reversed(generated_moves_sequence):
        inverse_func = inverse_moves_map[move_name]
        inverse_func() # Apply the inverse move

    # The cube should now be in the state it was in when the flag was generated
    recovered_encoded_state = cube.get_flat_cube_encoded()
    flag = "tjctf{" + recovered_encoded_state + "}"
    print(f"Recovered Flag: {flag}")

if __name__ == "__main__":
    solve_rubiks_cube()
