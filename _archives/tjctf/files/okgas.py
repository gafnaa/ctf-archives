import matplotlib.pyplot as plt

# The name of the file containing the mouse coordinates.
filename = 'mouse_mov.txt'

x_coords = []
y_coords = []

# Read the coordinates from the file.
try:
    with open(filename, 'r') as f:
        for line in f:
            try:
                # Split the line by the comma and convert to integers.
                x, y = line.strip().split(',')
                x_coords.append(int(x))
                y_coords.append(int(y))
            except ValueError:
                # Skip any malformed lines.
                print(f"Skipping invalid line: {line.strip()}")
except FileNotFoundError:
    print(f"Error: The file '{filename}' was not found.")
    exit()

# Create the plot.
plt.figure(figsize=(10, 5))
# Create a scatter plot of the points. 's=1' makes the points small.
plt.scatter(x_coords, y_coords, s=1)

# Invert the y-axis because screen coordinates typically have (0,0) at the top-left.
plt.gca().invert_yaxis()

# Add labels and a title for clarity.
plt.xlabel("X-coordinate")
plt.ylabel("Y-coordinate")
plt.title("Mouse Movement Visualization")
plt.grid(True) # Optional: adds a grid

# Display the plot.
plt.show()