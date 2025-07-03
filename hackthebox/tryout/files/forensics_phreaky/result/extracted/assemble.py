import os

def assemble_pdf_parts(base_filename, output_filename, num_parts):
    try:
        with open(output_filename, 'wb') as output_file:
            for i in range(1, num_parts + 1):
                part_filename = f"{base_filename}{i}"
                if not os.path.exists(part_filename):
                    print(f"Warning: Part file {part_filename} not found")
                    continue
                    
                with open(part_filename, 'rb') as part_file:
                    output_file.write(part_file.read())
                print(f"Added part {i} to {output_filename}")
                
        print(f"\nSuccessfully assembled {output_filename} from {num_parts} parts!")
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")

# Example usage for your specific files:
if __name__ == "__main__":
    base_name = "pbreaks_plan.pdf.part"
    output_pdf = "pbreaks_plan_assembled.pdf"
    total_parts = 15
    
    assemble_pdf_parts(base_name, output_pdf, total_parts)