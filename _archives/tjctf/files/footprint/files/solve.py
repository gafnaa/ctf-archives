import sys
from ds_store import DSStore

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <ds_store_file>")
        return

    ds_store_file = sys.argv[1]

    try:
        with open(ds_store_file, 'rb') as f:
            d = DSStore.open(f)
            for entry in d:
                print(entry.filename)
            d.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()