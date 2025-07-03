#!/bin/bash

if [ ! -f files.txt ]; then
    echo "Error: files.txt not found."
    exit 1
fi

if [ ! -f phreaks_plan.pdf ]; then
    touch phreaks_plan.pdf
fi

while IFS= read -r filename; do
    if [ -f "$filename" ]; then
        cat "$filename" >> phreaks_plan.pdf
        echo "Content of $filename appended to phreaks_plan.pdf"
    else
        echo "Error: $filename not found."
    fi
done < files.txt

echo "All files processed."