import os, sys, subprocess

### syntax:
'''
python3 SBOMGen.py PATH/TO/FILE
'''

if __name__ == "__main__":
    fpath = sys.argv[1]
     # Check if the path is
    if not os.path.exists(fpath):
        raise FileNotFoundError(f"Error: File not found at {fpath}")
    
    try:
        if any(fpath.endswith(ext) for ext in [".txt", ".csv", ".json"]):
            
            # Generate requirements.txt using pip freeze
            # subprocess.run(["pip", "freeze", ">", fpath], check=True)
            
            # Generate SBOM using cyclonedx-py to generate the SBOM in JSON format
            subprocess.run(["cyclonedx-py", "-r", "-i", fpath, "-o", "sbom.json", '--format', 'json'], check=True)
        
            print("SBOM generated successfully:")

        else:
            raise ValueError("Invalid input file format")

        # bom.write("bom.xml")
        # return bom
    except Exception as e:
        print(f"Error generating BOM: {e}", file=sys.stderr)
        sys.exit(1)
