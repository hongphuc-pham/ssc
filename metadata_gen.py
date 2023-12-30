import json, os, sys, subprocess
import cyclonedx
# import in_toto.models.layout as layout
# import in_toto.models.metadata as metadata
# import cyclonedx
from  in_toto.models.layout import Layout, Step, Inspection
from in_toto.models.metadata import Metablock
from securesystemslib.signer import CryptoSigner
# from in_toto.util import get_gpg_keyid

#########################################################
# def generate_layout(fpath):
#     txt_req_extract(fpath)
#     layout = layout.Layout(name="my-project-layout")

#     for requirement in requirements:
#         component = metadata.Component(name=requirement.name, version=requirement.specifier)
#         layout.add_component(component)
        
#     print(layout)
#     return layout

def read_requirements(fpath):
    """
    Read the requirements.txt file and extract package information.
    """
    with open(fpath, 'r') as file:
        lines = file.readlines()
        requirements = [line.strip() for line in lines if line.strip()]
    return requirements


def generate_metadata_layout(requirements):
    """
    Generate metadata layout using in-toto framework.
    """
    # Create an empty layout
    layout = Layout()
    step_package = Step(name="package")
    
    
    for requirement in requirements:
        metadata = Metablock()
        metadata.add_product_requirement(requirement)
        layout.add_step(metadata)

    return layout



def generate_bom_from_file(fpath):
    """
    Getting the file path of requirements.txt of package.json and using CycloneDX to get the recommended components which export in the pom.xml file
    Keyword arguments:
    fpath -- file path
    Return: pom.xml file 
    """
    
    # Check if the path is
    if not os.path.exists(fpath):
        raise FileNotFoundError(f"Error: File not found at {fpath}")
    
    try:
        if fpath.endswith(".txt"):
            
            # Generate requirements.txt using pip freeze
            subprocess.run(["pip", "freeze", ">", fpath], check=True)
            
            # Generate SBOM using cyclonedx-py
            subprocess.run(["cyclonedx-py", "-r", "-i", fpath, "-o", "sbom.xml"], check=True)

            print("SBOM generated successfully:", "sbom.xml")

        elif fpath.endswith(".json"):
            with open(fpath, "r") as f:
                package_data = json.load(f)
                dependencies = package_data.get("dependencies", {})

                bom = cyclonedx.bom.Bom()
                # ... create BOM components from dependencies

        else:
            raise ValueError("Invalid input file format")

        bom.write("bom.xml")
        return bom
    except Exception as e:
        print(f"Error generating BOM: {e}", file=sys.stderr)
        sys.exit(1)

def txt_req_extract(fpath):
    """Extracts package names and versions from a requirements.txt file into a dictionary.

    Args:
        requirements_file (str): Path to the requirements.txt file.

    Returns:
        dict: A dictionary containing package names as keys and versions as values.

    Raises:
        FileNotFoundError: If the requirements file is not found.
        ValueError: If a line in the file cannot be parsed.
    """

    packages = {}
    try:
        with open(fpath, 'r', encoding='cp1252') as f:
   
            lines = f.readlines()
            for line in lines:
                if line and not line.startswith('#'):
                    try:
                        package_name, *version_info = line.split('==')
                        packages[package_name] = version_info[0] if version_info else None
                    except ValueError as e:
                        raise ValueError(f"Error parsing line '{line}': {e}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Requirements file not found: {fpath}")
    return packages


if __name__ == "__main__":
    input_file = sys.argv[1]
    # generate_bom_from_file(input_file)
    # generate_layout(input_file)
    # print(txt_req_extract(input_file))
    requirements = read_requirements(input_file)

    # Generate metadata layout
    metadata_layout = generate_metadata_layout(requirements)

    # Write metadata layout to a file
    layout_file = 'metadata_layout'
    metadata_layout.dump(layout_file)
    