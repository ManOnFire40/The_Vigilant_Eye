import argparse
import os
import sys
import importlib.util
#import "../modules/backend/API/Abuse_IPDB.py"

# Set the path to the API folder relative to this file
API_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'backend', 'API')

# Function to list all callable methods in the API folder
def list_api_methods():
    methods = {}  # Dictionary to store method references
    for filename in os.listdir(API_FOLDER):  # Iterate over files in API folder
        if filename.endswith('.py') and not filename.startswith('__'):  # Only .py files, skip dunder files
            module_name = filename[:-3]  # Remove .py extension to get module name
            file_path = os.path.join(API_FOLDER, filename)  # Full path to the module file
            spec = importlib.util.spec_from_file_location(module_name, file_path)  # Create a module spec
            module = importlib.util.module_from_spec(spec)  # Create a module object from the spec
            spec.loader.exec_module(module)  # Load the module
            for attr in dir(module):  # Iterate over attributes in the module
                if callable(getattr(module, attr)) and not attr.startswith('_'):  # Only public callables
                    methods[f"{module_name}.{attr}"] = getattr(module, attr)  # Add to methods dict
    return methods  # Return the dictionary of methods

# Function to parse positional and keyword arguments from command line
def parse_args_and_kwargs(args):
    pos_args = []  # List for positional arguments
    kw_args = {}   # Dict for keyword arguments
    for arg in args:  # Iterate over provided arguments
        if '=' in arg:  # If argument is in key=value format
            key, value = arg.split('=', 1)  # Split into key and value
            kw_args[key] = value  # Add to keyword arguments
        else:
            pos_args.append(arg)  # Otherwise, add to positional arguments
    return pos_args, kw_args  # Return both lists

# Main function to parse arguments and call the selected API method
def main():
    parser = argparse.ArgumentParser(description="Call API methods from backend/API")  # Create argument parser
    parser.add_argument('method', help="Method to call in format module.method")  # Add method argument
    parser.add_argument('args', nargs='*', help="Arguments for the method (use key=value for keyword arguments)")  # Add args argument
    args = parser.parse_args()  # Parse command line arguments

    methods = list_api_methods()  # Get all available API methods
    if args.method not in methods:  # If requested method is not found
        print(f"Method {args.method} not found. Available methods:")  # Print error message
        for m in methods:  # List available methods
            print(f"  {m}")
        sys.exit(1)  # Exit with error

    method = methods[args.method]  # Get the method to call
    pos_args, kw_args = parse_args_and_kwargs(args.args)  # Parse positional and keyword arguments
    result = method(*pos_args, **kw_args)  # Call the method with arguments
    print(result)  # Print the result

# Entry point for the script
if __name__ == "__main__":
    main()  # Run the main function