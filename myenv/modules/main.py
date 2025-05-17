import argparse
import os
import sys
import importlib.util

API_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'backend', 'API')

def list_api_methods():
    methods = {}
    if not os.path.isdir(API_FOLDER):
        print(f"API folder '{API_FOLDER}' does not exist.")
        return methods
    for filename in os.listdir(API_FOLDER):
        if filename.endswith('.py') and not filename.startswith('__'):
            module_name = filename[:-3]
            file_path = os.path.join(API_FOLDER, filename)
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for attr in dir(module):
                if callable(getattr(module, attr)) and not attr.startswith('_'):
                    methods[f"{module_name}.{attr}"] = getattr(module, attr)
    return methods

def parse_input(input_str):
    import ast
    def convert(val):
        try:
            return ast.literal_eval(val)
        except Exception:
            return val

    if not input_str:
        return [], {}
    args = []
    kwargs = {}
    for item in input_str.split(','):
        item = item.strip()
        if '=' in item:
            key, value = item.split('=', 1)
            kwargs[key.strip()] = convert(value.strip())
        elif item:
            args.append(convert(item))
    return args, kwargs

def main():
    methods = list_api_methods()
    parser = argparse.ArgumentParser(
        description="Call any function from backend/API modules.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--function', '-f', help="Function to call in format module.function")
    parser.add_argument('--input', '-i', help="Function input as comma-separated values (use key=value for kwargs)")
    parser.add_argument('--list', action='store_true', help="List all available functions")
    args = parser.parse_args()

    if args.list or not args.function:
        print("Available functions:")
        for m in sorted(methods):
            print(f"  {m}")
        sys.exit(0)

    if args.function not in methods:
        print(f"Function '{args.function}' not found.\nAvailable functions:")
        for m in sorted(methods):
            print(f"  {m}")
        sys.exit(1)

    func = methods[args.function]
    pos_args, kw_args = parse_input(args.input)
    result = func(*pos_args, **kw_args)
    print(result)

if __name__ == "__main__":
    main()