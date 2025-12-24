import mcp
import pkgutil
import sys

print(f"MCP File: {mcp.__file__}")
print(f"MCP Path: {mcp.__path__}")

def list_submodules(package, prefix):
    for importer, modname, ispkg in pkgutil.iter_modules(package.__path__):
        print(f"{prefix}{modname} (is_pkg={ispkg})")
        if ispkg:
            try:
                submod = __import__(f"{package.__name__}.{modname}", fromlist=["dummy"])
                list_submodules(submod, prefix + "  ")
            except Exception as e:
                print(f"{prefix}  ERROR Importing {modname}: {e}")

list_submodules(mcp, "")
