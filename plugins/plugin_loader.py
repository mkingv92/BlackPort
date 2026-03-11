# plugins/plugin_loader.py
import importlib
import os

def load_plugins(plugin_dir="plugins"):
    """
    Dynamically loads all plugin classes from the plugins directory.
    Returns a list of instantiated plugin objects.
    """
    plugins = []
    for filename in os.listdir(plugin_dir):
        if filename.endswith(".py") and filename not in ("__init__.py", "plugin_base.py", "plugin_loader.py"):
            module_name = f"{plugin_dir}.{filename[:-3]}"
            try:
                module = importlib.import_module(module_name)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and attr_name != "PluginBase"
                        and hasattr(attr, "applicable_services")
                        and hasattr(attr, "run")
                    ):
                        plugins.append(attr())
            except Exception as e:
                print(f"[!] Failed to load plugin {filename}: {e}")
    return plugins


def run_plugins(plugins, target, port, service, banner=None):
    """
    Runs all plugins whose applicable_services match the detected service.
    Returns a list of result dicts from each matching plugin.
    """
    results = []
    service_upper = service.upper() if service else ""
    for plugin in plugins:
        if service_upper in [s.upper() for s in plugin.applicable_services]:
            try:
                result = plugin.run(target, port, banner=banner)
                if result:
                    results.append(result)
            except Exception as e:
                print(f"[!] Plugin '{plugin.name}' error on port {port}: {e}")
    return results
