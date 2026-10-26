
from app.core.config import load_config

config = load_config()

print("Application:", config["app"]["name"])
print("Simulation mode:", config["app"]["simulation_mode"])
print("Watched folders:", config["monitoring"]["watch_paths"])
print("Event window:", config["monitoring"]["event_window_seconds"])
print("Entropy threshold:", config["thresholds"]["high_entropy"])
