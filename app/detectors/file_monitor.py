
from datetime import datetime
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from app.database.connection import save_file_event
from app.detectors.detection_engine import DetectionEngine



class RansomwareFileHandler(FileSystemEventHandler):
    """Detect and record basic file activity."""
    def __init__(self):
     super().__init__()
     self.detection_engine = DetectionEngine()

   
    def log_event(self, event_type, file_path, destination_path=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"Event type: {event_type}")
        print(f"File path: {file_path}")

        if destination_path is not None:
            print(f"Destination path: {destination_path}")

        print(f"Timestamp: {timestamp}")

    
        try:
            event_id = save_file_event(
                event_type=event_type,
                file_path=file_path,
                destination_path=destination_path,
            )
            print(f"Saved to database. Event ID: {event_id}")

            self.detection_engine.add_event({
                "event_type": event_type,
                "file_path": file_path,
                "destination_path": destination_path,
                "timestamp": datetime.now(),
            })

            activity = self.detection_engine.analyze_activity()

            print(f"Threat score: {activity['threat_score']}")
            print(f"Threat level: {activity['threat_level']}")

        except Exception as error:
            print(f"Database save failed: {error}")




    def on_created(self, event):
        if not event.is_directory:
            self.log_event("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.log_event("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.log_event("moved", event.src_path, event.dest_path)




def start_file_monitoring():
    watch_path = Path("data/sandbox").resolve()
    watch_path.mkdir(parents=True, exist_ok=True)

    event_handler = RansomwareFileHandler()
    observer = Observer()
    observer.schedule(event_handler, str(watch_path), recursive=True)

    observer.start()
    print(f"Monitoring folder: {watch_path}")
    print("Press Ctrl+C to stop monitoring.")

    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("File monitoring stopped.")

    observer.join()


if __name__ == "__main__":
    start_file_monitoring()
