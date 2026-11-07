import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from history import HistoryManager
from scanner import ScanJob, ScanManager


class HistoryStorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "data" / "history.json"
        self.history = HistoryManager(self.path, limit=2)

    def tearDown(self):
        self.temporary.cleanup()

    def make_job(self, job_id="job-1"):
        job = ScanJob(targets=["127.0.0.1"], ports=[80], target_spec="127.0.0.1")
        job.id = job_id
        job.status = "completed"
        job.completed = 1
        job.open_port_count = 1
        job.results = [{"ip": "127.0.0.1", "hostname": "localhost", "latency": 3,
                        "foundAt": time.time(), "ports": [{"port": 80, "service": "HTTP"}]}]
        job.finished_at = time.time()
        return job

    def test_add_get_and_reload(self):
        self.history.add(self.make_job())
        summaries = self.history.list()
        self.assertEqual(len(summaries), 1)
        self.assertNotIn("results", summaries[0])
        self.assertEqual(summaries[0]["targetSpec"], "127.0.0.1")
        self.assertEqual(self.history.get("job-1")["results"][0]["ports"][0]["port"], 80)
        reloaded = HistoryManager(self.path)
        self.assertEqual(reloaded.list()[0]["id"], "job-1")

    def test_limit_delete_and_clear(self):
        for index in range(3):
            self.history.add(self.make_job(f"job-{index}"))
        self.assertEqual(len(self.history.list()), 2)
        self.assertIsNone(self.history.get("job-0"))
        self.assertTrue(self.history.delete("job-1"))
        self.assertFalse(self.history.delete("missing"))
        self.assertEqual(self.history.clear(), 1)
        self.assertEqual(self.history.list(), [])
        self.assertTrue(self.path.exists())


class HistoryArchiveTests(unittest.TestCase):
    @patch("scanner.ping", return_value=True)
    def test_manager_archives_finished_job(self, _ping):
        archived = []
        finished = threading.Event()

        def on_complete(job):
            archived.append(job.snapshot())
            finished.set()

        manager = ScanManager(on_complete=on_complete)
        job = manager.start({"targets": "127.0.0.1", "ports": "80", "scanPorts": False, "concurrency": 1})
        self.assertTrue(finished.wait(timeout=2))
        self.assertEqual(job.status, "completed")
        self.assertEqual(len(archived), 1)
        self.assertEqual(archived[0]["targetSpec"], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
