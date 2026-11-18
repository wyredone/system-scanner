import json
import unittest
from unittest.mock import patch
from investigation import reputation


class ReputationTests(unittest.TestCase):
    def query(self, status, stats=None):
        with patch("investigation.http.client.HTTPSConnection") as client:
            response = client.return_value.getresponse.return_value
            response.status = status
            response.read.return_value = json.dumps({"data": {"attributes": {
                "last_analysis_stats": stats}}}).encode()
            result = reputation("a" * 64, "demo")
            client.return_value.request.assert_called_once_with(
                "GET", "/api/v3/files/" + "a" * 64, headers={"x-apikey": "demo"})
            return result[0]

    def test_distinct_results(self):
        self.assertEqual(self.query(404), "unknown")
        self.assertEqual(self.query(200, {"malicious": 0, "suspicious": 0}), "neutral")
        self.assertEqual(self.query(200, {"malicious": 1, "suspicious": 0}), "attention")
        with self.assertRaises(ValueError):
            self.query(429)
