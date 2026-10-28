import unittest

from analysis.sensitivity_analysis import calculate_metrics, pr_auc, roc_auc


class SensitivityAnalysisTests(unittest.TestCase):
    def test_f2_weights_recall_more_than_precision(self):
        rows = [
            {"traffic_class": "ai_agent_attacker", "score": "8.0"},
            {"traffic_class": "ai_agent_attacker", "score": "2.0"},
            {"traffic_class": "benign_admin", "score": "1.0"},
            {"traffic_class": "benign_admin", "score": "0.5"},
        ]
        result = calculate_metrics(rows, "local", 4.0)
        self.assertAlmostEqual(result.precision, 1.0)
        self.assertAlmostEqual(result.recall, 0.5)
        self.assertAlmostEqual(result.f2_score, 5 / 9)

    def test_auc_values_are_bounded(self):
        labels = [True, True, False, False]
        scores = [0.9, 0.8, 0.2, 0.1]
        self.assertGreaterEqual(roc_auc(labels, scores), 0.0)
        self.assertLessEqual(roc_auc(labels, scores), 1.0)
        self.assertGreaterEqual(pr_auc(labels, scores), 0.0)
        self.assertLessEqual(pr_auc(labels, scores), 1.0)


if __name__ == "__main__":
    unittest.main()
