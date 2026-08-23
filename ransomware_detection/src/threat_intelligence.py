import csv
import os


class ThreatIntelligence:

    def __init__(self, csv_path):

        self.csv_path = csv_path
        self.indicators = []

        self.load_dataset()


    def load_dataset(self):

        if not os.path.exists(self.csv_path):

            raise FileNotFoundError(
                f"Threat intelligence dataset not found: "
                f"{self.csv_path}"
            )

        with open(
            self.csv_path,
            "r",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:

                self.indicators.append(row)


    def lookup(self, indicator):

        matches = []

        for record in self.indicators:

            if record["indicator"].lower() == indicator.lower():

                matches.append(record)

        return matches


    def is_known_indicator(self, indicator):

        results = self.lookup(indicator)

        return len(results) > 0


    def get_threat_score(self, indicator):

        results = self.lookup(indicator)

        if not results:

            return 0.0

        highest_confidence = 0.0

        for record in results:

            confidence = float(
                record["confidence"]
            )

            if confidence > highest_confidence:

                highest_confidence = confidence

        return highest_confidence