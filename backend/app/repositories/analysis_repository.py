from sqlalchemy.orm import Session

from app.models.analysis import Analysis


class AnalysisRepository:
    """
    Handles database operations related to analysis results.
    """

    @staticmethod
    def create(
        db: Session,
        sample_id: str,
        mime_type: str,
        entropy: float,
        pe_analysis: dict | None,
        yara_matches: list | None = None,
        suspicious_strings: list | None = None,
        risk_score: int = 0,
        severity: str = "LOW",
    ) -> Analysis:
        """
        Create and save a new analysis record.
        """

        analysis = Analysis(
            sample_id=sample_id,
            mime_type=mime_type,
            entropy=entropy,
            pe_analysis=pe_analysis,
            yara_matches=yara_matches,
            suspicious_strings=suspicious_strings,
            risk_score=risk_score,
            severity=severity,
        )

        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        return analysis

    @staticmethod
    def get_by_sample_id(
        db: Session,
        sample_id: str,
    ) -> Analysis | None:
        """
        Get analysis by sample ID.
        """

        return (
            db.query(Analysis)
            .filter(
                Analysis.sample_id == sample_id
            )
            .first()
        )

    @staticmethod
    def update(
        db: Session,
        analysis: Analysis,
        mime_type: str,
        entropy: float,
        pe_analysis: dict | None,
        yara_matches: list | None = None,
        suspicious_strings: list | None = None,
        risk_score: int = 0,
        severity: str = "LOW",
    ) -> Analysis:
        """
        Update an existing analysis record.
        """

        analysis.mime_type = mime_type

        analysis.entropy = entropy

        analysis.pe_analysis = pe_analysis

        analysis.yara_matches = yara_matches

        analysis.suspicious_strings = suspicious_strings

        analysis.risk_score = risk_score

        analysis.severity = severity

        db.commit()
        db.refresh(analysis)

        return analysis

    @staticmethod
    def delete(
        db: Session,
        analysis: Analysis,
    ) -> None:
        """
        Delete an analysis record.
        """

        db.delete(analysis)
        db.commit()