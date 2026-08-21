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
        yara_matches: list | None,
        suspicious_strings: list | None,
    ) -> Analysis:

        analysis = Analysis(
            sample_id=sample_id,
            mime_type=mime_type,
            entropy=entropy,
            pe_analysis=pe_analysis,
            yara_matches=yara_matches,
            suspicious_strings=suspicious_strings,
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

        return (
            db.query(Analysis)
            .filter(Analysis.sample_id == sample_id)
            .first()
        )

    @staticmethod
    def update(
        db: Session,
        analysis: Analysis,
        mime_type: str,
        entropy: float,
        pe_analysis: dict | None,
        yara_matches: list | None,
        suspicious_strings: list | None,
    ) -> Analysis:

        analysis.mime_type = mime_type
        analysis.entropy = entropy
        analysis.pe_analysis = pe_analysis
        analysis.yara_matches = yara_matches
        analysis.suspicious_strings = suspicious_strings

        db.commit()
        db.refresh(analysis)

        return analysis

    @staticmethod
    def delete(
        db: Session,
        analysis: Analysis,
    ):

        db.delete(analysis)
        db.commit()