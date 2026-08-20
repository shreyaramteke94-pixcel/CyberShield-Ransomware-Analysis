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
    ) -> Analysis:

        analysis = Analysis(
            sample_id=sample_id,
            mime_type=mime_type,
            entropy=entropy,
            pe_analysis=pe_analysis,
        )

        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        return analysis

    @staticmethod
    def get_by_sample_id(
        db: Session,
        sample_id: str,
    ):

        return (
            db.query(Analysis)
            .filter(Analysis.sample_id == sample_id)
            .first()
        )