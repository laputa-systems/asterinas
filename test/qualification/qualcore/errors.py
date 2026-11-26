class QualificationError(Exception):
    pass


class ManifestError(QualificationError):
    pass


class EvidenceError(QualificationError):
    pass
