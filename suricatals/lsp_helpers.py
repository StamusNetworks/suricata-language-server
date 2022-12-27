class FileRange:
    def __init__(self, line_start, col_start, line_end, col_end):
        self.line_start = line_start
        self.col_start = col_start
        self.line_end = line_end
        self.col_end = col_end

    def __repr__(self):
        return "FileRange()"

    def to_range(self):
        return {"start": {"line": self.line_start, "character": self.col_start}, "end": {"line": self.line_end, "character": self.col_end}}


class Diagnosis(object):
    INFO_LEVEL=4
    WARNING_LEVEL=2
    ERROR_LEVEL=1

    def __init__(self):
        self._range = None
        self._message = None
        self._severity = 1
        self._source="Suricata Language Server"

    def to_message(self):
        if self._range is None:
            return None
        if self._message is None:
            return None
        return {"range": self._range.to_range(), "message": self.message, "source": self.source, "severity": self.severity} 

    @property
    def range(self):
        return self._range

    @range.setter
    def range(self, sig_range):
        self._range = sig_range

    @property
    def message(self):
        return self._message

    @message.setter
    def message(self, message):
        self._message = message

    @property
    def severity(self):
        return self._severity

    @severity.setter
    def severity(self, severity):
        self._severity = severity

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, source):
        self._source = source
