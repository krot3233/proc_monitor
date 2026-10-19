from dataclasses import dataclass, field


@dataclass
class ProcInfo:
    pid: int
    name: str
    exe: str
    cmdline: list = field(default_factory=list)
    ppid: int = 0
    parent_name: str = ""
    create_time: float = 0.0