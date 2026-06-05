import dataclasses


@dataclasses.dataclass
class NodeCentrality:
    degree_in: float
    degree_out: float

    dll_calls: int

    instructions: int

    degree_centrality: float
    closeness_centrality: float
    eigenvector_centrality: float

    score: float = 0.0  # Custom score combining various centrality metrics

    def __post_init__(self):
        score = NodeCentrality.get_score(self)
        object.__setattr__(self, 'score', score)

    def __str__(self):
        return f"<Score: {self.score:.4f} | In: {self.degree_in}, Out: {self.degree_out}, DLL: {self.dll_calls}, Instr: {self.instructions}, DC={self.degree_centrality:.4f}, CC={self.closeness_centrality:.4f}, EC={self.eigenvector_centrality:.4f}>"

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def get_score(c: "NodeCentrality") -> float:
        return (1 +
                c.degree_centrality +
                c.closeness_centrality +
                c.eigenvector_centrality) \
            * (1 + c.dll_calls) \
            * (1 + c.degree_in + c.degree_out) \
            * (1 + c.instructions)
