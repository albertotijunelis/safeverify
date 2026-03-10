"""Tests for IOC graph generation."""

from hashguard.ioc_graph import build_graph, IOCGraph, GraphNode, GraphEdge


class TestBuildGraph:
    """Tests for build_graph function."""

    def test_empty_result(self):
        graph = build_graph({})
        # Should still have the central file node
        assert len(graph.nodes) == 1
        assert graph.nodes[0].node_type == "file"

    def test_with_iocs(self):
        result = {
            "strings_info": {
                "iocs": {
                    "urls": ["http://evil.com/payload"],
                    "ip_addresses": ["1.2.3.4"],
                    "domains": ["evil.com"],
                    "emails": ["bad@evil.com"],
                    "crypto_wallets": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
                    "registry_keys": [r"HKLM\Software\Malware"],
                }
            }
        }
        graph = build_graph(result)
        # 1 file + 1 url + 1 ip + 1 domain + 1 email + 1 wallet + 1 registry = 7
        assert len(graph.nodes) == 7
        # Each IOC has one edge from the file node
        assert len(graph.edges) == 6

    def test_family_detection_node(self):
        result = {
            "family_detection": {"family": "emotet", "confidence": 0.9},
        }
        graph = build_graph(result)
        families = [n for n in graph.nodes if n.node_type == "family"]
        assert len(families) == 1
        assert families[0].label == "emotet"

    def test_threat_intel_family(self):
        result = {
            "threat_intel": {
                "hits": [
                    {"found": True, "source": "MalwareBazaar", "malware_family": "AgentTesla"},
                ]
            },
        }
        graph = build_graph(result)
        families = [n for n in graph.nodes if n.node_type == "family"]
        assert len(families) == 1
        assert families[0].label == "AgentTesla"

    def test_no_duplicate_family_nodes(self):
        result = {
            "family_detection": {"family": "emotet", "confidence": 0.9},
            "threat_intel": {
                "hits": [
                    {"found": True, "source": "MalwareBazaar", "malware_family": "emotet"},
                ]
            },
        }
        graph = build_graph(result)
        families = [n for n in graph.nodes if n.node_type == "family"]
        assert len(families) == 1


class TestIOCGraphSerialization:
    """Tests for IOCGraph to_dict and to_visjs."""

    def test_to_dict(self):
        graph = IOCGraph(
            nodes=[GraphNode(id="n1", label="test", node_type="file")],
            edges=[GraphEdge(source="n1", target="n2", relationship="contacts")],
        )
        d = graph.to_dict()
        assert len(d["nodes"]) == 1
        assert d["nodes"][0]["id"] == "n1"
        assert d["edges"][0]["from"] == "n1"
        assert d["edges"][0]["relationship"] == "contacts"

    def test_to_visjs_colors_and_shapes(self):
        graph = IOCGraph(
            nodes=[
                GraphNode(id="f1", label="test.exe", node_type="file"),
                GraphNode(id="d1", label="evil.com", node_type="domain"),
            ],
            edges=[GraphEdge(source="f1", target="d1", relationship="resolves")],
        )
        visjs = graph.to_visjs()
        file_node = next(n for n in visjs["nodes"] if n["id"] == "f1")
        domain_node = next(n for n in visjs["nodes"] if n["id"] == "d1")
        assert file_node["shape"] == "diamond"
        assert file_node["size"] == 25
        assert domain_node["shape"] == "dot"
        assert domain_node["size"] == 15
        assert len(visjs["edges"]) == 1
