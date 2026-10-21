"""
ScamShield-RAG :: Live Global Web Intelligence Engine
Queries the open web and global threat feeds in real time.
"""

from typing import List, Dict, Any
import requests
import warnings

# Suppress transition warnings cleanly
warnings.filterwarnings("ignore", category=RuntimeWarning, module="duckduckgo_search")

try:
    try:
        from ddgs import DDGS
    except ImportError:
        from duckduckgo_search import DDGS
    DDGS_AVAILABLE = True
except ImportError:
    DDGS_AVAILABLE = False


class GlobalWebIntelligence:
    def __init__(self):
        self.available = DDGS_AVAILABLE

    def search_live_web(self, query: str, max_results: int = 3) -> List[Dict[str, str]]:
        """
        Searches the live open web globally for real-world threat reports,
        news, and fraud advisories matching the artifact.
        """
        if not self.available:
            return [{
                "title": "Local Advisory Fallback",
                "snippet": "Live internet search package not available.",
                "url": "https://cybercrime.gov.in",
                "source": "Local Fallback"
            }]

        clean_query = f"{query} scam fraud complaint advisory"
        results = []
        try:
            with DDGS() as ddgs:
                raw_results = list(ddgs.text(clean_query, max_results=max_results))
                for item in raw_results:
                    results.append({
                        "title": item.get("title", ""),
                        "snippet": item.get("body", ""),
                        "url": item.get("href", ""),
                        "source": "Global Web Search"
                    })
        except Exception as e:
            results.append({
                "title": "Live Intelligence Feed Notice",
                "snippet": f"Web query unavailable: {str(e)}",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories",
                "source": "Network Feed"
            })
        return results

    def check_urlhaus_global_feed(self, domain_or_url: str) -> Dict[str, Any]:
        """
        Queries URLhaus to check if a link or domain is flagged globally.
        """
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        try:
            resp = requests.post(api_url, data={"url": domain_or_url}, timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok":
                    return {
                        "is_flagged": True,
                        "threat": data.get("threat", "Malicious Link"),
                        "date_added": data.get("date_added", ""),
                        "tags": data.get("tags", [])
                    }
        except Exception:
            pass
        return {"is_flagged": False, "threat": None}