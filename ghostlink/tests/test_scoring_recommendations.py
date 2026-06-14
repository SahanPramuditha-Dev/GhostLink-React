from ghostlink.core.scoring import score_network
from ghostlink.core.recommendations import recommendations_for_network


def test_open_network_scores_low():
    result = score_network("Open", signal=78, congestion="Busy")
    assert result.score < 55
    assert result.label in {"High Risk", "Critical", "Moderate Risk"}


def test_wpa3_network_scores_high():
    result = score_network("WPA3-Personal", signal=55, congestion="Clear")
    assert result.score >= 75
    assert result.label in {"Excellent", "Good"}


def test_recommendations_for_open_network():
    recs = recommendations_for_network("Open", signal=90, congestion="Crowded", wps_enabled=True)
    joined = " ".join(recs).lower()
    assert "wpa2" in joined or "wpa3" in joined
    assert "wps" in joined
    assert "channel" in joined
