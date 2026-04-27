from pathlib import Path

from robustedge.data import DatasetIndex
from robustedge.features import FeatureTableBuilder, infer_feature_columns


def test_discover_minimal_dataset():
    data_root = Path(__file__).parent / "fixtures" / "minimal_dataset"
    index = DatasetIndex.from_root(data_root)
    df = index.to_frame()
    assert len(df) >= 3
    assert "attack_duration" in df.columns


def test_extract_features_minimal_dataset():
    data_root = Path(__file__).parent / "fixtures" / "minimal_dataset"
    runs = DatasetIndex.from_root(data_root).load_runs()
    features = FeatureTableBuilder(sysdig_window_seconds=4.0).transform_runs(runs)
    cols = infer_feature_columns(features)
    assert not features.empty
    assert len(cols) > 0
    assert "label" in features.columns
