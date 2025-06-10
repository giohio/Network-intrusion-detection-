import pandas as pd
import random
import json
import time
import argparse
import numpy as np
from datetime import datetime, timezone
from kafka import KafkaProducer
from kafka.errors import KafkaError

def load_nsl_kdd(file_path: str) -> pd.DataFrame:
    cols = [
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
        "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
        "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
        "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
        "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"
    ]
    try:
        df = pd.read_csv(file_path, names=cols + ['level'], header=None).drop('level', axis=1)
        print(f"[INFO] Đã nạp {len(df)} bản ghi từ {file_path}")
        numeric_cols = [c for c in cols if c not in ["protocol_type", "service", "flag", "label"]]
        for col in numeric_cols:
            df[col] = pd.to_numeric(df[col], errors='raise')
        return df
    except Exception as e:
        print(f"[LỖI] Không thể nạp dữ liệu: {e}")
        raise

def generate_device_list(num_devices: int) -> list:
    return [f"device_{i:03d}" for i in range(1, num_devices + 1)]

def perturb_record(record: dict, df: pd.DataFrame) -> dict:
    new_rec = record.copy()
    # Các cột số sẽ được điều chỉnh ±10%
    numeric_cols = ["duration", "src_bytes", "dst_bytes", "count", "srv_count"]
    for col in numeric_cols:
        val = float(new_rec[col])
        scale = random.uniform(0.9, 1.1)
        new_rec[col] = int(max(val * scale, 0))
    # Các cột tỷ lệ sẽ được thêm nhiễu ±0.05, giới hạn trong [0,1]
    rate_cols = [
        "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
        "diff_srv_rate", "srv_diff_host_rate", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
        "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
    ]
    for col in rate_cols:
        val = float(new_rec[col])
        noise = random.uniform(-0.05, 0.05)
        new_rec[col] = round(min(max(val + noise, 0.0), 1.0), 2)
    # Thỉnh thoảng đổi protocol_type/service/flag
    if random.random() < 0.2:
        new_rec["protocol_type"] = random.choice(df["protocol_type"].unique().tolist())
    if random.random() < 0.2:
        new_rec["service"] = random.choice(df["service"].unique().tolist())
    if random.random() < 0.2:
        new_rec["flag"] = random.choice(df["flag"].unique().tolist())
    # Đảm bảo đặc điểm của một số loại tấn công
    if new_rec["label"] == "smurf" and new_rec["count"] < 100:
        new_rec["count"] = int(random.uniform(100, 500))
    return new_rec

def build_log_entry(base_record: dict, device_id: str, df: pd.DataFrame, synthetic: bool) -> dict:
    record = perturb_record(base_record, df) if synthetic else base_record.copy()
    for k, v in record.items():
        if isinstance(v, (np.integer, np.floating)):
            record[k] = v.item()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": device_id,
        "features": record
    }

def main(args):
    df = load_nsl_kdd(args.nsl_csv)
    device_list = generate_device_list(args.num_devices)
    print(f"[INFO] Đang mô phỏng {len(device_list)} thiết bị")
    try:
        producer = KafkaProducer(
            bootstrap_servers=["localhost:9092"],
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            retries=5,
            retry_backoff_ms=1000
        )
        print("[INFO] Khởi tạo KafkaProducer thành công")
    except KafkaError as e:
        print(f"[LỖI] Không thể kết nối tới Kafka: {e}")
        raise

    normal_records = df[df["label"] == "normal"]
    attack_records = df[df["label"] != "normal"]
    normal_count = 0
    attack_count = 0

    try:
        while True:
            dev = random.choice(device_list)
            # Chọn ngẫu nhiên normal hoặc attack với tỷ lệ 50/50
            if random.random() < 0.5:
                base = normal_records.iloc[random.randint(0, len(normal_records) - 1)].to_dict()
                normal_count += 1
            else:
                base = attack_records.iloc[random.randint(0, len(attack_records) - 1)].to_dict()
                attack_count += 1
            is_synthetic = random.random() < args.synthetic_ratio
            log_entry = build_log_entry(base, dev, df, synthetic=is_synthetic)
            print(f"[DEBUG] Gửi: duration={log_entry['features']['duration']}, "
                  f"dst_host_srv_rerror_rate={log_entry['features']['dst_host_srv_rerror_rate']}, "
                  f"label={log_entry['features']['label']}, "
                  f"Normal/Attack: {normal_count}/{attack_count}")
            producer.send("nslkdd_logs", log_entry)
            producer.flush()
            time.sleep(args.delay)
    except KeyboardInterrupt:
        print("\n[STOP] Dừng sinh log.")
    except Exception as e:
        print(f"[LỖI] Lỗi trong vòng lặp chính: {e}")
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sinh log NSL-KDD")
    parser.add_argument("--nsl_csv", type=str, required=True, help="Đường dẫn tới file NSL-KDD TXT")
    parser.add_argument("--num_devices", type=int, default=10, help="Số lượng thiết bị")
    parser.add_argument("--delay", type=float, default=1.0, help="Độ trễ giữa các bản ghi (giây)")
    parser.add_argument("--synthetic_ratio", type=float, default=0.5, help="Tỷ lệ bản ghi tổng hợp")
    args = parser.parse_args()
    main(args)