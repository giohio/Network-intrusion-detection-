import pickle
import pandas as pd
import numpy as np
from pyspark.sql import SparkSession
from pyspark.sql.functions import from_json, col
from pyspark.sql.types import (
    StructType, StructField, StringType, IntegerType, DoubleType
)
from kafka import KafkaProducer
import json
import atexit

# Khởi tạo Kafka Producer
producer = KafkaProducer(
    bootstrap_servers=["localhost:9092"],
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

def load_pickle(file_path):
    """Hàm tiện ích để load file pickle."""
    try:
        with open(file_path, "rb") as f:
            return pickle.load(f)
    except Exception as e:
        print(f"[LỖI] Không thể load file pickle {file_path}: {e}")
        raise

def preprocess_and_predict(pdf_batch, scaler_numeric, tabular_model):
    """
    Tiền xử lý và dự đoán cho một batch Pandas DataFrame (pdf_batch).
    - pdf_batch: có các cột flatten từ JSON: 'timestamp', 'device_id', 
      rồi 34 cột numeric, 4 cột binary, 3 cột categorical, và 'label'.
    - scaler_numeric: StandardScaler đã fit lên 34 cột numeric lúc train.
    - tabular_model: PyTorch Tabular đã fit với continuous_cols = 34 cột numeric + 4 cột binary,
      categorical_cols = ["protocol_type", "service", "flag"].
    Trả về: Pandas DataFrame gốc kèm cột "prediction" (0=normal, 1=attack).
    """
    if pdf_batch.shape[0] == 0:
        return pdf_batch

    cols_numeric = [
        "duration", "src_bytes", "dst_bytes", "wrong_fragment", "urgent",
        "hot", "num_failed_logins", "num_compromised", "root_shell", "su_attempted",
        "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
        "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
        "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
        "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate"
    ]
    cols_binary = ["land", "logged_in", "is_host_login", "is_guest_login"]
    cols_category = ["protocol_type", "service", "flag"]

    try:
        features_df = pdf_batch[cols_numeric + cols_binary + cols_category + ["label"]].copy()
    except KeyError as e:
        print(f"[LỖI] Thiếu cột trong batch: {e}")
        raise

    try:
        features_df[cols_numeric] = scaler_numeric.transform(features_df[cols_numeric])
    except Exception as e:
        print(f"[LỖI] Lỗi khi scale numeric cols: {e}")
        raise

    df_model_input = features_df[cols_numeric + cols_binary + cols_category].reset_index(drop=True)

    expected_cols = len(cols_numeric) + len(cols_binary) + len(cols_category)  # 34 + 4 + 3 = 41
    if df_model_input.shape[1] != expected_cols:
        raise ValueError(
            f"[LỖI] Số cột đầu vào không khớp: DataFrame có {df_model_input.shape[1]} cột, "
            f"mô hình mong đợi {expected_cols} cột."
        )

    try:
        y_pred_df = tabular_model.predict(df_model_input)
    except Exception as e:
        print(f"[LỖI] Lỗi khi dự đoán: {e}")
        raise

    if "attack_prediction" not in y_pred_df.columns:
        print("[LỖI] Cột 'attack_prediction' không tồn tại trong y_pred_df!")
        raise ValueError("Không tìm thấy cột dự đoán hợp lệ trong y_pred_df!")

    y_pred = y_pred_df["attack_prediction"].values
    pdf_out = pdf_batch.copy()
    pdf_out["prediction"] = y_pred  # 0=normal, 1=attack
    return pdf_out

def process_batch(batch_df, batch_id, scaler_numeric, tabular_model):
    """
    Callback cho foreachBatch:
    - batch_df: Spark DataFrame của microbatch hiện tại.
    - batch_id: ID của batch.
    """
    pdf = batch_df.toPandas()
    if pdf.shape[0] == 0:
        return

    pdf_with_pred = preprocess_and_predict(
        pdf,
        scaler_numeric=scaler_numeric,
        tabular_model=tabular_model
    )

    for _, row in pdf_with_pred.iterrows():
        device = row["device_id"]
        ts = row["timestamp"]
        pred = row["prediction"]
        label_str = "ATTACK" if pred == 1 else "NORMAL"
        orig_label = row["label"] if "label" in row else "N/A"
        
        print(f"[BATCH {batch_id}] Device={device} | Time={ts} | Prediction={label_str} | Original Label={orig_label}")

        # Tạo document để gửi qua Kafka
        document = {
            "device_id": device,
            "timestamp": ts,
            "status": label_str,
            "original_label": orig_label
        }

        # Gửi dữ liệu qua Kafka topic "device_status"
        try:
            producer.send("device_status", document)
            print(f"[BATCH {batch_id}] Đã gửi bản ghi cho device_id={device} vào topic device_status")
        except Exception as e:
            print(f"[LỖI] Không thể gửi vào Kafka topic device_status: {e}")

if __name__ == "__main__":
    KAFKA_BOOTSTRAP = "localhost:9092"
    KAFKA_TOPIC = "nslkdd_logs"
    CHECKPOINT_LOCATION = "/tmp/spark_ckpt_intrusion"
    SCALER_PATH = "scaler_numeric.pkl"
    MODEL_PATH = "new_tabular_model.pkl"

    scaler_numeric = load_pickle(SCALER_PATH)
    tabular_model = load_pickle(MODEL_PATH)

    spark = (SparkSession.builder
             .appName("IntrusionDetectionStreaming_NoPCA")
             .config("spark.jars.packages", "org.apache.spark:spark-sql-kafka-0-10_2.12:3.1.2")
             .getOrCreate())
    spark.sparkContext.setLogLevel("ERROR")

    feature_schema = StructType([
        StructField("duration", IntegerType(), True),
        StructField("protocol_type", StringType(), True),
        StructField("service", StringType(), True),
        StructField("flag", StringType(), True),
        StructField("src_bytes", IntegerType(), True),
        StructField("dst_bytes", IntegerType(), True),
        StructField("land", IntegerType(), True),
        StructField("wrong_fragment", IntegerType(), True),
        StructField("urgent", IntegerType(), True),
        StructField("hot", IntegerType(), True),
        StructField("num_failed_logins", IntegerType(), True),
        StructField("logged_in", IntegerType(), True),
        StructField("num_compromised", IntegerType(), True),
        StructField("root_shell", IntegerType(), True),
        StructField("su_attempted", IntegerType(), True),
        StructField("num_root", IntegerType(), True),
        StructField("num_file_creations", IntegerType(), True),
        StructField("num_shells", IntegerType(), True),
        StructField("num_access_files", IntegerType(), True),
        StructField("num_outbound_cmds", IntegerType(), True),
        StructField("is_host_login", IntegerType(), True),
        StructField("is_guest_login", IntegerType(), True),
        StructField("count", IntegerType(), True),
        StructField("srv_count", IntegerType(), True),
        StructField("serror_rate", DoubleType(), True),
        StructField("srv_serror_rate", DoubleType(), True),
        StructField("rerror_rate", DoubleType(), True),
        StructField("srv_rerror_rate", DoubleType(), True),
        StructField("same_srv_rate", DoubleType(), True),
        StructField("diff_srv_rate", DoubleType(), True),
        StructField("srv_diff_host_rate", DoubleType(), True),
        StructField("dst_host_count", IntegerType(), True),
        StructField("dst_host_srv_count", IntegerType(), True),
        StructField("dst_host_same_srv_rate", DoubleType(), True),
        StructField("dst_host_diff_srv_rate", DoubleType(), True),
        StructField("dst_host_same_src_port_rate", DoubleType(), True),
        StructField("dst_host_srv_diff_host_rate", DoubleType(), True),
        StructField("dst_host_serror_rate", DoubleType(), True),
        StructField("dst_host_srv_serror_rate", DoubleType(), True),
        StructField("dst_host_rerror_rate", DoubleType(), True),
        StructField("dst_host_srv_rerror_rate", DoubleType(), True),
        StructField("label", StringType(), True)
    ])

    json_schema = StructType([
        StructField("timestamp", StringType(), True),
        StructField("device_id", StringType(), True),
        StructField("features", feature_schema, True)
    ])

    kafka_df = (spark.readStream
                .format("kafka")
                .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP)
                .option("subscribe", KAFKA_TOPIC)
                .option("startingOffsets", "latest")
                .load())

    json_str_df = kafka_df.selectExpr("CAST(value AS STRING) AS json_str")
    parsed_df = (json_str_df
                 .select(from_json(col("json_str"), json_schema).alias("data"))
                 .select("data.timestamp", "data.device_id", "data.features.*"))

    query = (parsed_df.writeStream
             .foreachBatch(lambda df, epoch_id: process_batch(
                 df, epoch_id,
                 scaler_numeric=scaler_numeric,
                 tabular_model=tabular_model
             ))
             .option("checkpointLocation", CHECKPOINT_LOCATION)
             .start())

    atexit.register(lambda: producer.close())
    query.awaitTermination()