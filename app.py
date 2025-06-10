from flask import Flask, render_template
from flask_socketio import SocketIO
from kafka import KafkaConsumer
import json
import threading

app = Flask(__name__)
socketio = SocketIO(app)

# Khởi tạo Kafka Consumer
consumer = KafkaConsumer(
    "device_status",
    bootstrap_servers=["localhost:9092"],
    auto_offset_reset="latest",
    enable_auto_commit=True,
    value_deserializer=lambda x: json.loads(x.decode("utf-8"))
)

# Hàm chạy trong luồng riêng để đọc từ Kafka và phát qua WebSocket
def kafka_listener():
    for message in consumer:
        data = message.value
        print(f"[DEBUG] Nhận từ Kafka: {data}")
        socketio.emit("device_status", data)  # Gửi dữ liệu tới client WebSocket

# Route để hiển thị trang web
@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    # Khởi động luồng Kafka listener
    kafka_thread = threading.Thread(target=kafka_listener, daemon=True)
    kafka_thread.start()
    # Chạy Flask server
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
