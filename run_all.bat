@echo off
rem Start Device_log.py
start "" python "%~dp0Device_log.py" --nsl_csv KDDTrain+.txt --num_devices 10 --delay 0.5 --synthetic_ratio 0.5
rem Start Spark Streaming.py
start "" python "%~dp0Spark Streaming.py"
rem Start app.py
start "" python "%~dp0app.py"
