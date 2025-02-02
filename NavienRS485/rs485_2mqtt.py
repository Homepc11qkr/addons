import paho.mqtt.client as mqtt
import time
import logging

# 로그 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MQTT_USERNAME = 'mqtt_user'
MQTT_PASSWORD = 'mqtt_pass'
MQTT_SERVER = '192.168.0.35'
ROOT_TOPIC_NAME = 'rs485_2mqtt'


class Wallpad:
    def __init__(self):
        self.mqtt_client = mqtt.Client(protocol=mqtt.MQTTv311, callback_api_version=2)  # 최신 API 적용
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)

        # MQTT 연결 시도
        self.connect_mqtt()

    def connect_mqtt(self):
        """MQTT 연결을 시도하고 실패해도 프로그램이 종료되지 않도록 구성"""
        while True:
            try:
                logging.info("MQTT 브로커 연결 시도 중...")
                self.mqtt_client.connect(MQTT_SERVER, 1883)
                self.mqtt_client.loop_start()  # 백그라운드 실행
                logging.info("MQTT 연결 성공")
                break
            except Exception as e:
                logging.error(f"MQTT 연결 실패: {e}, 5초 후 재시도")
                time.sleep(5)  # 5초 후 재연결 시도

    def on_connect(self, client, userdata, flags, rc):
        """연결 성공 시 호출"""
        if rc == 0:
            logging.info("MQTT 브로커 연결 성공")
        else:
            logging.warning(f"MQTT 연결 실패, 코드: {rc}")

    def on_disconnect(self, client, userdata, rc):
        """MQTT 연결이 끊어졌을 때 자동으로 재연결"""
        logging.warning(f"MQTT 연결 해제됨. rc: {rc}")
        time.sleep(5)  # 5초 대기 후 재연결 시도
        self.connect_mqtt()

    def on_message(self, client, userdata, msg):
        """MQTT 메시지 수신 시 호출"""
        try:
            logging.info(f"수신된 메시지: {msg.topic} - {msg.payload.decode()}")
        except Exception as e:
            self.on_error(f"MQTT 메시지 처리 중 오류 발생: {e}")

    def on_error(self, message):
        """오류 발생 시 로그 출력"""
        logging.error(message)

    def listen(self):
        """MQTT 메시지 수신을 위한 루프 실행"""
        logging.info("MQTT 구독 시작")

        try:
            while True:
                time.sleep(1)  # MQTT 루프가 백그라운드에서 실행 중이므로 별도 처리가 필요 없음
        except KeyboardInterrupt:
            logging.info("프로그램 종료됨")
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
        except Exception as e:
            self.on_error(f"메인 루프 오류 발생: {e}")


# =============================
# 프로그램 실행
# =============================
wallpad = Wallpad()
wallpad.listen()
