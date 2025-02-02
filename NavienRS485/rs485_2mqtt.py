import paho.mqtt.client as mqtt
import time

MQTT_USERNAME = 'mqtt_user'
MQTT_PASSWORD = 'mqtt_pass'
MQTT_SERVER = '192.168.0.35'
ROOT_TOPIC_NAME = 'rs485_2mqtt'


class Wallpad:
    def __init__(self):
        self.mqtt_client = mqtt.Client(protocol=mqtt.MQTTv311, callback_api_version=2)  # 최신 API 적용
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)

        self.connect_mqtt()

    def connect_mqtt(self):
        """MQTT 연결을 시도하고 실패하면 자동으로 재시도"""
        while True:
            try:
                print("MQTT 브로커 연결 시도 중...")
                self.mqtt_client.connect(MQTT_SERVER, 1883)
                self.mqtt_client.loop_start()  # 백그라운드 실행
                print("MQTT 연결 성공")
                break
            except Exception as e:
                print(f"MQTT 연결 실패: {e}, 5초 후 재시도")
                time.sleep(5)

    def on_connect(self, client, userdata, flags, rc):
        """연결 성공 시 호출"""
        if rc == 0:
            print("MQTT 브로커 연결 성공")
        else:
            print(f"MQTT 연결 실패, 코드: {rc}")

    def on_disconnect(self, client, userdata, rc):
        """MQTT 연결이 끊어졌을 때 자동으로 재연결"""
        print(f"MQTT 연결 해제됨. rc: {rc}")
        time.sleep(5)  # 5초 대기 후 재연결 시도
        self.connect_mqtt()

    def listen(self):
        """MQTT 메시지 수신을 위한 루프 실행"""
        print("MQTT 구독 시작")

        try:
            while True:
                time.sleep(1)  # MQTT 루프가 백그라운드에서 실행 중이므로 별도 처리가 필요 없음
        except KeyboardInterrupt:
            print("프로그램 종료됨")
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()


# =============================
# 프로그램 실행
# =============================
wallpad = Wallpad()
wallpad.listen()
